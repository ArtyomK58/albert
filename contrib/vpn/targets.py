"""Fixed-target VPN operations; no arbitrary shell commands from chat requests."""
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import time
import urllib.request


def command(args, timeout=25):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


class Targets:
    def __init__(self, config):
        self.config = config

    def mac(self, action, credentials=None, request_id=None):
        body = {'action': action}
        if credentials:
            body.update(credentials)
        if request_id:
            body['request_id'] = request_id
        request = urllib.request.Request(
            self.config['mac_url'] + '/control', data=json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + self.config['mac_token'],
                     'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=self.config.get('auth_timeout_seconds', 360)+45 if action != 'status' else 8) as response:
                return json.load(response)
        except Exception:
            return {'ok': False, 'state': 'unknown', 'code': 'mac_unavailable'}

    def vps_status(self):
        try:
            output = command([self.config['vps_command'], 'status']).stdout
            up = 'owned=yes' in output and 'tcp=estab' in output and 'state=up' in output
            return {'ok': True, 'state': 'connected' if up else 'disconnected'}
        except (OSError, subprocess.TimeoutExpired):
            return {'ok': False, 'state': 'unknown', 'code': 'vps_unavailable'}

    def vps_login(self, credentials, force, on_pending=None):
        if not force and self.vps_status().get('state') == 'connected':
            return {'ok': True, 'state': 'connected', 'changed': False}
        binary = self.config['vps_command']
        # The existing supervisor owns its child and refuses foreign TTY sessions.
        stopped = command([binary, 'stop'])
        if stopped.returncode:
            return {'ok': False, 'code': 'owned_session_stop_rejected', 'state': 'unknown'}
        master, slave = pty.openpty()
        proc = subprocess.Popen([binary, 'login'], stdin=slave, stdout=slave, stderr=slave,
                                close_fds=True, start_new_session=True)
        os.close(slave)
        buffer = b''
        sent = set()
        mfa = False
        started = time.monotonic()
        end = started + self.config.get('auth_timeout_seconds', 360)
        try:
            while time.monotonic() < end:
                if not select.select([master], [], [], 0.25)[0]:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                buffer = (buffer + chunk)[-16384:]
                # Raw terminal output stays in memory and is never returned/logged.
                for prompt, key in ((b'Username:', 'username'), (b'Password:', 'password')):
                    if prompt in buffer and key not in sent:
                        os.write(master, credentials[key].encode() + b'\n')
                        sent.add(key)
                if not mfa and b'AUTH_PENDING' in buffer:
                    mfa = True
                    if on_pending:
                        on_pending()
                if b'AUTH_FAILED' in buffer or b'auth-not-completed' in buffer:
                    break
            # Human instructions can mention a success line before authentication.
            # Only the independent transport check establishes actual completion.
            if self.vps_status().get('state') == 'connected':
                return {'ok': True, 'state': 'connected', 'changed': True, 'mfa_observed': mfa}
            status = command([binary, 'status']).stdout
            reason = re.search(r'\breason=([a-z-]+)', status)
            return {'ok': False, 'state': 'disconnected',
                    'code': reason.group(1) if reason else 'authentication_or_network_timeout',
                    'credentials_submitted': len(sent) == 2, 'mfa_observed': mfa,
                    'elapsed_seconds': round(time.monotonic()-started),
                    'controller_timeout': time.monotonic() >= end}
        finally:
            os.close(master)
            if proc.poll() is None:
                # Only our PTY attachment exits. The supervisor-owned tunnel remains.
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


class Credentials:
    def __init__(self, path):
        self.path = path

    def load(self):
        process = subprocess.run(['systemd-creds', 'decrypt', self.path, '-'],
                                 capture_output=True, timeout=15)
        if process.returncode:
            return None
        try:
            return validate_credentials(json.loads(process.stdout))
        except ValueError:
            return None

    def save(self, value):
        value = validate_credentials(value)
        dest = Path(self.path)
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = dest.with_name(dest.name + '.new')
        process = subprocess.run(['systemd-creds', 'encrypt', '--with-key=host',
                                  '--name=' + dest.name, '-', str(tmp)],
                                 input=json.dumps(value).encode(), capture_output=True, timeout=15)
        if process.returncode:
            raise RuntimeError('credential_storage_unavailable')
        tmp.chmod(0o600)
        tmp.replace(dest)


def validate_credentials(value):
    if not isinstance(value, dict):
        raise ValueError('invalid_credentials')
    result = {}
    for key in ('username', 'password'):
        item = value.get(key)
        if not isinstance(item, str) or not 1 <= len(item) <= 1024 or any(c in item for c in '\r\n\x00'):
            raise ValueError('invalid_credentials')
        result[key] = item
    return result
