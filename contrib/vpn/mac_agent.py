"""Loopback-only authenticated controller for one configured native VPN service."""
import argparse
import hmac
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from pathlib import Path
import subprocess
import threading
from gateway_plan import MAC_HELPER_BUDGET


class Controller:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.cache_path = Path(config['state_file'])
        self.results = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}
        # The fencing high-water mark lives outside the bounded result cache, so cache
        # eviction or a restart can never lower it. Older files kept it in the cache.
        self.epoch_path = self.cache_path.with_suffix('.epoch')
        stored = int(self.epoch_path.read_text()) if self.epoch_path.exists() else 0
        legacy = self.results.pop('_mode_epoch', 0)
        self.mode_epoch = max(stored, int(legacy) if type(legacy) is int else 0)
        if self.mode_epoch > stored:
            self.persist_epoch()

    def execute(self, request):
        action = request.get('action')
        if action == 'network':
            return self.network(request)
        if action not in ('status', 'connect', 'reconnect', 'disconnect'):
            return {'ok': False, 'code': 'invalid_action'}
        if action != 'status' and self.config.get('maintenance'):
            return {'ok': False, 'code': 'maintenance'}
        if action != 'status':
            ident = request.get('request_id', '')
            if not isinstance(ident, str) or not 8 <= len(ident) <= 100:
                return {'ok': False, 'code': 'invalid_request_id'}
            if not self.lock.acquire(blocking=False):
                return {'ok': False, 'code': 'busy'}
        try:
            if action != 'status':
                epoch = request.get('mode_epoch')
                if epoch is None and self.config.get('mode_epoch_required'):
                    return {'ok': False, 'code': 'mode_epoch_required'}
                if epoch is not None:
                    if type(epoch) is not int or epoch < 1 or epoch < self.mode_epoch:
                        return {'ok': False, 'code': 'stale_mode_epoch'}
                    if epoch > self.mode_epoch:
                        self.mode_epoch = epoch
                        self.persist_epoch()  # Durable before any dispatch.
                if ident in self.results:
                    return self.results[ident]
                # Save before dispatch: unknown outcomes must never repeat MFA.
                self.results[ident] = {'ok': False, 'code': 'outcome_unknown'}
                self.persist()
            payload = {'action': action, 'service_id': self.config['service_id']}
            payload['timeout_seconds'] = self.config.get('auth_timeout_seconds', 360)
            credentials = {key: request[key] for key in ('username', 'password') if key in request}
            if action in ('connect', 'reconnect') and self.config.get('use_saved_credentials'):
                data = json.dumps(credentials, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                digest = hmac.new(self.config['token'].encode(), data, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(digest, self.config.get('credentials_digest', '')):
                    result = {'ok': False, 'state': 'unknown', 'code': 'native_credential_update_required'}
                    self.results[ident] = result
                    self.persist()
                    return result
            else:
                payload.update(credentials)
            if action in ('connect', 'reconnect') and self.config.get('client_app'):
                subprocess.run(['/usr/bin/open', '-g', '-j', self.config['client_app']],
                               capture_output=True, timeout=15, check=True)
            process = subprocess.run([self.config['network_binary']], input=json.dumps(payload),
                                     capture_output=True, text=True,
                                     timeout=self.config.get('auth_timeout_seconds', 360)+25)
            result = json.loads(process.stdout)
            result = {k: v for k, v in result.items() if k in ('ok', 'state', 'code', 'changed')}
            # NetworkExtension may keep its tunnel up while the VPN transport
            # repeatedly resets. Report the provider's real connection events.
            if result.get('state') == 'connected' and self.config.get('core_log_file'):
                log = Path(self.config['core_log_file'])
                if log.exists():
                    with log.open('rb') as source:
                        source.seek(max(0, log.stat().st_size-131072))
                        events = re.findall(rb'EVENT: (CONNECTED|RECONNECTING|TRANSPORT_ERROR|DISCONNECTED|AUTH_FAILED|AUTH_PENDING)\b', source.read())
                    if events and events[-1] != b'CONNECTED':
                        result['state'] = 'disconnected' if events[-1] in (b'DISCONNECTED',b'AUTH_FAILED') else 'connecting'
                        if action != 'status':
                            result.update(ok=False,code='core_transport_not_connected')
            if action == 'status':
                result['credentials_ready'] = not self.config.get('use_saved_credentials') or bool(self.config.get('credentials_digest'))
            if action != 'status':
                self.results[ident] = result
                self.persist()
            return result
        except (OSError, ValueError, subprocess.SubprocessError):
            return {'ok': False, 'state': 'unknown', 'code': 'controller_unavailable'}
        finally:
            if action != 'status':
                self.lock.release()

    def network(self, request):
        """Fixed root helper only. No login, credential handling or shell RPC."""
        value = request.get('network', {})
        if not isinstance(value, dict):
            return {'ok': False, 'code': 'invalid_network_request'}
        phase, target, epoch = value.get('phase'), value.get('target'), request.get('mode_epoch')
        if (phase not in ('preflight', 'block', 'activate', 'verify', 'recover')
                or target not in ('mac', 'vps') or type(epoch) is not int or epoch < 1):
            return {'ok': False, 'code': 'invalid_network_request'}
        if self.config.get('maintenance') and phase != 'recover':
            return {'ok': False, 'code': 'maintenance'}
        if self.config.get('network_helper') != '/Library/PrivilegedHelperTools/FrogVPN/run':
            return {'ok': False, 'code': 'network_helper_unconfigured'}
        if not self.lock.acquire(blocking=False):
            return {'ok': False, 'code': 'busy'}
        try:
            if epoch < self.mode_epoch:
                return {'ok': False, 'code': 'stale_mode_epoch'}
            if phase not in ('preflight', 'verify') and epoch > self.mode_epoch:
                self.mode_epoch = epoch
                self.persist_epoch()
            # Network phases are idempotent and never authenticate. A repeated block
            # must execute after a failed activation, rather than reuse a cached reply.
            proc = subprocess.run(['/usr/bin/sudo', '-n', self.config['network_helper'],
                                   '--phase', phase, '--target', target, '--epoch', str(epoch)],
                                  capture_output=True, text=True, timeout=MAC_HELPER_BUDGET + 15)
            result = json.loads(proc.stdout)
            if proc.returncode == 0 and result.get('ok') and phase == 'activate':
                # A failed DNS lookup during MFA can remain cached after routing
                # returns. Refresh only resolver caches, never restart a VPN.
                subprocess.run(['/usr/bin/dscacheutil', '-flushcache'], capture_output=True,
                               timeout=8, check=True)
            return {'ok': proc.returncode == 0 and result.get('ok') is True,
                    'code': str(result.get('code', ''))[:64],
                    'kept': [str(x)[:64] for x in result.get('kept', [])[:32]]}
        except Exception:
            return {'ok': False, 'code': 'network_helper_outcome_unknown'}
        finally:
            self.lock.release()

    def persist_epoch(self):
        self.epoch_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.epoch_path.with_name(self.epoch_path.name + '.new')
        with tmp.open('w') as f:
            f.write(str(self.mode_epoch))
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o600)
        tmp.replace(self.epoch_path)

    def persist(self):
        self.results = dict(list(self.results.items())[-128:])
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.results))
        tmp.chmod(0o600)
        tmp.replace(self.cache_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    config = json.loads(Path(parser.parse_args().config).read_text())
    controller = Controller(config)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            header = self.headers.get('Authorization', '')
            if self.path != '/control' or not hmac.compare_digest(header, 'Bearer ' + config['token']):
                self.send_error(403)
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8192:
                    raise ValueError()
                result = controller.execute(json.loads(self.rfile.read(size)))
            except (ValueError, TypeError):
                result = {'ok': False, 'code': 'invalid_request'}
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(('127.0.0.1', config['port']), Handler).serve_forever()


if __name__ == '__main__':
    main()
