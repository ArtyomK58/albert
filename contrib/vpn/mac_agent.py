"""Loopback-only authenticated controller for one configured native VPN service."""
import argparse
import hmac
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading


class Controller:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.cache_path = Path(config['state_file'])
        self.results = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}

    def execute(self, request):
        action = request.get('action')
        if action not in ('status', 'connect', 'reconnect'):
            return {'ok': False, 'code': 'invalid_action'}
        if action != 'status':
            ident = request.get('request_id', '')
            if not isinstance(ident, str) or not 8 <= len(ident) <= 100:
                return {'ok': False, 'code': 'invalid_request_id'}
            if not self.lock.acquire(blocking=False):
                return {'ok': False, 'code': 'busy'}
        try:
            if action != 'status':
                if ident in self.results:
                    return self.results[ident]
                # Save before dispatch: unknown outcomes must never repeat MFA.
                self.results[ident] = {'ok': False, 'code': 'outcome_unknown'}
                self.persist()
            payload = {'action': action, 'service_id': self.config['service_id']}
            payload['timeout_seconds'] = self.config.get('auth_timeout_seconds', 360)
            credentials = {key: request[key] for key in ('username', 'password') if key in request}
            if action != 'status' and self.config.get('use_saved_credentials'):
                data = json.dumps(credentials, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                digest = hmac.new(self.config['token'].encode(), data, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(digest, self.config.get('credentials_digest', '')):
                    result = {'ok': False, 'state': 'unknown', 'code': 'native_credential_update_required'}
                    self.results[ident] = result
                    self.persist()
                    return result
            else:
                payload.update(credentials)
            if action != 'status' and self.config.get('client_app'):
                subprocess.run(['/usr/bin/open', '-g', '-j', self.config['client_app']],
                               capture_output=True, timeout=15, check=True)
            process = subprocess.run([self.config['network_binary']], input=json.dumps(payload),
                                     capture_output=True, text=True,
                                     timeout=self.config.get('auth_timeout_seconds', 360)+25)
            result = json.loads(process.stdout)
            result = {k: v for k, v in result.items() if k in ('ok', 'state', 'code', 'changed')}
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
