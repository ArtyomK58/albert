"""Capability-bound one-time enrollment. Serve only behind the configured HTTPS origin."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit


def start_web(config, broker):
    root = Path(__file__).parent / 'web'
    origin = config['public_url'].rstrip('/')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, status, body, content_type='application/json'):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            files = {'/vpn/': ('index.html', 'text/html; charset=utf-8'),
                     '/vpn/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                     '/vpn/style.css': ('style.css', 'text/css; charset=utf-8')}
            item = files.get(urlsplit(self.path).path)
            if not item:
                self.send(404, {'ok': False})
                return
            self.send(200, (root / item[0]).read_bytes(), item[1])

        def do_POST(self):
            # Token is in the URL fragment and Authorization header, never a
            # request path/query, so reverse-proxy access logs cannot capture it.
            if self.headers.get('Origin') != origin:
                self.send(403, {'ok': False, 'code': 'origin_rejected'})
                return
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            if not broker.enrollment_valid(token):
                self.send(403, {'ok': False, 'code': 'expired_link'})
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8192:
                    raise ValueError()
                if self.path == '/vpn/check':
                    self.rfile.read(size)
                    self.send(200, {'ok': True})
                elif self.path == '/vpn/enroll':
                    body = json.loads(self.rfile.read(size))
                    broker.enroll(token, body)
                    self.send(200, {'ok': True})
                else:
                    self.send(404, {'ok': False})
            except (ValueError, TypeError):
                self.send(400, {'ok': False, 'code': 'invalid_credentials'})
            except Exception:
                self.send(503, {'ok': False, 'code': 'storage_unavailable'})

    server = ThreadingHTTPServer(('127.0.0.1', config['web_port']), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
