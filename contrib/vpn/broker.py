"""Owner-bound RPC broker. The model never receives credentials or an auth tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import threading
import time
import urllib.request

from targets import Credentials, Targets


class Broker:
    def __init__(self, config, targets=None, credentials=None):
        self.config = config
        self.targets = targets or Targets(config)
        self.credentials = credentials or Credentials(config['credential_file'])
        self.state_path = Path(config['state_file'])
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {'sessions': {}, 'requests': {}}
        self.lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.enrollment = None
        # A process crash must not silently restart a half-completed MFA flow.
        for record in self.state['requests'].values():
            if record.get('state') == 'running':
                record.update(state='outcome_unknown')

    def persist(self):
        with self.state_lock:
            self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.state['requests'] = dict(list(self.state['requests'].items())[-128:])
            tmp = self.state_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self.state))
            tmp.chmod(0o600)
            tmp.replace(self.state_path)

    def notify(self, text, setup_url=None):
        token = os.environ.get(self.config['telegram_token_env'], '')
        if not token:
            return False
        payload = {'chat_id': self.config['owner_id'], 'text': text,
                   'reply_markup': {'keyboard': [['Подключись', 'Переподключись'], ['Статус VPN']], 'resize_keyboard': True}}
        if setup_url:
            payload['reply_markup'] = {'inline_keyboard': [[{'text': 'Ввести реквизиты VPN', 'url': setup_url}]]}
        request = urllib.request.Request('https://api.telegram.org/bot' + token + '/sendMessage',
                                         data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return bool(json.load(response).get('ok'))
        except Exception:
            return False

    def status(self):
        statuses = {'vps': self.targets.vps_status(), 'mac': self.targets.mac('status')}
        lines = ['VPN']
        labels = {'connected': 'подключён', 'disconnected': 'не подключён',
                  'connecting': 'подключается', 'disconnecting': 'отключается', 'unknown': 'нет связи'}
        for host, label in [('vps', 'VPS'), ('mac', 'Mac')]:
            state = statuses[host].get('state', 'unknown')
            text = label + ': ' + labels.get(state, 'нет связи')
            session = self.state['sessions'].get(host, {})
            start = session.get('started_at')
            if start and state == 'connected':
                remaining = max(0, int(start + self.config['session_seconds'] - time.time()))
                text += f'; ориентировочно {remaining // 3600} ч {(remaining % 3600) // 60} мин до повторного входа'
            elif state == 'connected':
                text += '; остаток сессии пока не определён'
            lines.append(text)
        if not self.credentials.load():
            lines.append('Реквизиты нужно сохранить один раз: /vpn_setup')
        return {'ok': True, 'text': '\n'.join(lines), 'targets': statuses}

    def setup(self):
        token = secrets.token_urlsafe(32)
        with self.state_lock:
            self.enrollment = (hashlib.sha256(token.encode()).digest(), time.time() + 600)
        url = self.config['public_url'].rstrip('/') + '/vpn/#' + token
        # The capability link travels directly to the owner's chat, not history/LLM.
        sent = self.notify('Один раз сохрани логин и пароль VPN на защищённой странице. После этого достаточно команды «переподключись» и подтверждения MFA. Ссылка действует 10 минут.', url)
        return {'ok': sent, 'text': 'Отправлена одноразовая ссылка для реквизитов VPN.' if sent else 'Не удалось отправить ссылку. Повтори /vpn_setup.'}

    def enrollment_valid(self, token):
        with self.state_lock:
            return bool(self.enrollment and self.enrollment[1] > time.time()
                        and secrets.compare_digest(self.enrollment[0], hashlib.sha256(token.encode()).digest()))

    def enroll(self, token, credentials):
        with self.state_lock:
            if not self.enrollment_valid(token):
                raise ValueError('expired_link')
            self.credentials.save(credentials)
            self.enrollment = None

    def handle(self, request):
        # This field is supplied only by the deterministic host adapter.
        if str(request.get('actor')) != str(self.config['owner_id']):
            return {'ok': False, 'text': 'Управление VPN доступно только владельцу.'}
        if self.config.get('maintenance') and request.get('action') != 'status':
            return {'ok': False, 'text': self.config.get('maintenance_message',
                    'Автоматическое управление VPN временно приостановлено для проверки устойчивости. Используй штатный клиент OpenVPN.')}
        action = request.get('action')
        if action == 'status':
            result = self.status()
            if self.config.get('maintenance'):
                result['text'] += '\nАвтоподключение временно заблокировано; доступна только проверка состояния.'
            return result
        if action == 'setup':
            return self.setup()
        if action not in ('connect', 'reconnect'):
            return {'ok': False, 'text': 'Неизвестная команда VPN.'}
        if not self.config.get('simultaneous_verified'):
            return {'ok': False, 'text': 'Одновременное подключение Mac и VPS ещё не проверено. Автоматический вход заблокирован до проверки устойчивости.'}
        hosts = request.get('targets', ['vps', 'mac'])
        if not isinstance(hosts, list) or not hosts or any(host not in ('vps', 'mac') for host in hosts):
            return {'ok': False, 'text': 'Неизвестное устройство VPN.'}
        hosts = [host for host in ['vps', 'mac'] if host in hosts]
        ident = request.get('request_id', '')
        if not isinstance(ident, str) or not 8 <= len(ident) <= 128:
            return {'ok': False, 'text': 'Не удалось определить запрос.'}
        if ident in self.state['requests']:
            return {'ok': True, 'text': 'Этот запрос уже принят. Новый запрос MFA не отправлен.'}
        credentials = self.credentials.load()
        if credentials is None:
            return {'ok': False, 'text': 'Сначала один раз сохрани реквизиты VPN: /vpn_setup'}
        if not self.lock.acquire(blocking=False):
            return {'ok': True, 'text': 'Подключение уже выполняется. Подтверди текущий запрос MFA.'}
        self.state['requests'][ident] = {'state': 'running', 'started_at': time.time()}
        self.persist()
        threading.Thread(target=self.job, args=(ident, action, credentials, hosts), daemon=True).start()
        devices = 'VPS и Mac' if len(hosts)==2 else ('VPS' if hosts[0]=='vps' else 'Mac')
        return {'ok': True, 'text': f'Запускаю VPN на {devices}. Подтверди запросы в Multifactor; пришлю результат.'}

    def job(self, ident, action, credentials, hosts):
        result = {}
        try:
            initial = {'vps': self.targets.vps_status(), 'mac': self.targets.mac('status')}
            if 'vps' not in hosts:
                result['vps'] = dict(self.targets.vps_status(), changed=False)
            if 'mac' not in hosts:
                result['mac'] = dict(self.targets.mac('status'), changed=False)
            for host in ['vps', 'mac']:
                if host not in hosts:
                    continue
                if action == 'connect':
                    current = initial[host]
                    if current.get('ok') and current.get('state') == 'connected':
                        result[host] = dict(current, changed=False)
                        continue
                self.notify(f'VPN {"VPS" if host == "vps" else "Mac"}: начинается вход. Подтверди запрос Multifactor, когда он появится.')
                try:
                    value = (self.targets.vps_login(credentials, action == 'reconnect',
                             on_pending=lambda: self.notify('VPN VPS: началась проверка входа. Подтверди запрос Multifactor сразу после появления — позднее подтверждение сервер может отклонить.')) if host == 'vps'
                             else self.targets.mac(action, credentials, ident + ':mac'))
                except Exception:
                    value = {'ok': False, 'state': 'unknown', 'code': 'controller_unavailable'}
                result[host] = value
                if value.get('ok') and value.get('state') == 'connected' and value.get('changed'):
                    self.state['sessions'][host] = {'started_at': time.time(), 'warned': False}
                    self.persist()
            for _ in range(2):
                live = {'vps': self.targets.vps_status(), 'mac': self.targets.mac('status')}
                for host in ['vps', 'mac']:
                    result[host]['verified_state'] = live[host].get('state', 'unknown')
                    if not live[host].get('ok') or live[host].get('state') != 'connected':
                        if result[host].get('ok'):
                            result[host]['code'] = 'connection_not_retained'
                        result[host].update(ok=False, state=live[host].get('state', 'unknown'))
                        self.state['sessions'].pop(host, None)
                    elif result[host].get('code') == 'authentication_or_network_timeout':
                        result[host].update(ok=True, state='connected', code='connected_after_status_refresh')
                if _ == 0:
                    time.sleep(self.config.get('verification_delay_seconds', 1))
            self.state['requests'][ident].update(state='done', results=result)
            self.persist()
            lines = ['VPN: результат']
            reasons = {'auth-mfa-timeout': 'подтверждение MFA не получено вовремя',
                       'auth-credentials-rejected': 'сервер отклонил аутентификацию',
                       'auth-session-limit': 'сервер ограничил число одновременных подключений',
                       'auth-client-policy': 'сервер отклонил тип или версию клиента',
                       'auth-account-locked': 'сервер сообщил о блокировке учётной записи',
                       'auth-cipher-negotiation': 'не согласованы параметры шифрования',
                       'native_credential_update_required': 'нужно один раз обновить сохранённые реквизиты на Mac'}
            for host, label in [('vps', 'VPS'), ('mac', 'Mac')]:
                value = result[host]
                lines.append(label + ': ' + ('подключён' if value.get('ok') and value.get('state') == 'connected'
                             else reasons.get(value.get('code'), 'вход не подтверждён или устройство недоступно')))
            self.notify('\n'.join(lines))
        finally:
            # Only metadata survives; credentials remain in this worker's memory.
            credentials.clear()
            self.lock.release()

    def tick(self):
        if self.config.get('maintenance'):
            return
        now = time.time()
        for host, session in self.state['sessions'].items():
            if not session.get('warned') and now >= session['started_at'] + self.config['session_seconds'] - self.config['warning_seconds']:
                remaining = max(0, int((session['started_at'] + self.config['session_seconds'] - now) / 60))
                # Persist before delivery. An unknown Telegram outcome must not
                # produce duplicate alerts every scheduler tick.
                session['warned'] = True
                self.persist()
                self.notify(f'VPN {host.upper() if host == "vps" else "Mac"}: ориентировочно через {remaining} мин потребуется новый вход. Нажми «Переподключись», когда удобно подтвердить MFA.')


def serve(config):
    broker = Broker(config)
    from enrollment import start_web
    start_web(config, broker)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            uid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
            if uid not in (0, config['client_uid']):
                return
            self.request.settimeout(20)
            raw = self.rfile.readline(8193)
            try:
                if len(raw) > 8192 or not raw.endswith(b'\n'):
                    raise ValueError()
                result = broker.handle(json.loads(raw))
            except Exception:
                result = {'ok': False, 'text': 'Контроллер VPN временно недоступен.'}
            self.wfile.write(json.dumps(result).encode() + b'\n')

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    path = Path(config['socket'])
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o750)
    os.chown(path.parent, 0, config['client_gid'])
    if path.exists():
        path.unlink()
    server = Server(str(path), Handler)
    os.chmod(path, 0o660)
    os.chown(path, 0, config['client_gid'])

    def ticker():
        while True:
            time.sleep(30)
            try:
                broker.tick()
            except Exception:
                pass

    threading.Thread(target=ticker, daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    serve(json.loads(Path(parser.parse_args().config).read_text()))
