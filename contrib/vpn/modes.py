"""Single-session mode switch, dormant until operator-owned acceptance gates pass."""
import fcntl
import json
from pathlib import Path
import re
import time


class Modes:
    def __init__(self, config, targets, credentials, sleep=time.sleep):
        self.config = config
        self.targets = targets
        self.credentials = credentials
        self.sleep = sleep

    def option(self):
        return self.config.get('gateway_option', {})

    def status(self):
        c = self.option()
        active = self.allowed()
        text = ('Режим шлюза подготовлен, но выключен. Корпоративная сессия и маршруты не переключаются.'
                if not active else 'Режим одной корпоративной сессии включён.')
        return {'ok': True, 'text': text, 'gateway': {'enabled': active, 'prepared': bool(c),
                'preferred_mode': c.get('preferred_mode', 'vps'), 'network_verified': c.get('network_verified', False)}}

    def allowed(self):
        c = self.option()
        return (c.get('enabled') is True and c.get('prepare_only') is False
                and c.get('network_verified') is True and not self.config.get('maintenance')
                and isinstance(c.get('network_hook'), list) and bool(c['network_hook']))

    def switch(self, target, ident, force=False):
        if target not in ('mac', 'vps'):
            return {'ok': False, 'code': 'invalid_mode', 'text': 'Неизвестный режим VPN.'}
        # This must precede even credential loading, target probing and filesystem writes.
        if not self.allowed():
            return dict(self.status(), ok=False, code='gateway_disabled')
        if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9:_-]{8,128}', ident):
            return {'ok': False, 'code': 'invalid_request_id', 'text': 'Не удалось определить запрос.'}
        c = self.option()
        state_path = Path(c['state_file'])
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = state_path.with_suffix('.lock').open('a')
        credentials = None
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'ok': False, 'code': 'busy', 'text': 'Переключение VPN уже выполняется.'}
            state = json.loads(state_path.read_text()) if state_path.exists() else {'epoch': 0, 'requests': {}}
            if ident in state['requests']:
                return {'ok': True, 'code': 'already_seen', 'text': 'Этот запрос уже принят; повторный вход не отправлен.'}
            if state.get('phase') in ('switching', 'outcome_unknown', 'failed'):
                return {'ok': False, 'code': 'operator_reconciliation_required',
                        'text': 'Предыдущее переключение нужно проверить. Новый вход автоматически не запускается.'}
            live = self.targets.mode_snapshot()
            if any(live[h].get('state') not in ('connected', 'disconnected') or not live[h].get('ok') for h in ('mac', 'vps')):
                return {'ok': False, 'code': 'uncertain_peer', 'text': 'Состояние одного устройства неизвестно. Переключение не начато.'}
            if all(live[h]['state'] == 'connected' for h in ('mac', 'vps')):
                return {'ok': False, 'code': 'conflict', 'text': 'Обнаружены две сессии. Нужна проверка владельца VPN.'}
            source = 'vps' if target == 'mac' else 'mac'
            if live[target]['state'] == 'connected' and live[source]['state'] == 'disconnected' and not force:
                return {'ok': True, 'code': 'already_connected', 'text': 'VPN уже подключён на выбранном устройстве.'}
            if not self.targets.mode_hook('preflight', target).get('ok'):
                return {'ok': False, 'code': 'network_preflight_failed', 'text': 'Сетевые настройки режима ещё не прошли проверку.'}
            credentials = self.credentials.load()
            if not credentials:
                return {'ok': False, 'code': 'credentials_missing', 'text': 'Сначала сохрани реквизиты VPN.'}
            state.update(epoch=state['epoch'] + 1, phase='switching', requested_mode=target)
            epoch = state['epoch']
            state['requests'][ident] = 'running'
            self.persist(state_path, state)
            # Withdraw gateway routing before releasing its session; never change host forwarding.
            if not self.targets.mode_hook('block', target).get('ok'):
                raise RuntimeError('gateway_block_failed')
            old = target if live[target]['state'] == 'connected' else source
            if live[old]['state'] == 'connected':
                result = self.targets.mode_stop(old, ident, epoch)
                if not result.get('ok'):
                    raise RuntimeError('stop_not_confirmed')
            after = self.targets.mode_snapshot()
            if any(after[h].get('state') != 'disconnected' or not after[h].get('ok') for h in ('mac', 'vps')):
                raise RuntimeError('stop_not_confirmed')
            result = self.targets.mode_start(target, credentials, ident, epoch)
            if not result.get('ok') or result.get('state') != 'connected':
                raise RuntimeError('new_session_not_confirmed')
            end = time.monotonic() + max(60, c.get('verify_seconds', 60))
            while True:
                snap = self.targets.mode_snapshot()
                if (not snap[target].get('ok') or snap[target].get('state') != 'connected'
                        or not snap[source].get('ok') or snap[source].get('state') != 'disconnected'):
                    raise RuntimeError('connection_not_retained')
                if time.monotonic() >= end:
                    break
                self.sleep(min(2, max(0, end - time.monotonic())))
            if not self.targets.mode_hook('activate', target).get('ok'):
                raise RuntimeError('gateway_activation_failed')
            if not self.targets.mode_hook('verify', target).get('ok'):
                raise RuntimeError('network_verification_failed')
            state.update(phase='ready', mode=target)
            state['requests'][ident] = 'done'
            self.persist(state_path, state)
            return {'ok': True, 'code': 'switched', 'text': 'VPN переключён на ' + ('VPS.' if target == 'vps' else 'Mac.')}
        except Exception:
            # Do not chase another session, retry MFA, restore the old session or stop a foreign one.
            if 'state' in locals() and state.get('phase') == 'switching':
                try:
                    self.targets.mode_hook('block', target)
                except Exception:
                    pass
                state['phase'] = 'outcome_unknown'
                state['requests'][ident] = 'outcome_unknown'
                self.persist(state_path, state)
            return {'ok': False, 'code': 'outcome_unknown',
                    'text': 'Переключение не подтверждено. Автоматический откат и повторный MFA не запускаются.'}
        finally:
            if credentials:
                credentials.clear()
            lock.close()

    @staticmethod
    def persist(path, value):
        value['requests'] = dict(list(value['requests'].items())[-128:])
        temp = path.with_suffix('.new')
        temp.write_text(json.dumps(value))
        temp.chmod(0o600)
        temp.replace(path)
