"""Single-session mode switch, dormant until operator-owned acceptance gates pass."""
import fcntl
import json
from pathlib import Path
import re
import time

FROZEN = ('switching', 'outcome_unknown', 'failed', 'recovering', 'recovery_incomplete')
REQUEST_ID = r'[A-Za-z0-9:_-]{8,128}'
UNREADABLE = {'ok': False, 'code': 'operator_reconciliation_required',
              'text': 'Файл состояния шлюза нечитаем. Новые входы и автоматическое восстановление заблокированы; '
                      'файл сохранён для проверки оператором.'}


class Modes:
    def __init__(self, config, targets, credentials, sleep=time.sleep):
        self.config = config
        self.targets = targets
        self.credentials = credentials
        self.sleep = sleep

    def option(self):
        value = self.config.get('gateway_option', {})
        return value if isinstance(value, dict) else {}

    def status(self):
        c = self.option()
        active = self.allowed()
        phase = mode = None
        if self.recoverable():
            state, broken = self.load_state(self.state_path())
            phase, mode = ('unreadable', None) if broken else (state.get('phase'), state.get('mode'))
        ready = phase == 'ready' and mode in ('mac', 'vps')
        # Configured is not active: a connected VPN session alone does not route the gateway.
        if not active:
            text = 'Режим шлюза подготовлен, но выключен. Корпоративная сессия и маршруты не переключаются.'
        elif ready:
            text = ('Режим одной корпоративной сессии включён; последнее подтверждённое применение шлюза: '
                    + ('VPS.' if mode == 'vps' else 'Mac.'))
        else:
            text = 'Режим одной корпоративной сессии включён в настройках, но маршрутизация шлюза сейчас не применена.'
            if phase not in FROZEN and phase != 'unreadable':
                text += (' /vpn_vps или /vpn_mac применит её; если сессия на выбранном устройстве уже работает, '
                         'новый вход не нужен.')
        if phase in FROZEN:
            text += ' Предыдущее переключение не подтверждено; новые входы заблокированы. Снять изменения шлюза: /vpn_recover.'
        elif phase == 'unreadable':
            text += ' ' + UNREADABLE['text']
        return {'ok': True, 'text': text, 'gateway': {'enabled': active, 'active': bool(active and ready),
                'prepared': bool(c), 'phase': phase, 'mode': mode if ready else None,
                'preferred_mode': c.get('preferred_mode', 'vps'), 'network_verified': c.get('network_verified', False)}}

    @staticmethod
    def load_state(path):
        """Return (state, broken). A damaged file is reported, never rewritten."""
        if not path.exists():
            return {'epoch': 0, 'requests': {}}, False
        try:
            state = json.loads(path.read_text())
        except (OSError, ValueError):
            return None, True
        if (not isinstance(state, dict) or type(state.get('epoch')) is not int
                or not isinstance(state.get('requests'), dict)):
            return None, True
        return state, False

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
        if not isinstance(ident, str) or not re.fullmatch(REQUEST_ID, ident):
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
            loaded, broken = self.load_state(state_path)
            if broken:
                return dict(UNREADABLE)
            state = loaded
            if ident in state['requests']:
                return {'ok': True, 'code': 'already_seen', 'text': 'Этот запрос уже принят; повторный вход не отправлен.'}
            if state.get('phase') in FROZEN:
                return {'ok': False, 'code': 'operator_reconciliation_required',
                        'text': 'Предыдущее переключение нужно проверить. Новый вход автоматически не запускается. '
                                'Снять сетевые изменения шлюза: /vpn_recover.'}
            live = self.targets.mode_snapshot()
            if any(live[h].get('state') not in ('connected', 'disconnected') or not live[h].get('ok') for h in ('mac', 'vps')):
                return {'ok': False, 'code': 'uncertain_peer', 'text': 'Состояние одного устройства неизвестно. Переключение не начато.'}
            if all(live[h]['state'] == 'connected' for h in ('mac', 'vps')):
                return {'ok': False, 'code': 'conflict', 'text': 'Обнаружены две сессии. Нужна проверка владельца VPN.'}
            source = 'vps' if target == 'mac' else 'mac'
            # A healthy session on the chosen host needs no login; only its network may be missing.
            network_only = live[target]['state'] == 'connected' and live[source]['state'] == 'disconnected' and not force
            if network_only and state.get('phase') == 'ready' and state.get('mode') == target:
                if self.targets.mode_hook('verify', target).get('ok'):
                    return {'ok': True, 'code': 'already_connected',
                            'text': 'VPN и маршрутизация шлюза уже применены для ' + ('VPS.' if target == 'vps' else 'Mac.')}
            if not self.targets.mode_hook('preflight', target).get('ok'):
                return {'ok': False, 'code': 'network_preflight_failed', 'text': 'Сетевые настройки режима ещё не прошли проверку.'}
            if not network_only:
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
            if network_only:
                # No stop, start, credentials or MFA: the existing session must still be the only one.
                end = time.monotonic()
            else:
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
            where = 'VPS.' if target == 'vps' else 'Mac.'
            if network_only:
                return {'ok': True, 'code': 'network_restored',
                        'text': 'Маршрутизация шлюза применена для уже работающей сессии на ' + where
                                + ' Новый вход и MFA не выполнялись.'}
            return {'ok': True, 'code': 'switched', 'text': 'VPN переключён на ' + where}
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

    def state_path(self):
        value = self.option().get('state_file')
        return Path(value) if isinstance(value, str) and value else None

    def recoverable(self):
        # Gateway network state can exist only after a switch persisted its state file.
        path = self.state_path()
        return bool(path and path.exists())

    def recover(self, ident):
        """Owned network withdrawal. Never logs in, starts MFA, stops a session or enables the gateway.

        It is a narrow exception to the disabled gate: without a persisted switch state
        nothing was ever applied, so it returns before touching files or the hook."""
        if not self.recoverable():
            return {'ok': True, 'code': 'nothing_to_recover',
                    'text': 'Сетевых изменений шлюза нет; восстанавливать нечего. VPN-сессии не затронуты.'}
        if not isinstance(ident, str) or not re.fullmatch(REQUEST_ID, ident):
            return {'ok': False, 'code': 'invalid_request_id', 'text': 'Не удалось определить запрос.'}
        state_path = self.state_path()
        lock = state_path.with_suffix('.lock').open('a')
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'ok': False, 'code': 'busy', 'text': 'Переключение VPN ещё выполняется; восстановление не начато.'}
            state, broken = self.load_state(state_path)
            if broken:
                return dict(UNREADABLE)
            if ident in state['requests']:
                return {'ok': True, 'code': 'already_seen', 'text': 'Этот запрос уже принят; повторно не выполняется.'}
            # A new epoch fences any delayed apply that could still reach the Mac.
            target = state.get('mode') or state.get('requested_mode') or 'mac'
            state.update(epoch=state['epoch'] + 1, phase='recovering')
            state['requests'][ident] = 'running'
            self.persist(state_path, state)
            result = self.targets.mode_hook('recover', target if target in ('mac', 'vps') else 'mac')
            if result.get('ok'):
                state.update(phase='recovered', mode=None, requested_mode=None)
                state['requests'][ident] = 'done'
                text = ('Сетевые изменения шлюза сняты. VPN-сессии не запускались и не останавливались; '
                        'проверь /vpn. Новый вход — только по новой явной команде.')
                if result.get('kept'):
                    text += ' Чужие изменения сохранены.'
            else:
                state['phase'] = 'recovery_incomplete'
                state['requests'][ident] = 'outcome_unknown'
                if 'ambiguous_policy_rule' in result.get('kept', []):
                    # Repeating cannot help: the kernel could delete the other owner's rule.
                    text = ('Восстановление выполнено не полностью: найдено чужое правило маршрутизации, '
                            'неотличимое для ядра от правила шлюза. Оно не удалено; новые входы заблокированы. '
                            'Нужна проверка оператором, повтор /vpn_recover до неё не поможет.')
                else:
                    text = ('Восстановление выполнено не полностью; новые входы заблокированы. '
                            'Повтори /vpn_recover, когда устройство будет доступно, или проверь сеть вручную.')
            self.persist(state_path, state)
            return {'ok': bool(result.get('ok')), 'code': 'recovered' if result.get('ok') else 'recovery_incomplete',
                    'text': text}
        finally:
            lock.close()

    @staticmethod
    def persist(path, value):
        value['requests'] = dict(list(value['requests'].items())[-128:])
        temp = path.with_suffix('.new')
        temp.write_text(json.dumps(value))
        temp.chmod(0o600)
        temp.replace(path)


def main():
    """Root operator off-ramp when the bot is unavailable: `modes.py --config <broker-config> --recover`."""
    import argparse
    import os
    import secrets
    from targets import Targets
    p = argparse.ArgumentParser(description=main.__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--recover', action='store_true', required=True)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root_operator_required; nothing changed')
    config = json.loads(Path(a.config).read_text())
    result = Modes(config, Targets(config), None).recover('operator:recover:' + secrets.token_hex(8))
    print(json.dumps({'ok': result['ok'], 'code': result['code'], 'text': result['text']}, ensure_ascii=False))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
