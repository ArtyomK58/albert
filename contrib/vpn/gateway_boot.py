"""Reinstall the owned blocked overlay guard on boot. Never starts authentication."""
import argparse
import json
import os
from pathlib import Path

from gateway_hook import NetworkHook, signature
from gateway_plan import acquire, validate
from modes import Modes


def bootstrap(c, hook=None):
    if c.get('enabled') is not True or c.get('prepare_only') is not False:
        return {'ok': False, 'code': 'gateway_disabled'}
    validate(c['network'])
    if c['network'].get('transport') != 'tailnet':
        return {'ok': False, 'code': 'overlay_boot_guard_only'}
    hook = hook or NetworkHook(c)
    owner = hook.owner()
    if owner and owner.get('signature') != signature(c['network']):
        return {'ok': False, 'code': 'network_spec_requires_operator'}
    hook.host_filter(False)
    path = Path(c['mode_state'])
    state, broken = Modes.load_state(path)
    # Never erase an unknown authentication result. A previously ready mode loses
    # its routing/session on reboot and cannot still be advertised as active.
    if not broken and path.exists() and state.get('phase') == 'ready':
        state.update(epoch=state['epoch'] + 1, phase='recovered', mode=None, requested_mode=None)
        Modes.persist(path, state)
    return {'ok': True, 'code': 'corporate_forwarding_blocked', 'authentication_started': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    path = Path(a.config)
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    c = json.loads(path.read_text())
    with Path(c['lock_file']).open('a') as lock:
        if not acquire(lock, 10):
            return 1
        result = bootstrap(c)
    print(json.dumps(result))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
