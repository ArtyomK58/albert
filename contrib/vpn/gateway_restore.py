"""Restore networking for an existing VPS session; authentication is impossible."""
import argparse
import json
import os
from pathlib import Path
import time

from modes import Modes
from targets import Targets


# Missing or stale route state that only a re-application can repair. A failed DNS or TCP
# probe may be a corporate-side outage; re-blocking for it would only break a working path.
REPAIRABLE = ('route_verification_failed', 'mode_not_ready')


class NoCredentials:
    def load(self):
        return None


class NetworkOnlyTargets(Targets):
    def mode_stop(self, *args):
        raise RuntimeError('network_restore_never_stops_sessions')

    def mode_start(self, *args):
        raise RuntimeError('network_restore_never_authenticates')


def restore(config, targets=None):
    targets = targets or NetworkOnlyTargets(config)
    modes = Modes(config, targets, NoCredentials())
    if not modes.allowed():
        return {'ok': False, 'code': 'gateway_disabled'}
    live = targets.mode_snapshot()
    if (not live['vps'].get('ok') or live['vps'].get('state') != 'connected'
            or not live['mac'].get('ok') or live['mac'].get('state') != 'disconnected'):
        return {'ok': False, 'code': 'existing_vps_session_required', 'authentication_started': False}
    result = modes.switch('vps', 'network:restore:' + str(time.time_ns()), repair_reasons=REPAIRABLE)
    return {'ok': result.get('ok') is True, 'code': result.get('code', ''), 'reason': result.get('reason', ''),
            'authentication_started': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    path = Path(a.config)
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    print(json.dumps(restore(json.loads(path.read_text()))))


if __name__ == '__main__':
    main()
