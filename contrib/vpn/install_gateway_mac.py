#!/usr/bin/env python3
"""Stageable operator installer. Root installation does not activate networking."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path('/Library/PrivilegedHelperTools/FrogVPN')
DATA = Path('/Library/Application Support/FrogVPN')
SUDOERS = Path('/etc/sudoers.d/frog-vpn-gateway')

LAUNCHER = '''#!/usr/bin/python3 -I
import argparse
import sys
sys.path.insert(0, "/Library/PrivilegedHelperTools/FrogVPN")
from gateway_mac import main
p = argparse.ArgumentParser()
p.add_argument("--phase", choices=["preflight", "block", "activate", "verify", "recover", "egress"], required=True)
p.add_argument("--target", choices=["mac", "vps"], required=True)
p.add_argument("--epoch", type=int, required=True)
a = p.parse_args()
sys.argv = ["frog-gateway-mac", "--config", "/Library/Application Support/FrogVPN/gateway.json",
            "--phase", a.phase, "--target", a.target, "--epoch", str(a.epoch)]
raise SystemExit(main())
'''


def install(operator, config, root=ROOT, data=DATA, sudoers=SUDOERS, run=subprocess.run):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', operator):
        raise SystemExit('invalid_operator')
    c = json.loads(Path(config).read_text())
    if c.get('enabled') is not False or c.get('prepare_only') is not True:
        raise SystemExit('installer accepts disabled manifests only')
    if root.exists() or data.exists():
        raise SystemExit('existing installation requires backed-up operator upgrade')
    if sudoers.exists():
        raise SystemExit('existing sudo policy requires review')
    rule = operator + ' ALL=(root) NOPASSWD: ' + str(root / 'run') + ' *\n'
    with tempfile.NamedTemporaryFile(mode='w', prefix='frog-sudo-check-') as f:
        f.write(rule)
        f.flush()
        run(['/usr/sbin/visudo', '-cf', f.name], capture_output=True, check=True)
    created = []  # Only what this run created is removed on failure.
    try:
        for path, mode in ((root, 0o755), (data, 0o700)):
            path.mkdir(mode=mode)
            created.append(path)
        for name in ['gateway_mac.py', 'gateway_plan.py']:
            shutil.copyfile(Path(__file__).with_name(name), root / name)
            (root / name).chmod(0o644)
        (root / 'run').write_text(LAUNCHER)
        (root / 'run').chmod(0o755)
        shutil.copyfile(config, data / 'gateway.json')
        (data / 'gateway.json').chmod(0o600)
        created.append(sudoers)
        sudoers.write_text(rule)
        sudoers.chmod(0o440)
        run(['/usr/sbin/visudo', '-c'], capture_output=True, check=True)
    except BaseException:
        for path in reversed(created):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        raise
    return {'installed': True, 'enabled': False, 'network_commands_executed': False}


MODULES = ('gateway_mac.py', 'gateway_plan.py')
# The only launcher an upgrade may replace: the same fixed paths without the egress phase.
PREVIOUS_LAUNCHER = LAUNCHER.replace(', "egress"]', ']')
EGRESS_KEYS = {'local_egress_prefixes', 'local_egress_interface'}


def replace(path, data, mode):
    temp = path.with_name(path.name + '.new')
    temp.write_bytes(data)
    temp.chmod(mode)
    temp.replace(path)


def upgrade(egress=None, root=ROOT, data=DATA):
    """Replace helper modules (and optionally the local-egress keys), keeping one .prev generation.

    The launcher, sudo policy and every other operator setting stay as installed. No network
    command runs: the new routes appear only at the next explicit activation."""
    launcher = (root / 'run').read_text()
    if launcher not in (LAUNCHER, PREVIOUS_LAUNCHER):
        raise SystemExit('installed launcher differs; review before upgrade')
    config = data / 'gateway.json'
    current = json.loads(config.read_text())
    if egress is not None:
        patch = json.loads(Path(egress).read_text())
        if not patch or set(patch) - EGRESS_KEYS:
            raise SystemExit('egress file may contain only ' + ', '.join(sorted(EGRESS_KEYS)))
        current['network'].update(patch)
        sys.path.insert(0, str(Path(__file__).parent))
        from gateway_plan import validate
        validate(current['network'])  # The new validator, before anything is replaced.
    for name in MODULES + ('run',):
        replace(root / (name + '.prev'), (root / name).read_bytes(), 0o644)
    if egress is not None:
        replace(data / 'gateway.json.prev', config.read_bytes(), 0o600)
        replace(config, json.dumps(current, indent=2).encode(), 0o600)
    for name in MODULES:
        replace(root / name, Path(__file__).with_name(name).read_bytes(), 0o644)
    replace(root / 'run', LAUNCHER.encode(), 0o755)
    return {'upgraded': True, 'egress_changed': egress is not None, 'network_commands_executed': False}


def rollback(root=ROOT, data=DATA):
    """Restore the .prev generation written by upgrade. Network state is not touched."""
    restored = []
    for path in [root / name for name in MODULES + ('run',)] + [data / 'gateway.json']:
        prev = path.with_name(path.name + '.prev')
        if prev.exists():
            mode = 0o600 if path.parent == data else 0o755 if path.name == 'run' else 0o644
            replace(path, prev.read_bytes(), mode)
            restored.append(path.name)
    return {'restored': restored, 'network_commands_executed': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator')
    p.add_argument('--config')
    p.add_argument('--upgrade', action='store_true')
    p.add_argument('--egress', help='JSON with only the local-egress keys (upgrade only)')
    p.add_argument('--rollback', action='store_true')
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root_installation_required; no files changed')
    if a.rollback:
        print(json.dumps(rollback()))
    elif a.upgrade:
        print(json.dumps(upgrade(a.egress)))
    elif a.operator and a.config and not a.egress:
        print(json.dumps(install(a.operator, a.config)))
    else:
        raise SystemExit('use --operator/--config, --upgrade [--egress FILE] or --rollback')


if __name__ == '__main__':
    main()
