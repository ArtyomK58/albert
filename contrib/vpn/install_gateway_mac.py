#!/usr/bin/env python3
"""Stageable operator installer. Root installation does not activate networking."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
p.add_argument("--phase", choices=["preflight", "block", "activate", "verify", "recover"], required=True)
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator', required=True)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root_installation_required; no files changed')
    print(json.dumps(install(a.operator, a.config)))


if __name__ == '__main__':
    main()
