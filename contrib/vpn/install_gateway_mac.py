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


LAUNCHER = '''#!/usr/bin/python3 -I
import argparse
import sys
sys.path.insert(0, "/Library/PrivilegedHelperTools/FrogVPN")
from gateway_mac import main
p = argparse.ArgumentParser()
p.add_argument("--phase", choices=["preflight", "block", "activate", "verify"], required=True)
p.add_argument("--target", choices=["mac", "vps"], required=True)
p.add_argument("--epoch", type=int, required=True)
a = p.parse_args()
sys.argv = ["frog-gateway-mac", "--config", "/Library/Application Support/FrogVPN/gateway.json",
            "--phase", a.phase, "--target", a.target, "--epoch", str(a.epoch)]
raise SystemExit(main())
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator', required=True)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root_installation_required; no files changed')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', a.operator):
        raise SystemExit('invalid_operator')
    config = Path(a.config)
    c = json.loads(config.read_text())
    if c.get('enabled') is not False or c.get('prepare_only') is not True:
        raise SystemExit('installer accepts disabled manifests only')
    root = Path('/Library/PrivilegedHelperTools/FrogVPN')
    data = Path('/Library/Application Support/FrogVPN')
    if root.exists() or data.exists():
        raise SystemExit('existing installation requires backed-up operator upgrade')
    sudoers = Path('/etc/sudoers.d/frog-vpn-gateway')
    if sudoers.exists():
        raise SystemExit('existing sudo policy requires review')
    rule = a.operator + ' ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/FrogVPN/run *\n'
    with tempfile.NamedTemporaryFile(mode='w', prefix='frog-sudo-check-') as f:
        f.write(rule)
        f.flush()
        subprocess.run(['/usr/sbin/visudo', '-cf', f.name], capture_output=True, check=True)
    root.mkdir(mode=0o755)
    data.mkdir(mode=0o700)
    try:
        for name in ['gateway_mac.py', 'gateway_plan.py']:
            shutil.copyfile(Path(__file__).with_name(name), root / name)
            (root / name).chmod(0o644)
        (root / 'run').write_text(LAUNCHER)
        (root / 'run').chmod(0o755)
        shutil.copyfile(config, data / 'gateway.json')
        (data / 'gateway.json').chmod(0o600)
        sudoers.write_text(rule)
        sudoers.chmod(0o440)
        subprocess.run(['/usr/sbin/visudo', '-c'], capture_output=True, check=True)
    except Exception:
        sudoers.unlink(missing_ok=True)
        shutil.rmtree(root)
        shutil.rmtree(data)
        raise
    print(json.dumps({'installed': True, 'enabled': False, 'network_commands_executed': False}))


if __name__ == '__main__':
    main()
