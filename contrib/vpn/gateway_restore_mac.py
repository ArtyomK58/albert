"""At most one successful route restore per Mac boot/overlay interface generation,
plus an idempotent public-site egress sync on every run."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def restore(c, run=subprocess.run):
    try:
        result = corporate(c, run)
    except Exception:
        result = {'ok': False, 'code': 'network_restore_unconfirmed', 'authentication_started': False}
    if c.get('egress_command'):
        # Public-site routes follow the current uplink on every run; corporate state is untouched.
        try:
            proc = run(c['egress_command'], capture_output=True, text=True, timeout=120)
            result['egress'] = str(json.loads(proc.stdout).get('code', ''))[:64]
        except Exception:
            result['egress'] = 'egress_unconfirmed'
    return result


def corporate(c, run):
    source = json.loads(Path(c['link_config']).read_text()).get('tailnet_source')
    text = run(['/sbin/ifconfig'], capture_output=True, text=True, timeout=5).stdout
    interface = None
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            current = line.split(':', 1)[0]
        if source and line.strip().split()[:2] == ['inet', source] and current.startswith('utun'):
            interface = current
    if not interface:
        return {'ok': False, 'code': 'waiting_for_overlay'}
    boot = run(['/usr/sbin/sysctl', '-n', 'kern.boottime'], capture_output=True, text=True, timeout=5).stdout.strip()
    generation = {'boot': boot, 'interface': interface}
    path = Path(c['restore_state'])
    if path.exists() and json.loads(path.read_text()) == generation:
        return {'ok': True, 'code': 'generation_already_verified'}
    # The remote program cannot load credentials, stop a session, or start MFA.
    proc = run(c['restore_command'], capture_output=True, text=True, timeout=900)
    result = json.loads(proc.stdout)
    if proc.returncode == 0 and result.get('ok'):
        temp = path.with_suffix('.new');temp.write_text(json.dumps(generation));temp.chmod(0o600);temp.replace(path)
    return {k: result[k] for k in ('ok', 'code', 'reason', 'authentication_started') if k in result}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    try:
        result = restore(json.loads(Path(a.config).read_text()))
    except Exception:
        result = {'ok': False, 'code': 'network_restore_unconfirmed', 'authentication_started': False}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
