#!/usr/bin/env python3
"""Privileged Mac route/DNS/PF helper, installed only during attended activation."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess

from gateway_plan import validate


class MacNetwork:
    def __init__(self, config, run=subprocess.run):
        self.c = config
        self.s = config.get('network', {})
        self.run = run

    def command(self, args, data=None, check=True):
        r = self.run(args, input=data, capture_output=True, text=True, timeout=20)
        if check and r.returncode:
            raise RuntimeError('mac_network_command_failed')
        return r

    def vpn_interface(self):
        source = str(ipaddress.ip_network(self.s['mac_peer']).network_address)
        current = None
        for line in self.command(['/sbin/ifconfig']).stdout.splitlines():
            if line and not line[0].isspace():
                current = line.split(':', 1)[0]
            if line.strip().split()[:2] == ['inet', source]:
                if not current or not re.fullmatch(r'utun[0-9]+', current):
                    raise RuntimeError('unexpected_personal_vpn_interface')
                return current
        raise RuntimeError('personal_vpn_source_absent')

    def route_interface(self, prefix):
        r = self.command(['/sbin/route', '-n', 'get', '-net', prefix], check=False)
        match = re.search(r'(?m)^\s*interface:\s*(utun[0-9]+)\s*$', r.stdout)
        return match.group(1) if match else None

    def guard(self, interface=None):
        # The stock Apple wildcard anchor must already be loaded; never replace pf.conf.
        prefixes = ', '.join(self.s['corporate_prefixes'])
        qualifier = ('on ! ' + interface + ' ') if interface else ''
        body = 'table <frog_corp> const { ' + prefixes + ' }\n'
        body += 'block drop out quick ' + qualifier + 'inet to <frog_corp>\n'
        self.command(['/sbin/pfctl', '-a', 'com.apple/frog-corp', '-f', '-'], body)
        info = self.command(['/sbin/pfctl', '-s', 'info']).stdout
        if 'Status: Enabled' not in info:
            if not self.c.get('allow_pf_enable'):
                raise RuntimeError('pf_enable_requires_operator_acceptance')
            # Keep PF enabled throughout mode changes; do not disable another owner's PF.
            enabled = self.command(['/sbin/pfctl', '-E'])
            token = re.search(r'Token\s*:\s*([0-9]+)', enabled.stdout + enabled.stderr)
            if not token:
                raise RuntimeError('pf_reference_receipt_missing')
            reference = Path(self.c['state_file']).with_suffix('.pf-token')
            reference.write_text(token.group(1))
            reference.chmod(0o600)
        for prefix in self.s['corporate_prefixes']:
            self.command(['/sbin/pfctl', '-k', '0.0.0.0/0', '-k', prefix])

    def withdraw(self, state):
        # Never overwrite or delete a file modified by somebody else.
        for zone, content in state.get('resolvers', {}).items():
            p = Path(self.c['resolver_dir']) / zone
            if p.exists():
                if p.read_text() != content:
                    raise RuntimeError('resolver_changed_by_another_owner')
                p.unlink()
        state['resolvers'] = {}
        for prefix, interface in state.get('routes', {}).items():
            if self.route_interface(prefix) == interface:
                self.command(['/sbin/route', '-n', 'delete', '-net', prefix, '-interface', interface])
        state['routes'] = {}

    def preflight(self, target):
        if not all(self.c.get(k) is True for k in ('pf_policy_verified', 'dns_fail_closed_verified', 'ipv6_policy_verified')):
            raise RuntimeError('mac_operator_acceptance_missing')
        if 'anchor "com.apple/*"' not in self.command(['/sbin/pfctl', '-sr']).stdout:
            raise RuntimeError('expected_pf_anchor_missing')
        if target == 'vps':
            self.vpn_interface()
        for zone in self.s['dns_zones']:
            p = Path(self.c['resolver_dir']) / zone
            if p.exists() and p.read_text() != 'nameserver ' + self.s['corporate_dns'] + '\n':
                raise RuntimeError('existing_resolver_requires_review')

    def execute(self, phase, target, epoch):
        if self.c.get('enabled') is not True or self.c.get('prepare_only') is not False:
            return {'ok': False, 'code': 'gateway_disabled'}
        if phase not in ('preflight', 'block', 'activate', 'verify') or target not in ('mac', 'vps') or type(epoch) is not int or epoch < 0:
            return {'ok': False, 'code': 'invalid_request'}
        validate(self.s)
        path = Path(self.c['state_file'])
        state = json.loads(path.read_text()) if path.exists() else {'epoch': 0, 'routes': {}, 'resolvers': {}}
        if epoch < state['epoch']:
            return {'ok': False, 'code': 'stale_mode_epoch'}
        try:
            if phase == 'preflight':
                self.preflight(target)
                return {'ok': True}
            if phase == 'verify':
                if state.get('mode') != target or state.get('phase') != 'ready':
                    raise RuntimeError('mode_not_ready')
                expected = state.get('active_interface')
                if not expected or any(self.route_interface(p) != expected for p in self.s['corporate_prefixes']):
                    raise RuntimeError('route_verification_failed')
                # DNS/IPv6 leak acceptance is a separate attended gate, never inferred from this TCP check.
                address = socket.gethostbyname(self.c['probe_host'])
                if not any(ipaddress.ip_address(address) in ipaddress.ip_network(p) for p in self.s['corporate_prefixes']):
                    raise RuntimeError('probe_not_on_corporate_route')
                with socket.create_connection((address, self.c.get('probe_port', 443)), timeout=5):
                    pass
                return {'ok': True}
            state.update(epoch=epoch, phase='applying')
            self.save(path, state)  # Lost replies cannot erase ownership/fencing.
            self.guard()
            self.withdraw(state)
            if phase == 'block':
                state['phase'] = 'blocked'
            elif target == 'vps':
                interface = self.vpn_interface()
                for prefix in self.s['corporate_prefixes']:
                    self.command(['/sbin/route', '-n', 'add', '-net', prefix, '-interface', interface])
                    state['routes'][prefix] = interface
                    self.save(path, state)
                directory = Path(self.c['resolver_dir'])
                directory.mkdir(exist_ok=True)
                for zone in self.s['dns_zones']:
                    p = directory / zone
                    content = 'nameserver ' + self.s['corporate_dns'] + '\n'
                    if p.exists():
                        if p.read_text() != content:
                            raise RuntimeError('resolver_requires_review')
                    else:
                        p.write_text(content)
                        p.chmod(0o644)
                        state['resolvers'][zone] = content
                        self.save(path, state)
                self.guard(interface)
                state.update(mode=target, phase='ready', active_interface=interface)
            else:
                interface = self.route_interface(self.s['corporate_dns'])
                try:
                    personal = self.vpn_interface()
                except RuntimeError:
                    personal = None
                if not interface or interface == personal:
                    raise RuntimeError('native_corporate_route_missing')
                self.guard(interface)
                state.update(mode=target, phase='ready', active_interface=interface)
            self.save(path, state)
            return {'ok': True}
        except Exception:
            if phase == 'preflight':
                return {'ok': False, 'code': 'mac_network_preflight_failed'}
            try:
                self.guard()
            except Exception:
                pass
            state.update(epoch=epoch, phase='outcome_unknown')
            self.save(path, state)
            return {'ok': False, 'code': 'mac_network_phase_failed'}

    @staticmethod
    def save(path, state):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        p = path.with_suffix('.new')
        p.write_text(json.dumps(state))
        p.chmod(0o600)
        p.replace(path)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--phase', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--epoch', required=True, type=int)
    a = p.parse_args()
    path = Path(a.config)
    c = json.loads(path.read_text())
    if not c.get('enabled') or c.get('prepare_only', True):
        print(json.dumps({'ok': False, 'code': 'gateway_disabled'}))
        return 1
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    with Path(c['lock_file']).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = MacNetwork(c).execute(a.phase, a.target, a.epoch)
    print(json.dumps(result))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
