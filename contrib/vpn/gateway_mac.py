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
import threading
import time

from gateway_plan import (Deadline, MAC_COMMAND_TIMEOUT, MAC_FAILSAFE_RESERVE, MAC_HELPER_BUDGET,
                          MAC_LOCK_WAIT, acquire, validate)

ANCHOR = 'com.apple/frog-corp'
PHASES = ('preflight', 'block', 'activate', 'verify', 'recover')


def bounded_resolve(host, timeout):
    box = {}

    def work():
        try:
            box['address'] = socket.gethostbyname(host)
        except OSError:
            pass
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(timeout)
    if 'address' not in box:
        raise RuntimeError('probe_resolution_failed')
    return box['address']


class MacNetwork:
    def __init__(self, config, run=None, clock=time.monotonic, deadline=None,
                 resolve=bounded_resolve, connect=socket.create_connection):
        self.c = config
        self.s = config.get('network', {})
        self.run = run or subprocess.run
        self.deadline = deadline or Deadline(MAC_HELPER_BUDGET, clock)
        self.resolve = resolve
        self.connect = connect

    def command(self, args, data=None, check=True, reserve=MAC_FAILSAFE_RESERVE):
        timeout = self.deadline.admit(MAC_COMMAND_TIMEOUT, reserve)
        r = self.run(args, input=data, capture_output=True, text=True, timeout=timeout)
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

    def route_fields(self, prefix):
        r = self.command(['/sbin/route', '-n', 'get', '-net', prefix], check=False)
        return dict(re.findall(r'(?m)^\s*(destination|mask|interface):\s*(\S+)\s*$', r.stdout))

    def route_interface(self, prefix):
        # Best route actually used for the destination.
        name = self.route_fields(prefix).get('interface', '')
        return name if re.fullmatch(r'utun[0-9]+', name) else None

    def exact_route(self, prefix):
        # Only a route for exactly this prefix, never a covering default or wider route.
        net = ipaddress.ip_network(prefix)
        f = self.route_fields(prefix)
        if f.get('destination') != str(net.network_address):
            return None
        if f.get('mask', str(ipaddress.ip_network('0.0.0.0/32').netmask)) != str(net.netmask):
            return None
        return f.get('interface')

    def anchor_is_ours(self):
        rules = self.command(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout
        return all('<frog_corp>' in line for line in rules.splitlines() if line.strip())

    def guard(self, state, path, interface=None, reserve=MAC_FAILSAFE_RESERVE):
        # The stock Apple wildcard anchor must already be loaded; never replace pf.conf.
        prefixes = ', '.join(self.s['corporate_prefixes'])
        qualifier = ('on ! ' + interface + ' ') if interface else ''
        body = 'table <frog_corp> const { ' + prefixes + ' }\n'
        body += 'block drop out quick ' + qualifier + 'inet to <frog_corp>\n'
        if not state.get('anchor_owned'):
            state['anchor_owned'] = True
            self.save(path, state)  # Ownership is recorded before the anchor exists.
        self.command(['/sbin/pfctl', '-a', ANCHOR, '-f', '-'], body, reserve=reserve)
        info = self.command(['/sbin/pfctl', '-s', 'info'], reserve=reserve).stdout
        if 'Status: Enabled' not in info:
            if not self.c.get('allow_pf_enable'):
                raise RuntimeError('pf_enable_requires_operator_acceptance')
            # Keep PF enabled throughout mode changes; recovery releases only this reference.
            enabled = self.command(['/sbin/pfctl', '-E'], reserve=reserve)
            token = re.search(r'Token\s*:\s*([0-9]+)', enabled.stdout + enabled.stderr)
            if not token:
                raise RuntimeError('pf_reference_receipt_missing')
            state['pf_token'] = token.group(1)
            self.save(path, state)
        for prefix in self.s['corporate_prefixes']:
            self.command(['/sbin/pfctl', '-k', '0.0.0.0/0', '-k', prefix], reserve=reserve)

    def withdraw(self, state, path, kept=None):
        # Never overwrite or delete a file or route modified by somebody else.
        for zone, content in list(state.get('resolvers', {}).items()):
            p = Path(self.c['resolver_dir']) / zone
            if p.exists():
                if p.read_text() != content:
                    if kept is None:
                        raise RuntimeError('resolver_changed_by_another_owner')
                    kept.append('resolver')
                else:
                    p.unlink()
            del state['resolvers'][zone]
            self.save(path, state)
        for prefix, interface in list(state.get('routes', {}).items()):
            if self.exact_route(prefix) == interface:
                self.command(['/sbin/route', '-n', 'delete', '-net', prefix, '-interface', interface])
            del state['routes'][prefix]
            self.save(path, state)

    def preflight(self, target, state):
        if not all(self.c.get(k) is True for k in ('pf_policy_verified', 'dns_fail_closed_verified', 'ipv6_policy_verified')):
            raise RuntimeError('mac_operator_acceptance_missing')
        if 'anchor "com.apple/*"' not in self.command(['/sbin/pfctl', '-sr']).stdout:
            raise RuntimeError('expected_pf_anchor_missing')
        if not state.get('anchor_owned') and not self.anchor_is_ours():
            raise RuntimeError('pf_anchor_used_by_another_owner')
        if target == 'vps':
            self.vpn_interface()
        for zone in self.s['dns_zones']:
            p = Path(self.c['resolver_dir']) / zone
            if p.exists() and p.read_text() != 'nameserver ' + self.s['corporate_dns'] + '\n':
                raise RuntimeError('existing_resolver_requires_review')

    def recover(self, state, path, epoch):
        # Owned withdrawal only: no login, no session stop, no pf.conf or global PF change.
        kept = []
        state.update(epoch=epoch, phase='recovering')
        self.save(path, state)
        self.withdraw(state, path, kept)
        if state.get('anchor_owned'):
            if not self.anchor_is_ours():
                raise RuntimeError('pf_anchor_contains_foreign_rules')
            self.command(['/sbin/pfctl', '-a', ANCHOR, '-F', 'rules'])
            self.command(['/sbin/pfctl', '-a', ANCHOR, '-F', 'Tables'])
            state['anchor_owned'] = False
            self.save(path, state)
        legacy = path.with_suffix('.pf-token')
        token = state.get('pf_token') or (legacy.read_text().strip() if legacy.exists() else None)
        if token:
            # Releases only this helper's enable reference; another owner's PF stays enabled.
            self.command(['/sbin/pfctl', '-X', token])
            state['pf_token'] = None
            self.save(path, state)
            legacy.unlink(missing_ok=True)
        state.update(phase='recovered', mode=None, active_interface=None)
        self.save(path, state)
        return {'ok': True, 'code': 'recovered', 'kept': kept}

    def execute(self, phase, target, epoch):
        if phase not in PHASES or target not in ('mac', 'vps') or type(epoch) is not int or epoch < 0:
            return {'ok': False, 'code': 'invalid_request'}
        if phase != 'recover' and (self.c.get('enabled') is not True or self.c.get('prepare_only') is not False):
            return {'ok': False, 'code': 'gateway_disabled'}
        path = Path(self.c['state_file'])
        if phase == 'recover':
            # Narrow exception to the disabled gate: it can only remove recorded own resources.
            if not path.exists():
                return {'ok': True, 'code': 'nothing_owned', 'kept': []}
            state = json.loads(path.read_text())
            if epoch < state['epoch']:
                return {'ok': False, 'code': 'stale_mode_epoch'}
            try:
                return self.recover(state, path, epoch)
            except Exception:
                state['phase'] = 'recovery_incomplete'
                self.save(path, state)
                return {'ok': False, 'code': 'mac_recovery_incomplete'}
        validate(self.s)
        state = json.loads(path.read_text()) if path.exists() else {'epoch': 0, 'routes': {}, 'resolvers': {}}
        if epoch < state['epoch']:
            return {'ok': False, 'code': 'stale_mode_epoch'}
        try:
            if phase == 'preflight':
                self.preflight(target, state)
                return {'ok': True}
            if phase == 'verify':
                if state.get('mode') != target or state.get('phase') != 'ready':
                    raise RuntimeError('mode_not_ready')
                expected = state.get('active_interface')
                if not expected or any(self.route_interface(p) != expected for p in self.s['corporate_prefixes']):
                    raise RuntimeError('route_verification_failed')
                # Route plus TCP reachability only. DNS-leak and IPv6-leak acceptance are
                # separate attended tests and are never inferred from this probe.
                self.deadline.admit(10, MAC_FAILSAFE_RESERVE)
                address = self.resolve(self.c['probe_host'], 5)
                if not any(ipaddress.ip_address(address) in ipaddress.ip_network(p) for p in self.s['corporate_prefixes']):
                    raise RuntimeError('probe_not_on_corporate_route')
                with self.connect((address, self.c.get('probe_port', 443)), timeout=5):
                    pass
                return {'ok': True}
            state.update(epoch=epoch, phase='applying')
            state.setdefault('routes', {})
            state.setdefault('resolvers', {})
            self.save(path, state)  # Lost replies cannot erase ownership/fencing.
            self.guard(state, path)
            self.withdraw(state, path)
            if phase == 'block':
                state['phase'] = 'blocked'
            elif target == 'vps':
                interface = self.vpn_interface()
                for prefix in self.s['corporate_prefixes']:
                    if self.exact_route(prefix) is not None:
                        raise RuntimeError('route_already_present_requires_review')
                    state['routes'][prefix] = interface
                    self.save(path, state)  # Recorded before creation; removal re-checks it.
                    self.command(['/sbin/route', '-n', 'add', '-net', prefix, '-interface', interface])
                directory = Path(self.c['resolver_dir'])
                directory.mkdir(exist_ok=True)
                for zone in self.s['dns_zones']:
                    p = directory / zone
                    content = 'nameserver ' + self.s['corporate_dns'] + '\n'
                    if p.exists():
                        if p.read_text() != content:
                            raise RuntimeError('resolver_requires_review')
                    else:
                        state['resolvers'][zone] = content
                        self.save(path, state)
                        p.write_text(content)
                        p.chmod(0o644)
                self.guard(state, path, interface)
                state.update(mode=target, phase='ready', active_interface=interface)
            else:
                interface = self.route_interface(self.s['corporate_dns'])
                try:
                    personal = self.vpn_interface()
                except RuntimeError:
                    personal = None
                if not interface or interface == personal:
                    raise RuntimeError('native_corporate_route_missing')
                self.guard(state, path, interface)
                state.update(mode=target, phase='ready', active_interface=interface)
            self.save(path, state)
            return {'ok': True}
        except Exception:
            if phase == 'preflight':
                return {'ok': False, 'code': 'mac_network_preflight_failed'}
            try:
                self.guard(state, path, reserve=0)  # Uses the reserved budget.
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
    deadline = Deadline(MAC_HELPER_BUDGET, time.monotonic)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--phase', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--epoch', required=True, type=int)
    a = p.parse_args()
    path = Path(a.config)
    c = json.loads(path.read_text())
    if a.phase != 'recover' and (c.get('enabled') is not True or c.get('prepare_only') is not False):
        print(json.dumps({'ok': False, 'code': 'gateway_disabled'}))
        return 1
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    if a.phase == 'recover' and not Path(c['state_file']).exists():
        print(json.dumps({'ok': True, 'code': 'nothing_owned', 'kept': []}))
        return 0
    with Path(c['lock_file']).open('a') as lock:
        if not acquire(lock, MAC_LOCK_WAIT):
            print(json.dumps({'ok': False, 'code': 'busy'}))
            return 1
        result = MacNetwork(c, deadline=deadline).execute(a.phase, a.target, a.epoch)
    print(json.dumps(result))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
