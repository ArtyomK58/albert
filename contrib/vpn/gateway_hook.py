#!/usr/bin/env python3
"""Operator-only phased network hook. Disabled manifests perform no commands."""
import argparse
import fcntl
import json
import hashlib
import os
from pathlib import Path
import subprocess

from gateway_plan import validate


class NetworkHook:
    def __init__(self, config, run=subprocess.run):
        self.c = config
        self.run = run
        self.spec = config.get('network', {})

    def command(self, args, data=None, check=True):
        r = self.run(args, input=data, capture_output=True, text=True, timeout=25)
        if check and r.returncode:
            raise RuntimeError('network_command_failed')
        return r

    def chain(self, prefix, table, name, hook, rules):
        # Only our chain is replaced; never flush shared Docker or namespace tables.
        lines = ['*' + table, ':' + name + ' - [0:0]', '-F ' + name]
        lines += ['-A ' + name + ' ' + rule for rule in rules]
        self.command(prefix + ['iptables-restore', '-w', '5', '--noflush'], '\n'.join(lines + ['COMMIT', '']))
        base = prefix + ['iptables', '-w', '-t', table]
        if self.command(base + ['-C', hook, '-j', name], check=False).returncode:
            self.command(base + ['-I', hook, '1', '-j', name])

    def host_filter(self, active):
        s = self.spec
        # Preserve replies to namespace-owned outbound connections, including the
        # corporate VPN's encrypted transport, even while peer forwarding is blocked.
        rules = ['-o ' + s['host_veth'] + ' -d ' + s['namespace_link_address']
                 + '/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT']
        if active:
            rules.append('-i {host_veth} -o {host_bridge} -d {mac_peer} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'.format(**s))
            for p in s['corporate_prefixes']:
                rules.append('-i {host_bridge} -o {host_veth} -s {mac_peer} -d '.format(**s) + p
                             + ' -m mac --mac-source ' + s['container_mac'] + ' -j ACCEPT')
        rules += ['-i ' + s['host_bridge'] + ' -d ' + p + ' -j REJECT' for p in s['corporate_prefixes']]
        rules.append('-o ' + s['host_veth'] + ' -j REJECT')
        self.chain([], 'filter', 'FROG_CG_HOST', 'DOCKER-USER', rules)

    def mac(self, phase, target, epoch):
        argv = self.c.get('mac_command', [])
        if not argv or not all(isinstance(x, str) for x in argv):
            raise RuntimeError('mac_privileged_helper_unconfigured')
        r = self.command(argv + ['--phase', phase, '--target', target, '--epoch', str(epoch)])
        value = json.loads(r.stdout)
        # mac-link does not replay a command whose reply was lost.
        if value.get('state') != 'completed' or value.get('result', {}).get('exit_code') != 0:
            raise RuntimeError('mac_network_outcome_unknown')
        if json.loads(value['result']['stdout']).get('ok') is not True:
            raise RuntimeError('mac_network_not_verified')

    def preflight(self, target, epoch):
        s = self.spec
        if self.command(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip() != '1':
            raise RuntimeError('shared_forwarding_must_already_be_enabled')
        data = json.loads(self.command(['docker', 'inspect', s['container']]).stdout)[0]
        found = any(n.get('IPAddress') == s['container_address'] and n.get('MacAddress', '').lower() == s['container_mac'].lower()
                    for n in data['NetworkSettings']['Networks'].values())
        if not found:
            raise RuntimeError('container_topology_changed')
        signature = hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()
        owner = Path(self.c['resource_state'])
        if owner.exists():
            if json.loads(owner.read_text()).get('signature') != signature:
                raise RuntimeError('network_spec_changed_requires_reconciliation')
        else:
            rules = json.loads(self.command(['ip', '-j', 'rule', 'show']).stdout)
            if any(str(x.get('table')) == str(s['table']) or x.get('priority') == s['rule_priority'] for x in rules):
                raise RuntimeError('routing_resource_already_owned')
            table = self.command(['ip', '-j', 'route', 'show', 'table', str(s['table'])], check=False)
            if table.returncode == 0:
                if json.loads(table.stdout or '[]'):
                    raise RuntimeError('routing_table_already_owned')
            elif 'FIB table does not exist' not in table.stderr:
                raise RuntimeError('routing_table_inspection_failed')
            if self.command(['iptables', '-S', 'FROG_CG_HOST'], check=False).returncode == 0:
                raise RuntimeError('firewall_resource_already_owned')
        # Acceptance must explicitly cover cryptokey peer isolation and the private supervisor.
        if not all(self.c.get(k) is True for k in ('peer_isolation_verified', 'supervisor_policy_verified')):
            raise RuntimeError('operator_acceptance_missing')
        self.mac('preflight', target, epoch)

    def block(self, target, epoch):
        owner = Path(self.c['resource_state'])
        owner.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not owner.exists():
            owner.write_text(json.dumps({'signature': hashlib.sha256(json.dumps(self.spec, sort_keys=True).encode()).hexdigest()}))
            owner.chmod(0o600)
        self.host_filter(False)
        self.mac('block', target, epoch)

    def activate(self, target, epoch):
        s = self.spec
        self.host_filter(False)
        if target == 'mac':
            self.mac('activate', target, epoch)
            return
        ns = ['ip', 'netns', 'exec', s['namespace']]
        ns_rules = ['-i {tunnel} -o {namespace_veth} -d {mac_peer} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'.format(**s)]
        ns_rules += ['-i {namespace_veth} -o {tunnel} -s {mac_peer} -d '.format(**s) + p + ' -j ACCEPT' for p in s['corporate_prefixes']]
        self.chain(ns, 'filter', 'FROG_CG_NS', 'FORWARD', ns_rules + ['-j REJECT'])
        self.command(ns + ['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        self.command(ns + ['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=2'])
        self.command(['ip', 'route', 'replace', s['mac_peer'], 'via', s['container_address'], 'dev', s['host_bridge']])
        self.command(['ip', '-n', s['namespace'], 'route', 'replace', s['mac_peer'], 'via', s['host_link_address'], 'dev', s['namespace_veth']])
        for p in s['corporate_prefixes']:
            self.command(['ip', 'route', 'replace', 'unreachable', p, 'table', str(s['table']), 'metric', '32760'])
            self.command(['ip', '-n', s['namespace'], 'route', 'replace', 'unreachable', p, 'metric', '32760'])
            rule = ['priority', str(s['rule_priority']), 'iif', s['host_bridge'], 'from', s['mac_peer'], 'to', p, 'lookup', str(s['table'])]
            # Duplicated rules are removed by exact ownership tuple, never by priority alone.
            self.command(['ip', 'rule', 'del'] + rule, check=False)
            self.command(['ip', 'rule', 'add'] + rule)
            self.command(['ip', 'route', 'replace', p, 'via', s['namespace_link_address'], 'dev', s['host_veth'], 'table', str(s['table']), 'metric', '10'])
        bypass = ['-s ' + s['mac_peer'] + ' -d ' + p + ' -j ACCEPT' for p in s['corporate_prefixes']]
        self.chain(['docker', 'exec', '-i', s['container']], 'nat', 'FROG_CG_BYPASS', 'POSTROUTING', bypass)
        snat = ['-s ' + s['mac_peer'] + ' -d ' + p + ' -o ' + s['tunnel'] + ' -j MASQUERADE' for p in s['corporate_prefixes']]
        self.chain(ns, 'nat', 'FROG_CG_SNAT', 'POSTROUTING', snat)
        mss = str(s['tcp_mss'])
        rules = [d + ' ' + s['mac_peer'] + ' -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss '
                 + str(s['tcp_mss'] + 1) + ':65535 -j TCPMSS --set-mss ' + mss for d in ('-s', '-d')]
        self.chain(ns, 'mangle', 'FROG_CG_MSS', 'FORWARD', rules)
        self.mac('activate', target, epoch)
        self.host_filter(True)  # Last step exposes only the configured peer.

    def execute(self, phase, target, epoch):
        if self.c.get('enabled') is not True or self.c.get('prepare_only') is not False:
            return {'ok': False, 'code': 'gateway_disabled'}
        if phase not in ('preflight', 'block', 'activate', 'verify') or target not in ('mac', 'vps') or type(epoch) is not int or epoch < 0:
            return {'ok': False, 'code': 'invalid_request'}
        validate(self.spec)
        try:
            if phase == 'preflight':
                self.preflight(target, epoch)
            elif phase == 'block':
                self.block(target, epoch)
            elif phase == 'activate':
                self.activate(target, epoch)
            else:
                self.mac('verify', target, epoch)
            return {'ok': True}
        except Exception:
            if phase != 'preflight':
                try:
                    self.host_filter(False)
                except Exception:
                    pass
            return {'ok': False, 'code': 'network_phase_failed'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    path = Path(a.config)
    c = json.loads(path.read_text())
    if not c.get('enabled') or c.get('prepare_only', True):
        print(json.dumps({'ok': False, 'code': 'gateway_disabled'}))
        return 1
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    req = json.loads(input())
    state = json.loads(Path(c['mode_state']).read_text()) if Path(c['mode_state']).exists() else {'epoch': 0}
    with Path(c['lock_file']).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = NetworkHook(c).execute(req.get('phase'), req.get('target'), state['epoch'])
    print(json.dumps(result))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
