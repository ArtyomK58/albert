#!/usr/bin/env python3
"""Operator-only phased network hook. Disabled manifests perform no commands."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from gateway_plan import (Deadline, HOOK_BUDGET, HOOK_LOCK_WAIT, HOST_COMMAND_TIMEOUT, HOST_FAILSAFE_RESERVE,
                          MAC_CALL_TIMEOUT, MAC_LINK_EXEC_TIMEOUT, acquire, validate)
from tailnet_guard import TailnetGuard

PHASES = ('preflight', 'block', 'activate', 'verify', 'recover')
HOST_CHAIN = 'FROG_CG_HOST'
NS_CHAINS = (('filter', 'FROG_CG_NS', 'FORWARD'), ('nat', 'FROG_CG_SNAT', 'POSTROUTING'),
             ('mangle', 'FROG_CG_MSS', 'FORWARD'))
CONTAINER_CHAIN = ('nat', 'FROG_CG_BYPASS', 'POSTROUTING')
RULE_CORE = ('priority', 'iif', 'src', 'srclen', 'dst', 'dstlen', 'table')
NS_SYSCTL = (('net.ipv4.ip_forward', '1'), ('net.ipv4.conf.all.rp_filter', '2'))


def signature(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


class NetworkHook:
    def __init__(self, config, run=None, clock=time.monotonic, deadline=None):
        self.c = config
        self.run = run or subprocess.run
        self.spec = config.get('network', {})
        self.deadline = deadline or Deadline(HOOK_BUDGET, clock)

    def command(self, args, data=None, check=True, reserve=HOST_FAILSAFE_RESERVE):
        timeout = self.deadline.admit(HOST_COMMAND_TIMEOUT, reserve)
        r = self.run(args, input=data, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode:
            raise RuntimeError('network_command_failed')
        return r

    # Ownership manifest: every resource is recorded before it is created, so a
    # crash or lost reply can only leave resources that recovery knows about.
    def owner(self):
        path = Path(self.c['resource_state'])
        return json.loads(path.read_text()) if path.exists() else None

    def save_owner(self, value):
        path = Path(self.c['resource_state'])
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = path.with_suffix('.new')
        temp.write_text(json.dumps(value))
        temp.chmod(0o600)
        temp.replace(path)

    def record(self, **resources):
        value = self.owner() or {'signature': signature(self.spec), 'spec': self.spec, 'resources': {}}
        value['resources'].update(resources)
        self.save_owner(value)
        return value

    def chain(self, prefix, table, name, hook, rules, reserve=HOST_FAILSAFE_RESERVE):
        # Only our chain is replaced; never flush shared Docker or namespace tables.
        lines = ['*' + table, ':' + name + ' - [0:0]', '-F ' + name]
        lines += ['-A ' + name + ' ' + rule for rule in rules]
        self.command(prefix + ['iptables-restore', '-w', '5', '--noflush'], '\n'.join(lines + ['COMMIT', '']), reserve=reserve)
        base = prefix + ['iptables', '-w', '-t', table]
        if self.command(base + ['-C', hook, '-j', name], check=False, reserve=reserve).returncode:
            self.command(base + ['-I', hook, '1', '-j', name], reserve=reserve)

    def drop_chain(self, prefix, table, name, hook):
        if not prefix and name == HOST_CHAIN and self.spec.get('transport') == 'tailnet':
            return TailnetGuard(self).remove(HOST_FAILSAFE_RESERVE)
        base = prefix + ['iptables', '-w', '-t', table]
        for _ in range(8):
            if self.command(base + ['-C', hook, '-j', name], check=False).returncode:
                break
            self.command(base + ['-D', hook, '-j', name])
        if self.command(base + ['-S', name], check=False).returncode == 0:
            self.command(base + ['-F', name])
            self.command(base + ['-X', name])

    def host_filter(self, active, reserve=HOST_FAILSAFE_RESERVE):
        if self.spec.get('transport') == 'tailnet':
            return TailnetGuard(self).apply(active, reserve)
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
        if not (self.owner() or {}).get('resources', {}).get('host_chain'):
            self.record(host_chain=True)
        self.chain([], 'filter', HOST_CHAIN, 'DOCKER-USER', rules, reserve)

    def mac(self, phase, target, epoch):
        argv = self.c.get('mac_command', [])
        if not argv or not all(isinstance(x, str) for x in argv):
            raise RuntimeError('mac_privileged_helper_unconfigured')
        # The relay must end before this call's own timeout, or a still-valid Mac
        # phase would be cut off and misreported.
        if '--timeout' not in argv or argv[argv.index('--timeout') + 1:][:1] != [str(MAC_LINK_EXEC_TIMEOUT)]:
            raise RuntimeError('mac_command_timeout_mismatch')
        timeout = self.deadline.admit(MAC_CALL_TIMEOUT, HOST_FAILSAFE_RESERVE)
        r = self.run(argv + ['--phase', phase, '--target', target, '--epoch', str(epoch)],
                     input=None, capture_output=True, text=True, timeout=timeout)
        value = json.loads(r.stdout)
        # mac-link does not replay a command whose reply was lost.
        if value.get('state') != 'completed' or not isinstance(value.get('result'), dict):
            raise RuntimeError('mac_network_outcome_unknown')
        inner = json.loads(value['result'].get('stdout') or '{}')
        if r.returncode or value['result'].get('exit_code') != 0 or inner.get('ok') is not True:
            raise RuntimeError('mac_network_not_verified')
        return inner

    def ip_json(self, args):
        r = self.command(args, check=False)
        if r.returncode:
            if 'FIB table does not exist' in r.stderr:
                return []
            raise RuntimeError('routing_inspection_failed')
        return json.loads(r.stdout or '[]')

    @staticmethod
    def rule_args(s, prefix):
        return ['priority', str(s['rule_priority']), 'iif', s['host_bridge'], 'from', s['mac_peer'],
                'to', prefix, 'lookup', str(s['table'])]

    @staticmethod
    def delete_candidates(rules, s, prefix):
        """Every rule our `ip rule del` request could remove.

        The kernel compares only the selectors a delete request carries, so a rule with
        the same tuple plus any extra selector (fwmark, uidrange, ipproto, ...) or a
        different protocol is also a candidate. Deletion is safe only when there is
        exactly one candidate and it is the rule this hook recorded."""
        peer, net = ipaddress.ip_network(s['mac_peer']), ipaddress.ip_network(prefix)
        return [x for x in rules
                if x.get('priority') == s['rule_priority'] and x.get('iif') == s['host_bridge']
                and x.get('src') == str(peer.network_address) and x.get('srclen', 32) == peer.prefixlen
                and x.get('dst') == str(net.network_address) and x.get('dstlen', 32) == net.prefixlen
                and str(x.get('table')) == str(s['table'])]

    @staticmethod
    def rule_extras(x):
        # Attributes beyond our selectors, including kernel defaults, as observed at creation.
        return {k: v for k, v in x.items() if k not in RULE_CORE}

    def owned_rule(self, rules, s, prefix, resources):
        """Return the single unambiguous owned rule, None if absent, or raise when ambiguous."""
        candidates = self.delete_candidates(rules, s, prefix)
        if not candidates:
            return None
        recorded = resources.get('rule_attrs', {}).get(prefix)
        if len(candidates) == 1 and recorded is not None and self.rule_extras(candidates[0]) == recorded:
            return candidates[0]
        raise RuntimeError('ambiguous_policy_rule_requires_operator')

    @staticmethod
    def corporate(dst, s):
        try:
            return ipaddress.ip_network(dst) in {ipaddress.ip_network(p) for p in s['corporate_prefixes']}
        except ValueError:
            return False

    def return_route(self, ns=False):
        s = self.spec
        peer = str(ipaddress.ip_network(s['mac_peer']).network_address)
        prefix = ['ip', '-n', s['namespace']] if ns else ['ip']
        gateway, dev = (s['host_link_address'], s['namespace_veth']) if ns else (s['container_address'], s['host_bridge'])
        routes = self.ip_json(prefix + ['-j', 'route', 'show', 'exact', peer + '/32'])
        ours = [r for r in routes if r.get('gateway') == gateway and r.get('dev') == dev and 'metric' not in r
                and r.get('type', 'unicast') == 'unicast']
        return routes, ours, prefix + ['route', 'del', peer, 'via', gateway, 'dev', dev]

    def preflight(self, target, epoch):
        s = self.spec
        if self.command(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip() != '1':
            raise RuntimeError('shared_forwarding_must_already_be_enabled')
        tailnet = s.get('transport') == 'tailnet'
        if tailnet:
            data = json.loads(self.command(['tailscale', 'status', '--json']).stdout)
            peer = str(ipaddress.ip_network(s['mac_peer']).network_address)
            found = any(n.get('ID') == s.get('tailnet_node_id') and n.get('Online') and peer in n.get('TailscaleIPs', [])
                        for n in (data.get('Peer') or {}).values())
            route = self.ip_json(['ip', '-j', 'route', 'get', peer])
            found = found and bool(route) and route[0].get('dev') == s['host_bridge']
        else:
            data = json.loads(self.command(['docker', 'inspect', s['container']]).stdout)[0]
            found = any(n.get('IPAddress') == s['container_address'] and n.get('MacAddress', '').lower() == s['container_mac'].lower()
                        for n in data['NetworkSettings']['Networks'].values())
        if not found:
            raise RuntimeError('container_topology_changed')
        owner = self.owner()
        if owner:
            if owner.get('signature') != signature(s):
                raise RuntimeError('network_spec_changed_requires_reconciliation')
        else:
            rules = self.ip_json(['ip', '-j', 'rule', 'show'])
            if any(str(x.get('table')) == str(s['table']) or x.get('priority') == s['rule_priority'] for x in rules):
                raise RuntimeError('routing_resource_already_owned')
            if self.ip_json(['ip', '-j', 'route', 'show', 'table', str(s['table'])]):
                raise RuntimeError('routing_table_already_owned')
            if tailnet and TailnetGuard(self).inspect(HOST_FAILSAFE_RESERVE) is not None:
                raise RuntimeError('firewall_resource_already_owned')
            if not tailnet and self.command(['iptables', '-S', HOST_CHAIN], check=False).returncode == 0:
                raise RuntimeError('firewall_resource_already_owned')
            if not tailnet and self.return_route()[0]:
                raise RuntimeError('return_route_already_owned')
        # Acceptance must explicitly cover cryptokey peer isolation and the private supervisor.
        if not all(self.c.get(k) is True for k in ('peer_isolation_verified', 'supervisor_policy_verified')):
            raise RuntimeError('operator_acceptance_missing')
        self.mac('preflight', target, epoch)

    def block(self, target, epoch):
        owner = self.owner()
        if owner and owner.get('signature') != signature(self.spec):
            raise RuntimeError('network_spec_changed_requires_reconciliation')
        self.host_filter(False)
        self.record(mac=True)
        self.mac('block', target, epoch)

    def ns_sysctl_prior(self, ns):
        recorded = (self.owner() or {}).get('resources', {}).get('ns_sysctl', {})
        prior = {}
        for key, wanted in NS_SYSCTL:
            current = self.command(ns + ['sysctl', '-n', key]).stdout.strip()
            # Re-applying in the same namespace keeps the originally recorded value.
            prior[key] = recorded[key] if key in recorded and current == wanted else current
        return prior

    def activate(self, target, epoch):
        s = self.spec
        self.host_filter(False)
        if target == 'mac':
            self.record(mac=True)
            self.mac('activate', target, epoch)
            return
        ns = ['ip', 'netns', 'exec', s['namespace']]
        tailnet = s.get('transport') == 'tailnet'
        resources = dict(ns_chains=True, ns_sysctl=self.ns_sysctl_prior(ns), ns_routes=True, rules=True, table_routes=True)
        if not tailnet:
            resources['container_chain'] = True
        self.record(**resources)
        ns_rules = ['-i {tunnel} -o {namespace_veth} -d {mac_peer} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'.format(**s)]
        ns_rules += ['-i {namespace_veth} -o {tunnel} -s {mac_peer} -d '.format(**s) + p + ' -j ACCEPT' for p in s['corporate_prefixes']]
        self.chain(ns, 'filter', 'FROG_CG_NS', 'FORWARD', ns_rules + ['-j REJECT'])
        for key, wanted in NS_SYSCTL:
            self.command(ns + ['sysctl', '-w', key + '=' + wanted])
        if not tailnet:
            routes, ours, _ = self.return_route()
            if routes != ours or (routes and not self.owner()['resources'].get('return_route')):
                raise RuntimeError('return_route_already_owned')
            self.record(return_route=True)
            self.command(['ip', 'route', 'replace', s['mac_peer'], 'via', s['container_address'], 'dev', s['host_bridge']])
        self.command(['ip', '-n', s['namespace'], 'route', 'replace', s['mac_peer'], 'via', s['host_link_address'], 'dev', s['namespace_veth']])
        for p in s['corporate_prefixes']:
            self.command(['ip', 'route', 'replace', 'unreachable', p, 'table', str(s['table']), 'metric', '32760'])
            self.command(['ip', '-n', s['namespace'], 'route', 'replace', 'unreachable', p, 'metric', '32760'])
            # Never delete-and-re-add: a delete could hit a foreign rule with extra selectors.
            resources = self.owner()['resources']
            if self.owned_rule(self.ip_json(['ip', '-j', 'rule', 'show']), s, p, resources) is None:
                self.command(['ip', 'rule', 'add'] + self.rule_args(s, p))
                created = self.delete_candidates(self.ip_json(['ip', '-j', 'rule', 'show']), s, p)
                if len(created) != 1:
                    raise RuntimeError('ambiguous_policy_rule_requires_operator')
                attrs = dict(resources.get('rule_attrs', {}), **{p: self.rule_extras(created[0])})
                self.record(rule_attrs=attrs)
            self.command(['ip', 'route', 'replace', p, 'via', s['namespace_link_address'], 'dev', s['host_veth'], 'table', str(s['table']), 'metric', '10'])
        if not tailnet:
            bypass = ['-s ' + s['mac_peer'] + ' -d ' + p + ' -j ACCEPT' for p in s['corporate_prefixes']]
            self.chain(['docker', 'exec', '-i', s['container']], 'nat', 'FROG_CG_BYPASS', 'POSTROUTING', bypass)
        snat = ['-s ' + s['mac_peer'] + ' -d ' + p + ' -o ' + s['tunnel'] + ' -j MASQUERADE' for p in s['corporate_prefixes']]
        self.chain(ns, 'nat', 'FROG_CG_SNAT', 'POSTROUTING', snat)
        mss = str(s['tcp_mss'])
        rules = [d + ' ' + s['mac_peer'] + ' -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss '
                 + str(s['tcp_mss'] + 1) + ':65535 -j TCPMSS --set-mss ' + mss for d in ('-s', '-d')]
        self.chain(ns, 'mangle', 'FROG_CG_MSS', 'FORWARD', rules)
        self.record(mac=True)
        self.mac('activate', target, epoch)
        self.host_filter(True)  # Last step exposes only the configured peer.

    def recover(self, target, epoch):
        """Remove only recorded own resources; never log in, stop a session or touch shared state."""
        owner = self.owner()
        if owner is None:
            return {'ok': True, 'code': 'nothing_owned', 'kept': []}
        # Withdrawal uses the generation that created the resources, not the current spec.
        self.spec = s = owner['spec']
        res = owner['resources']
        kept, failed = [], []

        def done(*names):
            for name in names:
                res.pop(name, None)
            self.save_owner(owner)

        def step(name, action):
            try:
                action()
            except Exception:
                failed.append(name)

        if res.get('host_chain'):
            step('host_block', lambda: self.host_filter(False))  # Fail closed before dismantling.
            # Re-blocking may update the owned table receipt. Keep that generation
            # when later recovery steps persist resource removal.
            owner = self.owner()
            res = owner['resources']
        if res.get('mac'):
            def mac_recover():
                kept.extend('mac_' + item for item in self.mac('recover', target, epoch).get('kept', []))
                done('mac')
            step('mac', mac_recover)
        if res.get('container_chain'):
            def container():
                r = self.command(['docker', 'inspect', '-f', '{{.State.Running}}', s['container']], check=False)
                if r.returncode == 0 and r.stdout.strip() == 'true':
                    self.drop_chain(['docker', 'exec', s['container']], *CONTAINER_CHAIN)
                elif r.returncode and 'No such object' not in r.stderr:
                    raise RuntimeError('container_state_unknown')
                done('container_chain')
            step('container_chain', container)
        if res.get('rules'):
            def rules():
                ambiguous = False
                for p in s['corporate_prefixes']:
                    current = self.ip_json(['ip', '-j', 'rule', 'show'])
                    try:
                        ours = self.owned_rule(current, s, p, res)
                    except RuntimeError:
                        ambiguous = True  # Keep every candidate; an operator must reconcile.
                        continue
                    if ours is not None:
                        self.command(['ip', 'rule', 'del'] + self.rule_args(s, p))
                        after = self.ip_json(['ip', '-j', 'rule', 'show'])
                        if [x for x in current if x is not ours] != after:
                            raise RuntimeError('policy_rule_delete_unverified')
                remaining = self.ip_json(['ip', '-j', 'rule', 'show'])
                if any(x.get('priority') == s['rule_priority'] or str(x.get('table')) == str(s['table']) for x in remaining):
                    kept.append('foreign_rule')
                if ambiguous:
                    kept.append('ambiguous_policy_rule')
                    raise RuntimeError('ambiguous_policy_rule_requires_operator')
                done('rules', 'rule_attrs')
            step('rules', rules)
        if res.get('table_routes'):
            def table():
                for r in self.ip_json(['ip', '-j', 'route', 'show', 'table', str(s['table'])]):
                    if not self.corporate(r.get('dst', ''), s):
                        kept.append('foreign_table_route')
                    elif r.get('type') == 'unreachable' and r.get('metric') == 32760:
                        self.command(['ip', 'route', 'del', 'unreachable', r['dst'], 'table', str(s['table']), 'metric', '32760'])
                    elif (r.get('gateway') == s['namespace_link_address'] and r.get('dev') == s['host_veth']
                          and r.get('metric') == 10):
                        self.command(['ip', 'route', 'del', r['dst'], 'via', s['namespace_link_address'], 'dev',
                                      s['host_veth'], 'table', str(s['table']), 'metric', '10'])
                    else:
                        kept.append('foreign_table_route')
                done('table_routes')
            step('table_routes', table)
        if res.get('return_route'):
            def host_return():
                routes, ours, delete = self.return_route()
                if ours:
                    self.command(delete)
                if len(routes) > len(ours):
                    kept.append('foreign_return_route')
                done('return_route')
            step('return_route', host_return)
        if any(res.get(k) for k in ('ns_chains', 'ns_routes', 'ns_sysctl')):
            def namespace():
                names = [line.split()[0] for line in self.command(['ip', 'netns', 'list']).stdout.splitlines() if line.split()]
                if s['namespace'] in names:
                    ns = ['ip', 'netns', 'exec', s['namespace']]
                    for table, name, hook in NS_CHAINS:
                        self.drop_chain(ns, table, name, hook)
                    _, ours, delete = self.return_route(ns=True)
                    if ours:
                        self.command(delete)
                    for r in self.ip_json(['ip', '-n', s['namespace'], '-j', 'route', 'show']):
                        if r.get('type') == 'unreachable' and r.get('metric') == 32760 and self.corporate(r.get('dst', ''), s):
                            self.command(['ip', '-n', s['namespace'], 'route', 'del', 'unreachable', r['dst'], 'metric', '32760'])
                    for key, wanted in NS_SYSCTL:
                        prior = res.get('ns_sysctl', {}).get(key)
                        # Restore only a value this hook set; a recreated namespace is left alone.
                        if prior is not None and prior != wanted and self.command(ns + ['sysctl', '-n', key]).stdout.strip() == wanted:
                            self.command(ns + ['sysctl', '-w', key + '=' + prior])
                done('ns_chains', 'ns_routes', 'ns_sysctl')
            step('namespace', namespace)
        if res.get('host_chain') and not failed:
            # Removed last: until here it keeps the peer blocked.
            step('host_chain', lambda: (self.drop_chain([], 'filter', HOST_CHAIN, 'DOCKER-USER'), done('host_chain')))
        if failed or res:
            return {'ok': False, 'code': 'recovery_incomplete', 'failed': failed, 'kept': kept}
        Path(self.c['resource_state']).unlink()
        return {'ok': True, 'code': 'recovered', 'kept': kept}

    def execute(self, phase, target, epoch):
        if phase not in PHASES or target not in ('mac', 'vps') or type(epoch) is not int or epoch < 0:
            return {'ok': False, 'code': 'invalid_request'}
        if phase == 'recover':
            # Narrow exception to the disabled gate: it can only remove recorded own resources.
            try:
                return self.recover(target, epoch)
            except Exception:
                return {'ok': False, 'code': 'recovery_incomplete'}
        if self.c.get('enabled') is not True or self.c.get('prepare_only') is not False:
            return {'ok': False, 'code': 'gateway_disabled'}
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
                    self.host_filter(False, reserve=0)  # Uses the reserved budget.
                except Exception:
                    pass
            return {'ok': False, 'code': 'network_phase_failed'}


def main():
    deadline = Deadline(HOOK_BUDGET, time.monotonic)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    a = p.parse_args()
    path = Path(a.config)
    c = json.loads(path.read_text())
    try:
        req = json.loads(sys.stdin.readline(4097))
        phase = req.get('phase')
    except (ValueError, AttributeError):
        req, phase = {}, None
    if phase != 'recover' and (c.get('enabled') is not True or c.get('prepare_only') is not False):
        print(json.dumps({'ok': False, 'code': 'gateway_disabled'}))
        return 1
    if os.geteuid() != 0 or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise SystemExit('operator_owned_config_required')
    if phase == 'recover' and not Path(c['resource_state']).exists():
        # Nothing recorded as ours: no lock file, no state and no command.
        print(json.dumps({'ok': True, 'code': 'nothing_owned', 'kept': []}))
        return 0
    state = json.loads(Path(c['mode_state']).read_text()) if Path(c['mode_state']).exists() else {'epoch': 0}
    with Path(c['lock_file']).open('a') as lock:
        if not acquire(lock, HOOK_LOCK_WAIT):
            print(json.dumps({'ok': False, 'code': 'busy'}))
            return 1
        result = NetworkHook(c, deadline=deadline).execute(phase, req.get('target'), state['epoch'])
    print(json.dumps(result))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
