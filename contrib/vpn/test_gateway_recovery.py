"""Recovery, fencing and timeout regressions on fully simulated hosts. No OS network command runs."""
import copy
import io
import itertools
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

import gateway_hook
import gateway_mac
import gateway_plan
from broker import Broker
from gateway_hook import NetworkHook
from gateway_mac import MacNetwork
from gateway_plan import render
from install_gateway_mac import install
from mac_agent import Controller
import modes
from modes import Modes
from targets import Targets
from test_gateway import FakeTargets, fixture

ANCHOR = 'com.apple/frog-corp'
MAC_COMMAND = ['mac-link', '--timeout', str(gateway_plan.MAC_LINK_EXEC_TIMEOUT), 'shell', '--',
               'sudo', '-n', '/operator/run']


def done(args, rc=0, out='', err=''):
    return subprocess.CompletedProcess(args, rc, out, err)


def ip_dst(value):
    n = ipaddress.ip_network(value)
    return str(n.network_address) if n.prefixlen == 32 else str(n)


class FakeMac:
    """pfctl/route/ifconfig model with an anchor, owned and native routes and PF references."""

    def __init__(self, spec):
        self.s = spec
        self.calls = []
        self.anchor = []          # rule lines as `pfctl -sr` would print them
        self.tables = False
        self.pf_refs = {'other-owner'}
        self.next_token = 100
        self.personal = 'utun3'   # carries the gateway peer address
        self.native = 'utun7'     # the native corporate client
        self.native_routes = {}   # prefix -> interface, owned by the native client
        self.routes = {}          # prefix -> interface, added through `route add`
        self.forbidden = []
        self.slow = {}            # substring -> seconds consumed by the fake clock
        self.now = [0.0]

    def clock(self):
        return self.now[0]

    def __call__(self, args, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append((list(args), input, timeout))
        line = ' '.join(args)
        for key, seconds in self.slow.items():
            if key in line:
                self.now[0] += seconds
        if args[:2] == ['/sbin/pfctl', '-d'] or ('-F' in args and 'all' in args) or '/etc/pf.conf' in args:
            self.forbidden.append(args)
            return done(args, 1)
        if args == ['/sbin/ifconfig']:
            out = 'en0: flags=8863<UP>\n\tinet 192.0.2.10 netmask 0xffffff00\n'
            if self.personal:
                out += self.personal + ': flags=8051<UP>\n\tinet ' + str(ipaddress.ip_network(self.s['mac_peer']).network_address) + ' --> x\n'
            if self.native_routes:
                out += self.native + ': flags=8051<UP>\n\tinet 192.0.2.77 --> x\n'
            return done(args, 0, out)
        if args[:4] == ['/sbin/route', '-n', 'get', '-net']:
            target = ipaddress.ip_network(args[4], strict=False)
            best = None
            for table in (self.native_routes, self.routes):
                for prefix, name in table.items():
                    net = ipaddress.ip_network(prefix)
                    if target.subnet_of(net) and (best is None or net.prefixlen > best[0].prefixlen):
                        best = (net, name)
            if best is None:
                return done(args, 0, '   route to: x\ndestination: default\n       mask: default\n  interface: en0\n')
            net, name = best
            return done(args, 0, '   route to: x\ndestination: %s\n       mask: %s\n  interface: %s\n'
                        % (net.network_address, net.netmask, name))
        if args[:4] == ['/sbin/route', '-n', 'add', '-net']:
            if args[4] in self.routes or args[4] in self.native_routes:
                return done(args, 1, '', 'File exists')
            self.routes[args[4]] = args[6]
            return done(args)
        if args[:4] == ['/sbin/route', '-n', 'delete', '-net']:
            if self.routes.get(args[4]) == args[6]:
                del self.routes[args[4]]
                return done(args)
            if self.native_routes.get(args[4]) == args[6]:
                self.forbidden.append(args)  # native client's route deleted
                del self.native_routes[args[4]]
                return done(args)
            return done(args, 1)
        if args == ['/sbin/pfctl', '-sr']:
            return done(args, 0, 'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n')
        if args[:3] == ['/sbin/pfctl', '-a', ANCHOR]:
            if args[3:] == ['-f', '-']:
                self.anchor = [l.replace(' inet to ', ' inet from any to ') for l in input.splitlines() if l.startswith('block')]
                self.tables = True
                return done(args)
            if args[3:] == ['-sr']:
                return done(args, 0, ''.join(l + '\n' for l in self.anchor))
            if args[3:] == ['-F', 'rules']:
                self.anchor = []
                return done(args, 0, '', 'rules cleared\n')
            if args[3:] == ['-F', 'Tables']:
                self.tables = False
                return done(args, 0, '', '1 tables deleted.\n')
        if args == ['/sbin/pfctl', '-s', 'info']:
            return done(args, 0, 'Status: ' + ('Enabled' if self.pf_refs else 'Disabled') + ' for 0 days\n')
        if args == ['/sbin/pfctl', '-E']:
            self.next_token += 1
            self.pf_refs.add(str(self.next_token))
            return done(args, 0, '', 'pf enabled\nToken : %d\n' % self.next_token)
        if args[:2] == ['/sbin/pfctl', '-X']:
            if args[2] not in self.pf_refs:
                return done(args, 1)
            self.pf_refs.discard(args[2])
            return done(args)
        if args[:2] == ['/sbin/pfctl', '-k']:
            return done(args)
        self.forbidden.append(args)
        return done(args, 1)

    def corporate_blocked_on(self, interface):
        for rule in self.anchor:
            if ' on ! ' in rule:
                if rule.split(' on ! ')[1].split()[0] != interface:
                    return True
            else:
                return True
        return False


class FakeHost:
    """Linux host model: iptables chains/jumps, policy rules, routes, a namespace and a container."""

    def __init__(self, spec, mac_link=None):
        self.s = spec
        self.calls = []
        self.forbidden = []
        self.sysctl = {'host': {'net.ipv4.ip_forward': '1', 'net.ipv4.conf.all.rp_filter': '2'},
                       'ns': {'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.rp_filter': '0'}}
        self.chains = {}  # (where, table, chain) -> rules
        self.jumps = {('host', 'filter', 'DOCKER-USER'): ['FOREIGN_SHARED'],
                      ('ns', 'filter', 'FORWARD'): [], ('ns', 'nat', 'POSTROUTING'): [],
                      ('ns', 'mangle', 'FORWARD'): [], ('container', 'nat', 'POSTROUTING'): ['MASQUERADE']}
        self.rules = [{'priority': 0, 'src': 'all', 'table': 'local'},
                      {'priority': 32766, 'src': 'all', 'table': 'main'}]
        self.routes = {'host': [{'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'eth0', 'table': 'main'}],
                       'ns': [{'dst': 'default', 'gateway': spec['host_link_address'], 'dev': spec['namespace_veth'], 'table': 'main'}]}
        self.namespace = True
        self.container = 'running'
        self.mac_link = mac_link
        self.now = [0.0]
        self.slow = {}

    def clock(self):
        return self.now[0]

    def snapshot(self):
        return copy.deepcopy((self.sysctl, self.chains, self.jumps, self.rules, self.routes))

    def __call__(self, args, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append((list(args), input, timeout))
        line = ' '.join(args)
        for key, seconds in self.slow.items():
            if key in line:
                self.now[0] += seconds
        a, where = list(args), 'host'
        if a[:3] == ['ip', 'netns', 'exec']:
            if not self.namespace:
                return done(args, 1, '', 'Cannot open network namespace')
            a, where = a[4:], 'ns'
        elif a[:2] == ['docker', 'exec']:
            a = a[2:]
            if a[0] == '-i':
                a = a[1:]
            if self.container != 'running':
                return done(args, 1, '', 'not running')
            a, where = a[1:], 'container'
        if a[0] == 'mac-link':
            return self.mac_link(a, timeout)
        if a[0] == 'iptables-restore':
            return self.restore(where, input, args)
        if a[0] == 'iptables':
            return self.iptables(where, a[1:], args)
        if a[0] == 'sysctl':
            if a[1] == '-n':
                return done(args, 0, self.sysctl[where][a[2]] + '\n')
            key, value = a[2].split('=')
            if where == 'host':
                self.forbidden.append(args)
            self.sysctl[where][key] = value
            return done(args)
        if a[:2] == ['docker', 'inspect']:
            if self.container == 'absent':
                return done(args, 1, '', 'Error: No such object: x')
            if a[2] == '-f':
                return done(args, 0, 'true\n' if self.container == 'running' else 'false\n')
            nets = {'gw': {'IPAddress': self.s['container_address'], 'MacAddress': self.s['container_mac']}}
            return done(args, 0, json.dumps([{'NetworkSettings': {'Networks': nets}}]))
        if a[0] == 'ip':
            return self.ip(a[1:], args)
        self.forbidden.append(args)
        return done(args, 1)

    def restore(self, where, data, args):
        lines = data.splitlines()
        table = lines[0][1:]
        for line in lines[1:]:
            if line.startswith(':'):
                self.chains.setdefault((where, table, line[1:].split()[0]), [])
            elif line.startswith('-F '):
                name = line[3:]
                if not name.startswith('FROG_CG_'):
                    self.forbidden.append(args)
                self.chains[(where, table, name)] = []
            elif line.startswith('-A '):
                name, rule = line[3:].split(' ', 1)
                self.chains[(where, table, name)].append(rule)
        return done(args)

    def iptables(self, where, a, args):
        table = 'filter'
        if '-w' in a:
            a = [x for x in a if x != '-w']
        if a[:1] == ['-t']:
            table, a = a[1], a[2:]
        op, name = a[0], a[1]
        if op in ('-F', '-X') and not name.startswith('FROG_CG_'):
            self.forbidden.append(args)
        if op == '-S':
            return done(args, 0 if (where, table, name) in self.chains else 1)
        if op == '-F':
            self.chains[(where, table, name)] = []
            return done(args)
        if op == '-X':
            if any(name in j for j in self.jumps.values()):
                return done(args, 1, '', 'Chain is in use')
            self.chains.pop((where, table, name), None)
            return done(args)
        jumps = self.jumps.setdefault((where, table, name), [])
        target = a[a.index('-j') + 1]
        if op == '-C':
            return done(args, 0 if target in jumps else 1)
        if op == '-I':
            jumps.insert(0, target)
            return done(args)
        if op == '-D':
            if target not in jumps:
                return done(args, 1)
            jumps.remove(target)
            return done(args)
        self.forbidden.append(args)
        return done(args, 1)

    @staticmethod
    def parse_route(a):
        entry = {'table': 'main'}
        if a[0] == 'unreachable':
            entry['type'], a = 'unreachable', a[1:]
        entry['dst'] = ip_dst(a[0])
        rest = a[1:]
        for key, field in (('via', 'gateway'), ('dev', 'dev'), ('table', 'table'), ('metric', 'metric')):
            if key in rest:
                value = rest[rest.index(key) + 1]
                entry[field] = int(value) if field == 'metric' else value
        return entry

    def ip(self, a, args):
        where = 'host'
        if a[:1] == ['-n']:
            if not self.namespace:
                return done(args, 1, '', 'Cannot open network namespace')
            where, a = 'ns', a[2:]
        json_out = a[:1] == ['-j']
        if json_out:
            a = a[1:]
        if a == ['netns', 'list']:
            return done(args, 0, (self.s['namespace'] + ' (id: 0)\n') if self.namespace else '')
        if a[0] == 'rule':
            if a[1] == 'show':
                return done(args, 0, json.dumps(self.rules))
            kv = dict(zip(a[2::2], a[3::2]))
            src, dst = ipaddress.ip_network(kv['from']), ipaddress.ip_network(kv['to'])
            rule = {'priority': int(kv['priority']), 'src': str(src.network_address), 'dst': str(dst.network_address),
                    'dstlen': dst.prefixlen, 'iif': kv['iif'], 'table': kv['lookup']}
            if src.prefixlen != 32:
                rule['srclen'] = src.prefixlen
            if a[1] == 'add':
                self.rules.append(rule)
                return done(args)
            # Kernel semantics: unspecified selectors of a stored rule are not compared.
            for x in self.rules:
                if all(x.get(k) == v for k, v in rule.items()):
                    self.rules.remove(x)
                    return done(args)
            return done(args, 2, '', 'RTNETLINK answers: No such file or directory')
        if a[0] == 'route':
            routes = self.routes[where]
            if a[1] == 'show':
                rest = a[2:]
                if rest[:1] == ['table']:
                    rows = [r for r in routes if r['table'] == rest[1]]
                    if not rows:
                        return done(args, 2, '[', 'Error: ipv4: FIB table does not exist.\nDump terminated\n')
                elif rest[:1] == ['exact']:
                    rows = [r for r in routes if r['table'] == 'main' and r['dst'] == ip_dst(rest[1])]
                else:
                    rows = [r for r in routes if r['table'] == 'main']
                return done(args, 0, json.dumps([{k: v for k, v in r.items() if k != 'table'} for r in rows]))
            entry = self.parse_route(a[2:])
            if a[1] == 'replace':
                routes[:] = [r for r in routes if not (r['table'] == entry['table'] and r['dst'] == entry['dst']
                                                       and r.get('metric') == entry.get('metric'))]
                routes.append(entry)
                return done(args)
            if a[1] == 'del':
                for r in routes:
                    if all(r.get(k) == v for k, v in entry.items()) and r.get('type') == entry.get('type'):
                        routes.remove(r)
                        return done(args)
                return done(args, 2, '', 'RTNETLINK answers: No such process')
        self.forbidden.append(args)
        return done(args, 1)


class World:
    """Broker Modes + real hook/helper main() over the simulated VPS and Mac."""

    def __init__(self, d):
        self.d = Path(d)
        self.spec = fixture()
        self.mac = FakeMac(self.spec)
        self.host = FakeHost(self.spec, self.mac_link)
        self.mac_down = False
        self.mac_cfg = self.write('mac.json', {
            'enabled': True, 'prepare_only': False, 'network': self.spec, 'pf_policy_verified': True,
            'dns_fail_closed_verified': True, 'ipv6_policy_verified': True, 'allow_pf_enable': True,
            'state_file': str(self.d / 'mac-state' / 'state.json'), 'lock_file': str(self.d / 'mac.lock'),
            'resolver_dir': str(self.d / 'resolver'), 'probe_host': 'probe.internal.example', 'probe_port': 443})
        self.mode_state = self.d / 'broker' / 'mode.json'
        self.hook_cfg = self.write('hook.json', {
            'enabled': True, 'prepare_only': False, 'network': self.spec, 'peer_isolation_verified': True,
            'supervisor_policy_verified': True, 'resource_state': str(self.d / 'hook-state' / 'owner.json'),
            'mode_state': str(self.mode_state), 'lock_file': str(self.d / 'hook.lock'), 'mac_command': MAC_COMMAND})
        self.config = {'owner_id': '1', 'gateway_option': {
            'enabled': True, 'prepare_only': False, 'network_verified': True,
            'network_hook': ['/operator/hook', '--config', str(self.hook_cfg)], 'state_file': str(self.mode_state)}}
        self.targets = SimTargets(self)
        self.credentials = Mock()
        self.credentials.load.return_value = {'username': 'synthetic-user', 'password': 'synthetic-password'}

    def write(self, name, value):
        path = self.d / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def edit(self, path, **changes):
        value = json.loads(path.read_text())
        value.update(changes)
        path.write_text(json.dumps(value))

    def disable_everywhere(self):
        self.config['gateway_option'].update(enabled=False, prepare_only=True, network_verified=False)
        self.edit(self.hook_cfg, enabled=False, prepare_only=True)
        self.edit(self.mac_cfg, enabled=False, prepare_only=True)

    def mac_link(self, a, timeout):
        if self.mac_down:
            return done(a, 1, '', '{"state": "unavailable"}')
        tail = a[a.index('/operator/run') + 1:]
        argv = ['helper', '--config', str(self.mac_cfg)] + tail
        out = io.StringIO()
        with patch.object(sys, 'argv', argv), patch('sys.stdout', out), \
                patch('gateway_mac.subprocess.run', self.mac), \
                patch.object(gateway_mac.MacNetwork, '__init__', mac_init(self)):
            try:
                code = gateway_mac.main()
            except SystemExit as e:
                code = 1 if e.code else 0
        result = {'exit_code': code, 'stdout': out.getvalue()}
        return done(a, code, json.dumps({'state': 'completed', 'result': result}))

    def hook(self, phase, target):
        out = io.StringIO()
        argv = ['hook', '--config', str(self.hook_cfg)]
        with patch.object(sys, 'argv', argv), patch('sys.stdout', out), \
                patch('sys.stdin', io.StringIO(json.dumps({'phase': phase, 'target': target}) + '\n')), \
                patch('gateway_hook.subprocess.run', self.host):
            code = gateway_hook.main()
        value = json.loads(out.getvalue())
        return {'ok': code == 0 and value.get('ok') is True, 'code': value.get('code', ''), 'kept': value.get('kept', [])}

    def modes(self):
        return Modes(self.config, self.targets, self.credentials, sleep=lambda s: None)

    def phase(self):
        return json.loads(self.mode_state.read_text())['phase']


def mac_init(world):
    original = gateway_mac.MacNetwork.__init__

    def init(self, config, run=None, clock=None, deadline=None, resolve=None, connect=None):
        original(self, config, run=run, deadline=deadline,
                 resolve=lambda host, timeout: world.spec['corporate_dns'],
                 connect=lambda address, timeout: io.BytesIO())
    return init


class SimTargets(FakeTargets):
    def __init__(self, world):
        super().__init__()
        self.world = world
        self.states = {'mac': 'connected', 'vps': 'disconnected'}
        self.hook_override = {}

    def mode_hook(self, phase, target):
        self.events.append(phase)
        if phase in self.hook_override:
            return self.hook_override.pop(phase)
        return self.world.hook(phase, target)

    def mode_start(self, host, credentials, ident, epoch):
        self.events.append('start_' + host)
        if host == 'mac':
            self.world.mac.native_routes = {p: self.world.mac.native for p in self.world.spec['corporate_prefixes']}
        self.states[host] = 'connected'
        return {'ok': True, 'state': 'connected'}

    def mode_stop(self, host, ident, epoch):
        if host == 'mac':
            self.world.mac.native_routes = {}
        return super().mode_stop(host, ident, epoch)


def retention_clock():
    # Only the switch's retention clock jumps; hook/helper deadlines keep real time.
    ticks = itertools.chain([0], itertools.repeat(61))
    return patch.object(modes, 'time', types.SimpleNamespace(monotonic=lambda: next(ticks), sleep=time.sleep))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.w = World(d.name)
        self.w.mac.native_routes = {p: self.w.mac.native for p in self.w.spec['corporate_prefixes']}
        self.host_before = self.w.host.snapshot()

    def assert_clean(self):
        w = self.w
        self.assertEqual(w.host.snapshot(), self.host_before)
        self.assertEqual(w.host.forbidden, [])
        self.assertEqual(w.mac.forbidden, [])
        self.assertEqual(w.mac.anchor, [])
        self.assertFalse(w.mac.tables)
        self.assertEqual(w.mac.routes, {})
        self.assertEqual(w.mac.pf_refs, {'other-owner'})
        self.assertFalse(Path(json.loads(w.hook_cfg.read_text())['resource_state']).exists())

    def switch_to_vps(self):
        with retention_clock():
            return self.w.modes().switch('vps', 'vpn:123456789:10')

    def test_happy_switch_then_recover_restores_both_hosts_without_login(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertEqual(w.mac.routes, {p: 'utun3' for p in w.spec['corporate_prefixes']})
        self.assertTrue(w.mac.corporate_blocked_on('en0'))
        self.assertTrue((Path(w.d) / 'resolver' / 'internal.example').exists())
        w.credentials.load.reset_mock()
        events = len(w.targets.events)
        result = w.modes().recover('vpn:123456789:11')
        self.assertTrue(result['ok'], result)
        self.assertEqual(w.targets.events[events:], ['recover'])  # no stop/start/login
        self.assertEqual(w.credentials.load.call_count, 0)
        self.assertEqual(w.phase(), 'recovered')
        self.assertFalse((Path(w.d) / 'resolver' / 'internal.example').exists())
        self.assertIn('новой явной команде', result['text'])
        self.assert_clean()

    def test_failure_after_block_freezes_then_recover_restores_native_access_without_mfa(self):
        w = self.w
        w.targets.mode_start = Mock(return_value={'ok': False, 'state': 'unknown'})  # MFA timeout
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:20')['code'], 'outcome_unknown')
        self.assertTrue(w.mac.corporate_blocked_on(w.mac.native))  # fail-closed everywhere
        status = w.modes().status()
        self.assertIn('/vpn_recover', status['text'])
        self.assertEqual(w.modes().switch('mac', 'vpn:123456789:21')['code'], 'operator_reconciliation_required')
        # The user brings the native client back by hand; only the gateway block is in the way.
        w.mac.native_routes = {p: w.mac.native for p in w.spec['corporate_prefixes']}
        result = w.modes().recover('vpn:123456789:22')
        self.assertTrue(result['ok'], result)
        self.assertFalse(w.mac.corporate_blocked_on(w.mac.native))
        self.assertEqual(w.mac.native_routes, {p: w.mac.native for p in w.spec['corporate_prefixes']})
        self.assertEqual(w.targets.mode_start.call_count, 1)  # no second login
        self.assertEqual(w.credentials.load.call_count, 1)
        self.assert_clean()

    def test_hook_timeout_freezes_and_recover_withdraws(self):
        w = self.w
        w.targets.hook_override['activate'] = {'ok': False, 'code': 'network_hook_timeout'}
        self.assertEqual(self.switch_to_vps()['code'], 'outcome_unknown')
        self.assertEqual(w.phase(), 'outcome_unknown')
        self.assertTrue(w.modes().recover('vpn:123456789:31')['ok'])
        self.assert_clean()

    def test_recover_after_feature_disabled_removes_only_own_resources(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.disable_everywhere()
        self.assertEqual(w.hook('activate', 'vps')['code'], 'gateway_disabled')
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:41')['code'], 'gateway_disabled')
        self.assertTrue(w.modes().recover('vpn:123456789:42')['ok'])
        self.assert_clean()

    def test_disabled_without_own_state_creates_nothing_and_runs_nothing(self):
        w = self.w
        w.disable_everywhere()
        before = sorted(p.name for p in Path(w.d).iterdir())
        result = w.modes().recover('vpn:123456789:50')
        self.assertEqual(result['code'], 'nothing_to_recover')
        self.assertEqual(w.targets.events, [])
        hook = w.hook('recover', 'mac')
        self.assertEqual(hook['code'], 'nothing_owned')
        out = w.mac_link(['mac-link', '/operator/run', '--phase', 'recover', '--target', 'mac', '--epoch', '1'], 10)
        self.assertEqual(json.loads(json.loads(out.stdout)['result']['stdout'])['code'], 'nothing_owned')
        self.assertEqual(w.host.calls + w.mac.calls, [])
        self.assertEqual(sorted(p.name for p in Path(w.d).iterdir()), before)

    def test_foreign_changes_are_kept(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        h, s = w.host, w.spec
        resolver = Path(w.d) / 'resolver' / 'internal.example'
        resolver.write_text('nameserver 192.0.2.53\n')              # edited by another owner
        foreign_rule = {'priority': s['rule_priority'], 'src': '10.9.0.0', 'srclen': 24, 'dst': '10.60.0.0',
                        'dstlen': 16, 'iif': s['host_bridge'], 'table': str(s['table'])}
        h.rules.append(foreign_rule)
        foreign_route = {'dst': '192.168.55.0/24', 'gateway': '192.0.2.9', 'dev': 'eth0', 'table': str(s['table'])}
        h.routes['host'].append(foreign_route)
        w.mac.native_routes['10.200.0.0/16'] = w.mac.native
        result = w.modes().recover('vpn:123456789:60')
        self.assertTrue(result['ok'], result)
        self.assertIn('Чужие изменения сохранены', result['text'])
        self.assertEqual(resolver.read_text(), 'nameserver 192.0.2.53\n')
        self.assertIn(foreign_rule, h.rules)
        self.assertIn(foreign_route, h.routes['host'])
        self.assertIn('10.200.0.0/16', w.mac.native_routes)
        self.assertEqual(w.mac.anchor, [])
        self.assertEqual(h.forbidden + w.mac.forbidden, [])

    def test_foreign_return_route_is_neither_replaced_nor_deleted(self):
        w = self.w
        s = w.spec
        foreign = {'dst': '10.9.0.2', 'gateway': '198.51.100.99', 'dev': s['host_bridge'], 'table': 'main'}
        w.host.routes['host'].append(foreign)
        self.assertEqual(self.switch_to_vps()['code'], 'network_preflight_failed')
        self.assertIn(foreign, w.host.routes['host'])
        # Appearing after ownership was established: activation refuses instead of replacing it.
        w.host.routes['host'].remove(foreign)
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertTrue(w.modes().recover('vpn:123456789:70')['ok'])
        w.host.routes['host'].append(foreign)
        w.mode_state.unlink()
        self.host_before = w.host.snapshot()
        hook = NetworkHook(json.loads(w.hook_cfg.read_text()), w.host)
        hook.record(return_route=False)
        self.assertFalse(hook.execute('activate', 'vps', 9)['ok'])
        self.assertIn(foreign, w.host.routes['host'])

    def test_mac_unreachable_keeps_peer_blocked_and_recovery_can_be_retried(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.mac_down = True
        result = w.modes().recover('vpn:123456789:80')
        self.assertEqual(result['code'], 'recovery_incomplete')
        self.assertEqual(w.phase(), 'recovery_incomplete')
        host_rules = w.host.chains[('host', 'filter', 'FROG_CG_HOST')]
        self.assertFalse(any('--mac-source' in r for r in host_rules))   # peer no longer exposed
        self.assertIn('FROG_CG_HOST', w.host.jumps[('host', 'filter', 'DOCKER-USER')])
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:81')['code'], 'operator_reconciliation_required')
        w.mac_down = False
        self.assertTrue(w.modes().recover('vpn:123456789:82')['ok'])
        self.assert_clean()

    def test_recreated_namespace_and_restarted_container_are_left_alone(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.host.sysctl['ns'] = {'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.rp_filter': '0'}  # new namespace
        for key in list(w.host.chains):
            if key[0] in ('ns', 'container'):
                del w.host.chains[key]
        for key in w.host.jumps:
            if key[0] in ('ns', 'container'):
                w.host.jumps[key] = [j for j in w.host.jumps[key] if not j.startswith('FROG_CG_')]
        w.host.routes['ns'] = [r for r in w.host.routes['ns'] if r['dst'] == 'default']
        self.assertTrue(w.modes().recover('vpn:123456789:90')['ok'])
        self.assert_clean()

    def test_recovery_epoch_fences_a_delayed_apply(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        old = json.loads(w.mode_state.read_text())['epoch']
        self.assertTrue(w.modes().recover('vpn:123456789:95')['ok'])
        out = w.mac_link(['mac-link', '/operator/run', '--phase', 'activate', '--target', 'vps', '--epoch', str(old)], 10)
        self.assertEqual(json.loads(json.loads(out.stdout)['result']['stdout'])['code'], 'stale_mode_epoch')
        self.assertEqual(w.mac.anchor, [])

    def test_recover_never_issues_broad_or_shared_operations(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertTrue(w.modes().recover('vpn:123456789:96')['ok'])
        for args, _, _ in w.host.calls:
            if args[:3] == ['ip', 'rule', 'del']:
                self.assertIn('from', args)
                self.assertIn('to', args)
            if any(x.startswith('net.ipv4.ip_forward=') for x in args):
                self.assertEqual(args[:3], ['ip', 'netns', 'exec'])  # namespace-local only
        for args, _, _ in w.mac.calls:
            self.assertNotIn('-d', args)
            self.assertNotIn('all', args)
        self.assertEqual(w.host.forbidden + w.mac.forbidden, [])

    def test_broker_recover_is_owner_only_and_never_loads_credentials(self):
        w = self.w
        with tempfile.TemporaryDirectory() as d:
            cfg = dict(w.config, credential_file='unused', state_file=str(Path(d) / 'b.json'), maintenance=True)
            cfg['gateway_option'] = dict(cfg['gateway_option'], enabled=False, prepare_only=True)
            credentials = Mock()
            broker = Broker(cfg, w.targets, credentials)
            self.assertFalse(broker.handle({'actor': '2', 'action': 'mode_recover', 'request_id': 'vpn:2:12345'})['ok'])
            with patch('threading.Thread', side_effect=AssertionError('no worker without state')):
                result = broker.handle({'actor': '1', 'action': 'mode_recover', 'request_id': 'vpn:1:12345'})
            self.assertEqual(result['code'], 'nothing_to_recover')
            self.assertEqual(credentials.mock_calls, [])
            self.assertFalse(Path(cfg['gateway_option']['state_file']).exists())


class HierarchyTests(unittest.TestCase):
    def test_each_outer_timeout_strictly_covers_the_inner_budget(self):
        p = gateway_plan
        self.assertGreater(p.MAC_HELPER_BUDGET, p.MAC_LOCK_WAIT + p.MAC_COMMAND_TIMEOUT + p.MAC_FAILSAFE_RESERVE)
        self.assertGreater(p.MAC_LINK_EXEC_TIMEOUT, p.MAC_HELPER_BUDGET)
        self.assertGreaterEqual(p.MAC_CALL_TIMEOUT, p.MAC_LINK_EXEC_TIMEOUT + 5 + 2 * 4)
        self.assertGreater(p.HOOK_BUDGET, p.HOOK_LOCK_WAIT + p.MAC_CALL_TIMEOUT + p.HOST_FAILSAFE_RESERVE)
        self.assertGreater(p.HOOK_PROCESS_TIMEOUT, p.HOOK_BUDGET)

    def test_broker_waits_longer_than_the_hook_budget_and_maps_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            hook = Path(d) / 'hook'
            hook.write_text('#!/bin/sh\n')
            hook.chmod(0o700)
            t = Targets({'gateway_option': {'network_hook': [str(hook)]}})
            seen = {}

            def run(args, **kwargs):
                seen.update(kwargs)
                return done(args, 0, '{"ok": true}')
            with patch('targets.subprocess.run', run):
                self.assertTrue(t.mode_hook('verify', 'vps')['ok'])
            self.assertEqual(seen['timeout'], gateway_plan.HOOK_PROCESS_TIMEOUT)
            with patch('targets.subprocess.run', side_effect=subprocess.TimeoutExpired('hook', 1)):
                self.assertEqual(t.mode_hook('activate', 'vps')['code'], 'network_hook_timeout')

    def test_slow_but_valid_mac_step_completes_within_budget(self):
        with tempfile.TemporaryDirectory() as d:
            mac = FakeMac(fixture())
            mac.slow = {'-s info': gateway_plan.MAC_COMMAND_TIMEOUT - 0.5}
            cfg = {'enabled': True, 'prepare_only': False, 'network': fixture(), 'allow_pf_enable': True,
                   'state_file': str(Path(d) / 's.json'), 'resolver_dir': str(Path(d) / 'r')}
            obj = MacNetwork(cfg, mac, clock=mac.clock)
            self.assertTrue(obj.execute('block', 'mac', 1)['ok'])
            self.assertLessEqual(mac.now[0], gateway_plan.MAC_HELPER_BUDGET)
            self.assertTrue(all(t == gateway_plan.MAC_COMMAND_TIMEOUT for _, _, t in mac.calls))

    def test_mac_helper_refuses_new_steps_at_deadline_and_still_reblocks(self):
        with tempfile.TemporaryDirectory() as d:
            mac = FakeMac(fixture())
            mac.slow = {'-k': 7}  # every state kill takes 7 s: the phase cannot finish in budget
            cfg = {'enabled': True, 'prepare_only': False, 'network': fixture() | {'corporate_prefixes': [
                '10.60.%d.0/24' % i for i in range(20)], 'corporate_dns': '10.60.0.53'},
                'allow_pf_enable': True, 'state_file': str(Path(d) / 's.json'), 'resolver_dir': str(Path(d) / 'r')}
            obj = MacNetwork(cfg, mac, clock=mac.clock)
            result = obj.execute('block', 'mac', 1)
            self.assertEqual(result['code'], 'mac_network_phase_failed')
            self.assertLessEqual(mac.now[0], gateway_plan.MAC_HELPER_BUDGET + gateway_plan.MAC_COMMAND_TIMEOUT)
            self.assertTrue(mac.anchor)  # fail-closed block is in place
            self.assertEqual(json.loads(Path(cfg['state_file']).read_text())['phase'], 'outcome_unknown')

    def test_hook_does_not_start_a_mac_call_it_could_not_wait_for(self):
        host = FakeHost(fixture(), mac_link=Mock(side_effect=AssertionError('mac call started')))
        with tempfile.TemporaryDirectory() as d:
            cfg = {'enabled': True, 'prepare_only': False, 'network': fixture(), 'mac_command': MAC_COMMAND,
                   'resource_state': str(Path(d) / 'o.json')}
            hook = NetworkHook(cfg, host, clock=host.clock)
            host.now[0] = gateway_plan.HOOK_BUDGET - gateway_plan.MAC_CALL_TIMEOUT  # too little left
            self.assertFalse(hook.execute('block', 'mac', 1)['ok'])
            self.assertEqual(host.chains[('host', 'filter', 'FROG_CG_HOST')][-1], '-o veth_corp -j REJECT')

    def test_slow_but_valid_mac_call_is_not_cut_off(self):
        seen = []

        def link(a, timeout):
            seen.append(timeout)
            host.now[0] += gateway_plan.MAC_CALL_TIMEOUT - 1
            return done(a, 0, json.dumps({'state': 'completed', 'result': {'exit_code': 0, 'stdout': '{"ok": true}'}}))
        host = FakeHost(fixture(), mac_link=link)
        with tempfile.TemporaryDirectory() as d:
            cfg = {'enabled': True, 'prepare_only': False, 'network': fixture(), 'mac_command': MAC_COMMAND,
                   'resource_state': str(Path(d) / 'o.json')}
            self.assertTrue(NetworkHook(cfg, host, clock=host.clock).execute('activate', 'vps', 1)['ok'])
        self.assertEqual(seen, [gateway_plan.MAC_CALL_TIMEOUT])

    def test_relay_timeout_mismatch_is_refused_before_dispatch(self):
        host = FakeHost(fixture(), mac_link=Mock(side_effect=AssertionError('dispatched')))
        with tempfile.TemporaryDirectory() as d:
            cfg = {'enabled': True, 'prepare_only': False, 'network': fixture(),
                   'mac_command': ['mac-link', '--timeout', '25', 'shell', '--', 'sudo', '-n', '/operator/run'],
                   'resource_state': str(Path(d) / 'o.json')}
            self.assertFalse(NetworkHook(cfg, host).execute('block', 'mac', 1)['ok'])


class EpochAndInstallerTests(unittest.TestCase):
    def controller(self, d):
        return Controller({'state_file': str(Path(d) / 'mac.json'), 'network_binary': '/unused',
                           'service_id': 's', 'mode_epoch_required': True})

    def test_epoch_high_water_survives_cache_eviction_and_restart(self):
        with tempfile.TemporaryDirectory() as d, \
                patch('mac_agent.subprocess.run', return_value=Mock(stdout='{"ok":true,"state":"disconnected"}')) as run:
            c = self.controller(d)
            self.assertTrue(c.execute({'action': 'disconnect', 'request_id': 'vpn:1:100:stop', 'mode_epoch': 50})['ok'])
            for i in range(300):
                c.execute({'action': 'disconnect', 'request_id': 'vpn:1:%d:stop' % (1000 + i), 'mode_epoch': 50})
                if i in (126, 127, 128):
                    self.assertEqual(c.execute({'action': 'disconnect', 'request_id': 'vpn:1:%d:old' % i,
                                                'mode_epoch': 49})['code'], 'stale_mode_epoch')
            restarted = self.controller(d)
            calls = run.call_count
            for epoch in (1, 49):
                self.assertEqual(restarted.execute({'action': 'disconnect', 'request_id': 'vpn:1:%d:late' % epoch,
                                                    'mode_epoch': epoch})['code'], 'stale_mode_epoch')
            self.assertEqual(run.call_count, calls)
            self.assertNotIn('_mode_epoch', json.loads((Path(d) / 'mac.json').read_text()))

    def test_legacy_cache_epoch_is_migrated_without_lowering(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'mac.json').write_text(json.dumps({'_mode_epoch': 70, 'vpn:1:1:stop': {'ok': True}}))
            c = self.controller(d)
            self.assertEqual((Path(d) / 'mac.epoch').read_text(), '70')
            self.assertEqual(c.execute({'action': 'disconnect', 'request_id': 'vpn:1:2:stop', 'mode_epoch': 69})['code'],
                             'stale_mode_epoch')
            (Path(d) / 'mac.epoch').write_text('80')
            (Path(d) / 'mac.json').write_text(json.dumps({'_mode_epoch': 70}))
            self.assertEqual(self.controller(d).mode_epoch, 80)

    def test_epoch_is_durable_before_dispatch(self):
        with tempfile.TemporaryDirectory() as d:
            def run(*a, **k):
                self.assertEqual((Path(d) / 'mac.epoch').read_text(), '7')
                return Mock(stdout='{"ok":true,"state":"disconnected"}')
            with patch('mac_agent.subprocess.run', run):
                self.assertTrue(self.controller(d).execute({'action': 'disconnect', 'request_id': 'vpn:1:7:stop',
                                                            'mode_epoch': 7})['ok'])

    def installer_paths(self, d):
        base = Path(d)
        (base / 'helpers').mkdir()
        (base / 'support').mkdir()
        (base / 'sudoers.d').mkdir()
        cfg = base / 'gateway.json'
        cfg.write_text(json.dumps({'enabled': False, 'prepare_only': True}))
        return cfg, base / 'helpers' / 'FrogVPN', base / 'support' / 'FrogVPN', base / 'sudoers.d' / 'frog'

    def test_installer_failure_removes_only_what_it_created(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, root, data, sudoers = self.installer_paths(d)

            def run(args, **kwargs):
                if args == ['/usr/sbin/visudo', '-c']:
                    raise subprocess.CalledProcessError(1, args)
                return done(args)
            with self.assertRaises(subprocess.CalledProcessError):
                install('operator', cfg, root, data, sudoers, run)
            self.assertFalse(root.exists() or data.exists() or sudoers.exists())
            self.assertTrue(root.parent.exists() and data.parent.exists() and sudoers.parent.exists())

    def test_installer_partial_mkdir_failure_cleans_the_first_directory(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, root, data, sudoers = self.installer_paths(d)
            data.parent.rmdir()  # second mkdir fails
            with self.assertRaises(FileNotFoundError):
                install('operator', cfg, root, data, sudoers, lambda *a, **k: done(a))
            self.assertFalse(root.exists())
            self.assertFalse(sudoers.exists())
            self.assertEqual(install('operator', cfg, root, data.parent.parent / 'data2', sudoers,
                                     lambda *a, **k: done(a))['installed'], True)

    def test_installer_refuses_existing_installation_without_touching_it(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, root, data, sudoers = self.installer_paths(d)
            root.mkdir()
            (root / 'marker').write_text('keep')
            with self.assertRaises(SystemExit):
                install('operator', cfg, root, data, sudoers, lambda *a, **k: done(a))
            self.assertEqual((root / 'marker').read_text(), 'keep')
            self.assertFalse(data.exists())

    def test_rendered_plan_uses_neutral_personal_vpn_wording(self):
        text = json.dumps(render(fixture())).lower()
        self.assertIn('personal vpn', text)
        for brand in ('amnezia', 'wireguard', 'openvpn'):
            self.assertNotIn(brand, text)


if __name__ == '__main__':
    unittest.main()
