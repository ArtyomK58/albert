"""Deterministic simulated client and gateway hosts for gateway regressions. No OS command runs."""
import copy
import io
import ipaddress
import itertools
import json
from pathlib import Path
import subprocess
import sys
import time
import types
from unittest.mock import Mock, patch

import gateway_hook
import gateway_mac
import gateway_plan
import modes
from modes import Modes
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
        self.rule_defaults = {}  # attributes the kernel adds to a created rule
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
                self.rules.append(dict(rule, **self.rule_defaults))
                return done(args)
            # Kernel semantics: the first rule matching every selector the request carries
            # is removed; selectors the request omits (fwmark, uidrange, protocol...) are
            # wildcards. Prefix lengths are always carried by the request.
            for x in self.rules:
                if (all(x.get(k) == v for k, v in rule.items() if k not in ('srclen', 'dstlen'))
                        and x.get('srclen', 32) == src.prefixlen and x.get('dstlen', 32) == dst.prefixlen):
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


