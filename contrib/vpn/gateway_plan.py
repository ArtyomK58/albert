"""Validate and render an inert gateway plan. This module never runs commands."""
import argparse
import fcntl
import ipaddress
import json
from pathlib import Path
import re
import time


PRIVATE = tuple(ipaddress.ip_network(s) for s in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
OVERLAY = (ipaddress.ip_network('100.64.0.0/10'),)
NON_UNICAST = tuple(ipaddress.ip_network(s) for s in ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3'))

# Timeout hierarchy, innermost first. Each layer starts work only when its whole
# per-step timeout plus a fail-safe reserve still fits, so an outer layer never
# kills an inner step that is still within its own allowed budget.
MAC_COMMAND_TIMEOUT = 8                       # one OS command inside the Mac helper
MAC_FAILSAFE_RESERVE = 3 * MAC_COMMAND_TIMEOUT  # re-blocking after a failed phase
MAC_LOCK_WAIT = 10
MAC_HELPER_BUDGET = 90                        # absolute wall time of one helper phase
MAC_LINK_EXEC_TIMEOUT = MAC_HELPER_BUDGET + 10  # relay exec limit; covers sudo/interpreter start
MAC_LINK_OVERHEAD = 5 + 2 * 4 + 7             # relay HTTP slack, two endpoint probes, process start
MAC_CALL_TIMEOUT = MAC_LINK_EXEC_TIMEOUT + MAC_LINK_OVERHEAD
HOST_COMMAND_TIMEOUT = 8
HOST_FAILSAFE_RESERVE = 3 * HOST_COMMAND_TIMEOUT
HOOK_LOCK_WAIT = 10
HOOK_BUDGET = MAC_CALL_TIMEOUT + HOST_FAILSAFE_RESERVE + 90
HOOK_PROCESS_TIMEOUT = HOOK_BUDGET + 15       # broker -> hook process, includes interpreter start


class DeadlineExceeded(RuntimeError):
    pass


class Deadline:
    """Absolute budget. A step starts only if its full timeout and the reserve still fit."""

    def __init__(self, seconds, clock):
        self.clock = clock
        self.end = clock() + seconds

    def remaining(self):
        return self.end - self.clock()

    def admit(self, step_timeout, reserve):
        if self.remaining() < step_timeout + reserve:
            raise DeadlineExceeded('deadline_exceeded_before_step')
        return step_timeout


def acquire(lock, seconds, clock=time.monotonic, sleep=time.sleep):
    """Bounded exclusive file lock; an orphaned holder cannot block a phase forever."""
    end = clock() + seconds
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if clock() >= end:
                return False
            sleep(0.1)


def reason(error):
    """A bounded machine code for operators; free-form OS text and paths are never returned."""
    text = str(error)
    return text if re.fullmatch(r'[a-z][a-z0-9_]{2,63}', text) else 'unexpected_error'


def network(value):
    n = ipaddress.ip_network(value, strict=True)
    if n.version != 4:
        raise ValueError('ipv4_only')
    return n


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,14}', value):
        raise ValueError('invalid_interface_or_namespace')
    return value


def validate(c):
    if c.get('version') != 1:
        raise ValueError('unsupported_gateway_version')
    peer = network(c['mac_peer'])
    transport = c.get('transport', 'personal_vpn')
    if transport not in ('personal_vpn', 'tailnet'):
        raise ValueError('unsupported_gateway_transport')
    pools = OVERLAY if transport == 'tailnet' else PRIVATE
    if peer.prefixlen != 32 or not any(peer.subnet_of(p) for p in pools):
        raise ValueError('single_private_peer_required')
    prefixes = sorted(set(network(p) for p in c['corporate_prefixes']), key=str)
    if not prefixes:
        raise ValueError('corporate_prefixes_required')
    denied = [network(p) for p in c['protected_prefixes']] + [peer]
    for key in ('vps_endpoint', 'corporate_endpoint', 'container_address', 'host_link_address', 'namespace_link_address'):
        a = ipaddress.ip_address(c[key])
        if a.version != 4:
            raise ValueError('ipv4_only')
        denied.append(ipaddress.ip_network(str(a) + '/32'))
    for p in prefixes:
        if p.prefixlen == 0 or (not c.get('allow_public_prefixes', False) and not any(p.subnet_of(n) for n in PRIVATE)):
            raise ValueError('unapproved_public_or_default_route')
        if any(p.overlaps(n) for n in denied):
            raise ValueError('corporate_route_overlaps_protected_network')
    for key in ('container', 'host_bridge', 'host_veth', 'namespace', 'namespace_veth', 'tunnel'):
        identifier(c[key])
    if transport != 'tailnet' and not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', c.get('container_mac', '')):
        raise ValueError('container_identity_required')
    if c.get('ipv6_policy') != 'deny':
        raise ValueError('ipv6_requires_separate_acceptance')
    if not isinstance(c.get('table'), int) or not 10000 <= c['table'] <= 30000:
        raise ValueError('invalid_private_routing_table')
    if not isinstance(c.get('rule_priority'), int) or not 10000 <= c['rule_priority'] <= 30000:
        raise ValueError('invalid_private_rule_priority')
    if not isinstance(c.get('tcp_mss'), int) or not 1000 <= c['tcp_mss'] <= 1400:
        raise ValueError('invalid_tcp_mss')
    if not c.get('dns_zones'):
        raise ValueError('corporate_dns_zones_required')
    for domain in c['dns_zones']:
        if not isinstance(domain, str) or len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*', domain):
            raise ValueError('invalid_dns_zone')
    dns = ipaddress.ip_address(c['corporate_dns'])
    if not any(dns in p for p in prefixes):
        raise ValueError('dns_not_in_corporate_allowlist')
    local_egress(c, prefixes + denied)
    return prefixes


def local_egress(c, denied):
    """Public sites that must leave through the client's own uplink, not the overlay exit."""
    egress = [network(p) for p in c.get('local_egress_prefixes', [])]
    if not egress:
        return []
    identifier(c.get('local_egress_interface'))
    for p in egress:
        # Narrow public destinations only: never a default, private or overlay range.
        if p.prefixlen < 16 or any(p.overlaps(n) for n in PRIVATE + OVERLAY + NON_UNICAST):
            raise ValueError('local_egress_must_be_narrow_public_prefix')
        if any(p.overlaps(n) for n in denied):
            raise ValueError('local_egress_overlaps_gateway_network')
    return egress


def render(c):
    prefixes = validate(c)
    if c.get('transport') == 'tailnet':
        from types import SimpleNamespace
        from tailnet_guard import TailnetGuard
        guard = TailnetGuard(SimpleNamespace(spec=c))
        return {'schema': 1, 'state': 'staged', 'applied': False, 'transport': 'tailnet',
                'guard_block': guard.render(False, False), 'guard_active': guard.render(True, True),
                'executor': 'gateway_hook.NetworkHook', 'operations': [],
                'host_return_route': 'owned by overlay; never replaced by gateway',
                'container_changes': False,
                'mac': {'route_prefixes': [str(p) for p in prefixes], 'live_files_written': False},
                'acceptance_required': ['early-filter-peer-isolation', 'overlay-nat-preserves-source',
                                        'dns-fail-closed', 'ipv6-no-leak', 'mfa-single-session']}
    peer = c['mac_peer']
    table, priority = str(c['table']), str(c['rule_priority'])
    ns = ['ip', 'netns', 'exec', c['namespace']]
    operations = []

    def op(phase, argv, inverse=None, ensure=False):
        operations.append({'phase': phase, 'argv': argv, 'inverse': inverse, 'ensure': ensure})

    # Every chain is exclusively owned. Shared Docker chains are never flushed.
    for prefix, binary in (([], 'iptables'), (ns, 'iptables')):
        op('guards', prefix + [binary, '-w', '-N', 'FROG_CORP'], ensure=True)
    op('guards', ['iptables', '-w', '-I', 'DOCKER-USER', '1', '-j', 'FROG_CORP'],
       ['iptables', '-w', '-D', 'DOCKER-USER', '-j', 'FROG_CORP'], ensure=True)
    op('guards', ns + ['iptables', '-w', '-I', 'FORWARD', '1', '-j', 'FROG_CORP'],
       ns + ['iptables', '-w', '-D', 'FORWARD', '-j', 'FROG_CORP'], ensure=True)
    op('namespace', ns + ['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    op('namespace', ns + ['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=2'])
    op('return_path', ['ip', 'route', 'replace', peer, 'via', c['container_address'], 'dev', c['host_bridge']],
       ['ip', 'route', 'del', peer, 'via', c['container_address'], 'dev', c['host_bridge']])
    op('return_path', ['ip', '-n', c['namespace'], 'route', 'replace', peer,
                       'via', c['host_link_address'], 'dev', c['namespace_veth']])
    op('guards', ns + ['iptables', '-w', '-A', 'FROG_CORP', '-m', 'conntrack',
                       '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    op('guards', ['iptables', '-w', '-A', 'FROG_CORP', '-i', c['host_veth'], '-o', c['host_bridge'],
                  '-d', peer, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    op('guards', ['iptables', '-w', '-A', 'FROG_CORP', '-o', c['host_veth'],
                  '-d', c['namespace_link_address'] + '/32', '-m', 'conntrack',
                  '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    for p in prefixes:
        dest = str(p)
        # Unreachable entries stay when a tunnel/link disappears; no WAN fallback.
        op('guards', ['ip', 'route', 'replace', 'unreachable', dest, 'table', table, 'metric', '32760'])
        op('guards', ['ip', '-n', c['namespace'], 'route', 'replace', 'unreachable', dest, 'metric', '32760'])
        rule = ['ip', 'rule', 'add', 'priority', priority, 'iif', c['host_bridge'],
                'from', peer, 'to', dest, 'lookup', table]
        op('guards', rule, rule[:2] + ['del'] + rule[3:], ensure=True)
        # The container must retain peer identity before packets reach the host.
        nat = ['docker', 'exec', c['container'], 'iptables', '-w', '-t', 'nat', '-I',
               'POSTROUTING', '1', '-s', peer, '-d', dest, '-j', 'ACCEPT']
        op('gateway', nat, ['docker', 'exec', c['container'], 'iptables', '-w', '-t', 'nat',
                           '-D', 'POSTROUTING', '-s', peer, '-d', dest, '-j', 'ACCEPT'], ensure=True)
        op('gateway', ['ip', 'route', 'replace', dest, 'via', c['namespace_link_address'],
                       'dev', c['host_veth'], 'table', table, 'metric', '10'])
        op('gateway', ['iptables', '-w', '-A', 'FROG_CORP', '-i', c['host_bridge'],
                       '-o', c['host_veth'], '-s', peer, '-d', dest,
                       '-m', 'mac', '--mac-source', c['container_mac'], '-j', 'ACCEPT'])
        op('gateway', ns + ['iptables', '-w', '-A', 'FROG_CORP', '-i', c['namespace_veth'],
                            '-o', c['tunnel'], '-s', peer, '-d', dest, '-j', 'ACCEPT'])
        op('guards', ['iptables', '-w', '-A', 'FROG_CORP', '-i', c['host_bridge'], '-d', dest, '-j', 'REJECT'])
        op('gateway', ns + ['iptables', '-w', '-t', 'nat', '-A', 'POSTROUTING', '-s', peer,
                            '-d', dest, '-o', c['tunnel'], '-j', 'MASQUERADE'])
    op('guards', ['iptables', '-w', '-A', 'FROG_CORP', '-o', c['host_veth'], '-j', 'REJECT'])
    op('guards', ns + ['iptables', '-w', '-A', 'FROG_CORP', '-j', 'REJECT'])
    mss = str(c['tcp_mss'])
    for direction in ('-s', '-d'):
        op('gateway', ns + ['iptables', '-w', '-t', 'mangle', '-A', 'FORWARD', direction, peer,
                            '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-m', 'tcpmss',
                            '--mss', str(c['tcp_mss'] + 1) + ':65535', '-j', 'TCPMSS', '--set-mss', mss])
    return {'schema': 1, 'state': 'staged', 'applied': False, 'operations': operations,
            'operation_order': 'Render order is significant; guards precede routing exposure and per-prefix allows precede rejects.',
            'mac': {'interface_selection': 'find the configured personal VPN source address; never pin an utun number',
                    'route_prefixes': [str(p) for p in prefixes],
                    'resolver_files': {zone: 'nameserver ' + c['corporate_dns'] + '\n' for zone in c['dns_zones']},
                    'live_files_written': False},
            'acceptance_required': ['peer-isolation', 'dns-fail-closed', 'ipv6-no-leak', 'mfa-single-session',
                                    'route-collision-check', 'namespace-recreation', 'latency-comparison']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    args = p.parse_args()
    print(json.dumps(render(json.loads(Path(args.config).read_text())), indent=2))
