import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from gateway_fakes import FakeHost, FakeMac, done
from gateway_hook import NetworkHook
from gateway_mac import MacNetwork
from gateway_plan import validate, render
from gateway_boot import bootstrap
from tailnet_guard import TailnetGuard, digest
from test_gateway import fixture


def tailnet_spec():
    return fixture() | {'transport': 'tailnet', 'mac_peer': '100.70.80.90/32',
                        'host_bridge': 'tailscale0', 'tailnet_node_id': 'synthetic-node'}


class OverlayHost(FakeHost):
    def __init__(self, spec):
        super().__init__(spec)
        self.nft = None
        self.online = True
        self.node = spec['tailnet_node_id']
        self.advertised = list(spec['corporate_prefixes'])

    def __call__(self, args, input=None, **kwargs):
        peer = str(ipaddress.ip_network(self.s['mac_peer']).network_address)
        if args[:1] == ['nft']:
            self.calls.append((list(args), input, kwargs.get('timeout')))
            if args[1:3] == ['-s', '-j']:
                return done(args, 0, json.dumps(self.nft)) if self.nft else done(args, 1, '', 'No such file or directory')
            if args[1:] == ['-f', '-']:
                self.nft = {'nftables': [{'transaction': input}]}
            elif args[1:3] == ['delete', 'table']:
                self.nft = None
            else:
                raise AssertionError(args)
            return done(args)
        if args == ['tailscale', 'status', '--json']:
            return done(args, 0, json.dumps({'Peer': {'key': {'ID': self.node, 'Online': self.online,
                                                           'TailscaleIPs': [peer]}}}))
        if args == ['tailscale', 'debug', 'prefs']:
            return done(args, 0, json.dumps({'AdvertiseRoutes': self.advertised}))
        if args == ['ip', '-j', 'route', 'get', peer]:
            return done(args, 0, json.dumps([{'dev': self.s['host_bridge']}]))
        return super().__call__(args, input=input, **kwargs)


class TailnetTests(unittest.TestCase):
    def test_boot_blocks_without_mac_or_auth_and_clears_only_ready_mode(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            p = Path(d) / 'mode'
            c = hook.c | {'mode_state': str(p)}
            p.write_text(json.dumps({'epoch': 2, 'phase': 'ready', 'mode': 'vps', 'requests': {}}))
            self.assertTrue(bootstrap(c, hook)['ok'])
            self.assertEqual(json.loads(p.read_text())['phase'], 'recovered')
            self.assertEqual(json.loads(p.read_text())['epoch'], 3)
            hook.mac.assert_not_called()
            p.write_text(json.dumps({'epoch': 4, 'phase': 'outcome_unknown', 'requests': {}}))
            bootstrap(c, hook)
            self.assertEqual(json.loads(p.read_text())['phase'], 'outcome_unknown')

    def test_disabled_boot_never_reads_state_or_touches_network(self):
        hook = Mock(side_effect=AssertionError('disabled'))
        self.assertFalse(bootstrap({'enabled': False}, hook)['ok'])
        self.assertEqual(hook.mock_calls, [])

    def setup_hook(self, d):
        spec = tailnet_spec()
        host = OverlayHost(spec)
        hook = NetworkHook({'enabled': True, 'prepare_only': False, 'network': spec,
                            'resource_state': str(Path(d) / 'owner.json'),
                            'peer_isolation_verified': True, 'supervisor_policy_verified': True}, host)
        hook.mac = Mock(return_value={'ok': True})
        return host, hook

    def test_only_single_overlay_peer_and_supported_transport(self):
        validate(tailnet_spec())
        for patch in ({'mac_peer': '100.70.80.0/24'}, {'mac_peer': '10.9.0.2/32'},
                      {'transport': 'unknown'}):
            with self.assertRaises(ValueError):
                validate(tailnet_spec() | patch)

    def test_plan_does_not_offer_legacy_docker_or_host_return_route(self):
        plan = render(tailnet_spec())
        self.assertFalse(plan['applied'])
        self.assertFalse(plan['container_changes'])
        self.assertIn('priority -10', plan['guard_block'])
        self.assertIn('0xff00ffff', plan['guard_active'])

    def test_full_recovery_keeps_shared_overlay_routes_nat_and_forwarding(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            before = host.snapshot()
            self.assertTrue(hook.execute('preflight', 'vps', 1)['ok'])
            self.assertTrue(hook.execute('block', 'vps', 1)['ok'])
            self.assertTrue(hook.execute('activate', 'vps', 1)['ok'])
            self.assertFalse(hook.owner()['resources'].get('return_route'))
            self.assertFalse(any(a[:1] == ['docker'] for a, _, _ in host.calls))
            self.assertEqual(hook.execute('recover', 'vps', 2)['code'], 'recovered')
            self.assertIsNone(host.nft)
            self.assertEqual(host.snapshot(), before)
            self.assertEqual(host.forbidden, [])

    def test_node_identity_and_presence_are_verified(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            host.node = 'different-node'
            self.assertFalse(hook.execute('preflight', 'vps', 1)['ok'])
            host.node, host.online = hook.spec['tailnet_node_id'], False
            self.assertFalse(hook.execute('preflight', 'vps', 1)['ok'])
            self.assertIsNone(hook.owner())

    def test_default_exit_without_explicit_corporate_subnets_fails_preflight(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            host.advertised = ['0.0.0.0/0', '::/0']
            self.assertFalse(hook.execute('preflight', 'vps', 1)['ok'])
            hook.mac.assert_not_called()

    def test_modified_or_unowned_table_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            host.nft = {'nftables': [{'foreign': True}]}
            self.assertFalse(hook.execute('block', 'vps', 1)['ok'])
            self.assertEqual(host.nft, {'nftables': [{'foreign': True}]})
            host.nft = None
            self.assertTrue(hook.execute('block', 'vps', 1)['ok'])
            host.nft['foreign'] = True
            self.assertFalse(hook.execute('recover', 'vps', 2)['ok'])
            self.assertIn('foreign', host.nft)

    def test_persistent_boot_guard_survives_mode_recovery_and_is_reusable(self):
        with tempfile.TemporaryDirectory() as d:
            host, hook = self.setup_hook(d)
            hook.c.update(guard_state=str(Path(d) / 'guard.json'), retain_blocked_guard=True)
            self.assertTrue(hook.execute('block', 'vps', 1)['ok'])
            self.assertTrue(hook.execute('activate', 'vps', 1)['ok'])
            self.assertTrue(hook.execute('recover', 'vps', 2)['ok'])
            self.assertIsNotNone(host.nft)
            self.assertIsNone(hook.owner())
            self.assertTrue(Path(hook.c['guard_state']).exists())
            self.assertNotIn('ip saddr', host.nft['nftables'][0]['transaction'])
            self.assertTrue(hook.execute('preflight', 'vps', 3)['ok'])
            self.assertTrue(hook.execute('block', 'vps', 3)['ok'])


    def test_digest_ignores_handles_but_not_policy_changes(self):
        self.assertEqual(digest({'nftables': [{'metainfo': {'x': 1}}, {'handle': 2, 'rule': 3}]}),
                         digest({'nftables': [{'handle': 4, 'rule': 3}]}))
        self.assertNotEqual(digest({'rule': 'accept'}), digest({'rule': 'drop'}))

    def test_mac_ipv6_block_is_scoped_to_owned_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            spec = tailnet_spec()
            fake = FakeMac(spec)
            mac = MacNetwork({'network': spec}, fake)
            mac.guard({'epoch': 1}, Path(d) / 'state', 'utun3')
            body = next(data for args, data, _ in fake.calls if args[-2:] == ['-f', '-'])
            self.assertIn('on ! utun3 inet6 to <frog_corp6>', body)
            self.assertTrue(mac.anchor_is_ours())

    def test_native_mode_is_not_silently_accepted_with_exit_node(self):
        with tempfile.TemporaryDirectory() as d:
            c = {'network': tailnet_spec(), 'resolver_dir': d, 'pf_policy_verified': True,
                 'dns_fail_closed_verified': True, 'ipv6_policy_verified': True}
            mac = MacNetwork(c, FakeMac(c['network']))
            with self.assertRaisesRegex(RuntimeError, 'exit_node_withdrawal'):
                mac.preflight('mac', {})


if __name__ == '__main__':
    unittest.main()
