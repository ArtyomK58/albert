import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from gateway_hook import NetworkHook
from gateway_mac import MacNetwork
from test_gateway import fixture


class NetworkTests(unittest.TestCase):
    def test_disabled_hooks_never_execute_or_create_state(self):
        for cls in (NetworkHook, MacNetwork):
            with self.subTest(cls=cls):
                run = Mock(side_effect=AssertionError('no OS command is allowed'))
                obj = cls({'enabled': False, 'prepare_only': True}, run)
                self.assertEqual(obj.execute('activate', 'vps', 1)['code'], 'gateway_disabled')
                self.assertEqual(run.mock_calls, [])

    def test_mac_failed_preflight_is_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            run = Mock(side_effect=AssertionError('no OS command expected before acceptance'))
            state = Path(d) / 'state.json'
            obj = MacNetwork({'enabled': True, 'prepare_only': False, 'network': fixture(), 'state_file': str(state)}, run)
            self.assertFalse(obj.execute('preflight', 'vps', 0)['ok'])
            self.assertFalse(state.exists())
            self.assertEqual(run.mock_calls, [])

    def test_mac_stale_epoch_never_touches_network(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / 'state.json'
            state.write_text(json.dumps({'epoch': 5, 'routes': {}, 'resolvers': {}}))
            run = Mock(side_effect=AssertionError('stale epoch must not execute'))
            obj = MacNetwork({'enabled': True, 'prepare_only': False, 'network': fixture(), 'state_file': str(state)}, run)
            self.assertEqual(obj.execute('block', 'mac', 4)['code'], 'stale_mode_epoch')
            self.assertEqual(json.loads(state.read_text())['epoch'], 5)

    def test_vps_exposes_peer_only_after_namespace_and_mac_are_ready(self):
        events = []
        def run(args, **kwargs):
            events.append(('command', args, kwargs.get('input')))
            return subprocess.CompletedProcess(args, 0, '', '')
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        obj = NetworkHook({'enabled': True, 'prepare_only': False, 'network': fixture(),
                           'resource_state': str(Path(d.name) / 'owner.json')}, run)
        obj.host_filter = lambda active, reserve=None: events.append(('host_access', active))
        obj.mac = lambda *args: events.append(('mac', args))
        self.assertTrue(obj.execute('activate', 'vps', 1)['ok'])
        self.assertEqual(events[0], ('host_access', False))
        self.assertEqual(events[-2:], [('mac', ('activate', 'vps', 1)), ('host_access', True)])
        for row in events:
            if row[0] == 'command' and 'net.ipv4.ip_forward=1' in row[1]:
                self.assertEqual(row[1][:3], ['ip', 'netns', 'exec'])

    def test_failed_activation_withdraws_host_access_without_retry(self):
        run = Mock(side_effect=RuntimeError('synthetic failure'))
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        obj = NetworkHook({'enabled': True, 'prepare_only': False, 'network': fixture(),
                           'resource_state': str(Path(d.name) / 'owner.json')}, run)
        obj.host_filter = Mock()
        obj.mac = Mock()
        self.assertFalse(obj.execute('activate', 'vps', 1)['ok'])
        self.assertTrue(all(call.args == (False,) for call in obj.host_filter.call_args_list))
        self.assertEqual(run.call_count, 1)
        self.assertEqual(obj.mac.call_count, 0)

    def test_blocking_peer_preserves_namespace_vpn_transport_replies(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        obj = NetworkHook({'network': fixture(), 'resource_state': str(Path(d.name) / 'owner.json')})
        obj.chain = Mock()
        obj.host_filter(False)
        rules = obj.chain.call_args.args[4]
        self.assertIn(fixture()['namespace_link_address'] + '/32', rules[0])
        self.assertIn('ESTABLISHED,RELATED -j ACCEPT', rules[0])
        self.assertEqual(rules[-1], '-o ' + fixture()['host_veth'] + ' -j REJECT')

    def test_pf_reference_is_retained_for_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            def run(args, **kwargs):
                text = 'Status: Disabled' if args[-2:] == ['-s', 'info'] else ''
                if args[-1] == '-E':
                    text = 'Token : 12345'
                self.assertNotIn('-d', args)
                return subprocess.CompletedProcess(args, 0, text, '')
            state = Path(d) / 'state.json'
            obj = MacNetwork({'network': fixture(), 'allow_pf_enable': True, 'state_file': str(state)}, run)
            value = {'epoch': 1, 'routes': {}, 'resolvers': {}}
            obj.guard(value, state)
            saved = json.loads(state.read_text())
            self.assertEqual(saved['pf_token'], '12345')
            self.assertTrue(saved['anchor_owned'])


if __name__ == '__main__':
    unittest.main()
