import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from broker import Broker
from gateway_plan import render, validate
from mac_agent import Controller
from modes import Modes


def fixture():
    return {'version': 1, 'mac_peer': '10.9.0.2/32', 'corporate_prefixes': ['10.60.0.0/16'],
            'protected_prefixes': ['10.9.0.0/24', '172.31.77.0/24', '192.168.100.0/24'],
            'vps_endpoint': '203.0.113.1', 'corporate_endpoint': '203.0.113.2',
            'container_address': '198.51.100.3', 'host_link_address': '198.51.100.1',
            'namespace_link_address': '198.51.100.2', 'container': 'vpn_container',
            'container_mac': '02:00:00:00:00:01',
            'host_bridge': 'br_vpn', 'host_veth': 'veth_corp', 'namespace': 'corp_vpn',
            'namespace_veth': 'eth_peer', 'tunnel': 'tun0', 'ipv6_policy': 'deny',
            'table': 21000, 'rule_priority': 21000, 'tcp_mss': 1300,
            'corporate_dns': '10.60.0.53', 'dns_zones': ['internal.example']}


class FakeTargets:
    def __init__(self):
        self.states = {'mac': 'connected', 'vps': 'disconnected'}
        self.events = []
        self.stop_ok = True

    def mode_snapshot(self):
        self.events.append('snapshot')
        return {h: {'ok': True, 'state': s} for h, s in self.states.items()}

    def mode_hook(self, phase, target):
        self.events.append(phase)
        return {'ok': True}

    def mode_stop(self, host, ident, epoch):
        self.events.append('stop_' + host)
        if self.stop_ok:
            self.states[host] = 'disconnected'
        return {'ok': self.stop_ok}

    def mode_start(self, host, credentials, ident, epoch):
        self.events.append('start_' + host)
        self.states[host] = 'connected'
        return {'ok': True, 'state': 'connected'}


class GatewayTests(unittest.TestCase):
    def test_plan_is_inert_and_preserves_shared_networking(self):
        value = render(fixture())
        self.assertFalse(value['applied'])
        self.assertFalse(value['mac']['live_files_written'])
        for op in value['operations']:
            self.assertNotIn('-F', op['argv'])
            self.assertNotIn('default', op['argv'])
            if 'net.ipv4.ip_forward=1' in op['argv']:
                self.assertEqual(op['argv'][:3], ['ip', 'netns', 'exec'])
        self.assertTrue(any('unreachable' in op['argv'] for op in value['operations']))

    def test_routes_and_shell_like_values_are_rejected(self):
        for patch_value in [{'corporate_prefixes': ['0.0.0.0/0']},
                            {'corporate_prefixes': ['10.0.0.0/8']},
                            {'corporate_prefixes': ['172.31.77.0/24']},
                            {'corporate_prefixes': ['8.8.8.0/24']},
                            {'corporate_dns': '192.0.2.53'},
                            {'container': 'vpn;touch /tmp/x'},
                            {'dns_zones': ['../../resolver']},
                            {'ipv6_policy': 'allow'}]:
            value = fixture() | patch_value
            with self.subTest(value=patch_value), self.assertRaises(ValueError):
                validate(value)

    def test_disabled_mode_does_not_load_credentials_probe_or_write(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / 'never-created' / 'mode.json'
            targets, credentials = Mock(), Mock()
            c = {'owner_id': 'synthetic-owner', 'credential_file': 'unused',
                 'state_file': str(Path(d) / 'broker.json'), 'maintenance': True,
                 'gateway_option': {'enabled': False, 'prepare_only': True, 'state_file': str(state)}}
            broker = Broker(c, targets, credentials)
            for action in ['mode_vps', 'mode_mac']:
                result = broker.handle({'actor': 'synthetic-owner', 'action': action, 'request_id': 'synthetic:request'})
                self.assertEqual(result['code'], 'gateway_disabled')
            self.assertTrue(broker.handle({'actor': 'synthetic-owner', 'action': 'mode_status'})['ok'])
            self.assertEqual(targets.mock_calls, [])
            self.assertEqual(credentials.mock_calls, [])
            self.assertFalse(state.parent.exists())

    def test_one_flag_cannot_arm_mode(self):
        c = {'gateway_option': {'enabled': True, 'prepare_only': False, 'network_verified': False}}
        targets, credentials = Mock(), Mock()
        result = Modes(c, targets, credentials).switch('vps', 'synthetic:request')
        self.assertEqual(result['code'], 'gateway_disabled')
        self.assertEqual(targets.mock_calls + credentials.mock_calls, [])

    def enabled_config(self, d):
        return {'gateway_option': {'enabled': True, 'prepare_only': False, 'network_verified': True,
                                  'network_hook': ['/operator-owned-hook'], 'state_file': str(Path(d) / 'mode.json')}}

    def test_stop_confirm_start_then_network_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets()
            credentials = Mock()
            credentials.load.return_value = {'username': 'synthetic-user', 'password': 'synthetic-password'}
            with patch('modes.time.monotonic', side_effect=[0, 61]):
                result = Modes(self.enabled_config(d), targets, credentials).switch('vps', 'synthetic:request')
            self.assertTrue(result['ok'])
            self.assertLess(targets.events.index('stop_mac'), targets.events.index('start_vps'))
            self.assertEqual(targets.events[-2:], ['activate', 'verify'])
            self.assertEqual(json.loads((Path(d) / 'mode.json').read_text())['mode'], 'vps')

    def test_uncertain_stop_blocks_login_and_subsequent_replay(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets()
            targets.stop_ok = False
            credentials = Mock()
            credentials.load.return_value = {'username': 'synthetic-user', 'password': 'synthetic-password'}
            control = Modes(self.enabled_config(d), targets, credentials)
            self.assertEqual(control.switch('vps', 'synthetic:request')['code'], 'outcome_unknown')
            self.assertNotIn('start_vps', targets.events)
            self.assertEqual(control.switch('vps', 'different:request')['code'], 'operator_reconciliation_required')
            self.assertEqual(credentials.load.call_count, 1)

    def test_reconnect_on_current_owner_does_not_move_session_to_other_host(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets()
            credentials = Mock()
            credentials.load.return_value = {'username': 'synthetic-user', 'password': 'synthetic-password'}
            with patch('modes.time.monotonic', side_effect=[0, 61]):
                result = Modes(self.enabled_config(d), targets, credentials).switch('mac', 'synthetic:reconnect', True)
            self.assertTrue(result['ok'])
            self.assertIn('stop_mac', targets.events)
            self.assertIn('start_mac', targets.events)
            self.assertNotIn('start_vps', targets.events)

    def test_stale_mac_epoch_cannot_disconnect_newer_session(self):
        with tempfile.TemporaryDirectory() as d:
            c = {'state_file': str(Path(d) / 'mac.json'), 'network_binary': '/unused',
                 'service_id': 'synthetic-service', 'mode_epoch_required': True}
            control = Controller(c)
            with patch('mac_agent.subprocess.run', return_value=Mock(stdout='{"ok":true,"state":"disconnected"}')) as run:
                self.assertTrue(control.execute({'action': 'disconnect', 'request_id': 'synthetic:new', 'mode_epoch': 2})['ok'])
                self.assertEqual(control.execute({'action': 'disconnect', 'request_id': 'synthetic:old', 'mode_epoch': 1})['code'], 'stale_mode_epoch')
                self.assertEqual(control.execute({'action': 'connect', 'request_id': 'synthetic:plain'})['code'], 'mode_epoch_required')
                self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
