import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from gateway_restore import NetworkOnlyTargets, restore
from gateway_restore_mac import restore as restore_mac
from modes import Modes
from test_gateway import FakeTargets


class RestoreTests(unittest.TestCase):
    def config(self, d):
        return {'gateway_option': {'enabled': True, 'prepare_only': False, 'network_verified': True,
                                  'network_hook': ['synthetic-hook'], 'state_file': str(Path(d) / 'mode')}}

    def test_ready_mode_with_lost_routes_restores_without_credentials_or_mfa(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.config(d)
            p = Path(c['gateway_option']['state_file'])
            p.write_text(json.dumps({'epoch': 3, 'requests': {}, 'phase': 'ready', 'mode': 'vps'}))
            targets = FakeTargets();targets.states = {'vps': 'connected', 'mac': 'disconnected'}
            checks = []
            def phase(name, target):
                checks.append(name)
                return {'ok': not (name == 'verify' and len(checks) == 1)}
            targets.mode_hook = phase
            credentials = Mock(side_effect=AssertionError('no credentials'))
            result = Modes(c, targets, credentials).switch('vps', 'synthetic:network:restore')
            self.assertEqual(result['code'], 'network_restored')
            self.assertEqual(checks, ['verify', 'preflight', 'block', 'activate', 'verify'])
            self.assertFalse(any(e.startswith(('start_', 'stop_')) for e in targets.events))
            self.assertEqual(credentials.mock_calls, [])

    def test_background_restore_requires_existing_vps_session(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets()
            out = restore(self.config(d), targets)
            self.assertEqual(out['code'], 'existing_vps_session_required')
            self.assertFalse(out['authentication_started'])
            self.assertEqual(targets.events, ['snapshot'])

    def test_background_target_can_never_start_or_stop_a_session(self):
        targets = NetworkOnlyTargets({})
        for method in (targets.mode_start, targets.mode_stop):
            with self.assertRaises(RuntimeError):
                method()

    def test_mac_restores_once_per_boot_interface_generation(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / 'link';link.write_text(json.dumps({'tailnet_source': '100.70.80.90'}))
            c = {'link_config': str(link), 'restore_state': str(Path(d) / 'state'),
                 'restore_command': ['ssh', 'example.invalid', 'synthetic-restore']}
            calls = []
            interface = ['utun3']
            def run(argv, **kw):
                calls.append(argv)
                if argv == ['/sbin/ifconfig']:
                    out = interface[0] + ': flags\n\tinet 100.70.80.90 --> peer\n'
                elif argv[0] == '/usr/sbin/sysctl':
                    out = 'synthetic-boot'
                else:
                    out = '{"ok":true,"code":"already_connected","authentication_started":false}'
                return subprocess.CompletedProcess(argv, 0, out, '')
            self.assertTrue(restore_mac(c, run)['ok'])
            self.assertEqual(restore_mac(c, run)['code'], 'generation_already_verified')
            self.assertEqual(calls.count(c['restore_command']), 1)
            interface[0] = 'utun4'
            self.assertTrue(restore_mac(c, run)['ok'])
            self.assertEqual(calls.count(c['restore_command']), 2)


if __name__ == '__main__':
    unittest.main()
