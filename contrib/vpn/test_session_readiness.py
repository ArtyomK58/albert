import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from broker import Broker
from modes import Modes
import test_control as control
from test_gateway import FakeTargets


class ReadinessTests(unittest.TestCase):
    def config(self, d):
        return {'gateway_option': {'enabled': True, 'prepare_only': False, 'network_verified': True,
                                  'network_hook': ['synthetic'], 'state_file': str(Path(d) / 'mode')}}

    def test_new_login_waits_for_dns_without_auth_or_route_retry(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets();phases = [];probes = []
            def hook(phase, target):
                phases.append(phase)
                if phase == 'verify':
                    probes.append(1)
                    return {'ok': True} if len(probes) == 3 else {'ok': False, 'reason': 'probe_resolution_failed'}
                return {'ok': True}
            targets.mode_hook = hook
            credentials = Mock();credentials.load.return_value = {'username': 'synthetic', 'password': 'synthetic'}
            with patch('modes.time.monotonic', side_effect=[0, 61]):
                out = Modes(self.config(d), targets, credentials, sleep=Mock()).switch('vps', 'synthetic:new:login')
            self.assertTrue(out['ok'])
            self.assertEqual(targets.events.count('start_vps'), 1)
            self.assertEqual(targets.events.count('stop_mac'), 1)
            self.assertEqual(phases.count('activate'), 1)
            self.assertEqual(phases.count('block'), 1)
            self.assertEqual(phases.count('verify'), 3)

    def test_exhausted_readiness_persists_failure_step_without_relogin(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets()
            targets.states = {'mac': 'disconnected', 'vps': 'connected'}
            targets.mode_hook = lambda phase, target: ({'ok': False, 'reason': 'probe_connect_failed'}
                                                       if phase == 'verify' else {'ok': True})
            c = self.config(d)
            out = Modes(c, targets, Mock(), sleep=Mock()).switch('vps', 'synthetic:existing:session')
            self.assertFalse(out['ok'])
            s = json.loads(Path(c['gateway_option']['state_file']).read_text())
            self.assertEqual(s['failure_step'], 'verifying_routes')
            self.assertEqual(s['network_reason'], 'probe_connect_failed')
            self.assertNotIn('start_vps', targets.events)
            self.assertNotIn('stop_vps', targets.events)

    def test_in_progress_status_does_not_claim_an_earlier_failure(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.config(d)
            Path(c['gateway_option']['state_file']).write_text(json.dumps({'epoch': 1, 'phase': 'switching', 'requests': {}}))
            result = Modes(c, Mock(), Mock()).status()
            self.assertIn('Переключение VPN выполняется', result['text'])
            self.assertNotIn('Предыдущее переключение', result['text'])


class BrokerFailureClockTests(unittest.TestCase):
    setUp = control.BrokerTests.setUp
    tearDown = control.BrokerTests.tearDown
    request = control.BrokerTests.request
    wait_job = control.BrokerTests.wait_job

    def test_failed_network_job_still_observes_confirmed_new_vpn_clock(self):
        started = time.time() - 10
        self.targets.vps_status = lambda: {'ok': True, 'state': 'connected',
                                         'session_id': 'new-confirmed-generation', 'session_started_at': started}
        self.broker.state['sessions'] = {'vps': {'started_at': started - 28000, 'warned': True}}
        with patch('broker.Modes') as modes:
            modes.return_value.switch.return_value = {'ok': False, 'code': 'outcome_unknown', 'text': 'synthetic route failure'}
            self.broker.start_mode(self.request(), 'vps')
            self.wait_job()
        self.assertEqual(self.broker.state['sessions']['vps']['started_at'], started)
        self.assertFalse(self.broker.state['sessions']['vps']['warned'])


if __name__ == '__main__':
    unittest.main()
