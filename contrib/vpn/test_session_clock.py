import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from broker import Broker
from session_clock import process_session
from targets import Targets
from test_control import FakeTargets, Store


class SessionClockTests(unittest.TestCase):
    def fake_process(self, root):
        proc = root / 'proc';process = proc / '42';(process / 'ns').mkdir(parents=True)
        fields = ['S'] + ['0'] * 18 + ['500'] + ['0'] * 5
        (process / 'stat').write_text('42 (fixture process) ' + ' '.join(fields))
        (process / 'cmdline').write_bytes(b'/usr/bin/synthetic-vpn\0--opaque\0not-returned\0')
        (process / 'ns/net').write_text('synthetic namespace')
        ns = root / 'namespace';os.link(process / 'ns/net', ns)
        (proc / 'stat').write_text('cpu 0\nbtime 1000\n')
        pid = root / 'pid';pid.write_text('42');pid.chmod(0o600)
        return pid, ns, proc

    def test_uses_confirmed_owned_process_generation_not_old_broker_clock(self):
        with tempfile.TemporaryDirectory() as d:
            pid, ns, proc = self.fake_process(Path(d))
            result = process_session(pid, ns, '/usr/bin/synthetic-vpn', proc, 100)
            self.assertEqual(result, {'session_id': '42:500', 'session_started_at': 1005})
            self.assertNotIn('not-returned', json.dumps(result))

    def test_rejects_foreign_namespace_binary_and_writable_pidfile(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);pid, ns, proc = self.fake_process(root)
            foreign = root / 'foreign';foreign.write_text('foreign')
            self.assertEqual(process_session(pid, foreign, '/usr/bin/synthetic-vpn', proc, 100), {})
            self.assertEqual(process_session(pid, ns, '/usr/bin/other', proc, 100), {})
            pid.chmod(0o666)
            self.assertEqual(process_session(pid, ns, '/usr/bin/synthetic-vpn', proc, 100), {})

    def test_pending_auth_never_exposes_a_new_session_clock(self):
        with patch('targets.command', return_value=subprocess.CompletedProcess([], 0, 'state=waiting-auth owned=yes tcp=estab')):
            with patch('targets.process_session') as clock:
                result = Targets({'vps_command': 'synthetic-supervisor'}).vps_status()
                self.assertEqual(result['state'], 'disconnected')
                clock.assert_not_called()

    def test_status_and_warning_follow_new_generation_despite_route_failure(self):
        with tempfile.TemporaryDirectory() as d:
            targets = FakeTargets();targets.vps_status = lambda: {
                'ok': True, 'state': 'connected', 'session_id': 'new-generation', 'session_started_at': 49000}
            cfg = {'owner_id': 7, 'state_file': str(Path(d) / 'state'), 'session_seconds': 43200,
                   'warning_seconds': 3600, 'vps_session_pid_file': 'synthetic-pid'}
            broker = Broker(cfg, targets, Store());broker.notify = lambda *a: True
            broker.state['sessions'] = {'vps': {'started_at': 20000, 'warned': True, 'session_id': 'old-generation'}}
            with patch('broker.time.time', return_value=50000):
                result = broker.status()
                self.assertIn('11 ч 43 мин', result['text'])
                self.assertFalse(broker.state['sessions']['vps']['warned'])
                broker.state['sessions']['vps']['warned'] = True
                broker.status()
                self.assertTrue(broker.state['sessions']['vps']['warned'])
            self.assertEqual(broker.state['sessions']['vps']['started_at'], 49000)

    def test_unreadable_live_clock_never_displays_previous_session_remaining(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'owner_id': 7, 'state_file': str(Path(d) / 'state'), 'session_seconds': 43200,
                   'warning_seconds': 3600, 'vps_session_pid_file': 'synthetic-pid'}
            broker = Broker(cfg, FakeTargets(), Store())
            broker.state['sessions']['vps'] = {'started_at': 1000, 'warned': False}
            result = broker.status()
            self.assertIn('остаток сессии пока не определён', result['text'])


if __name__ == '__main__':
    unittest.main()
