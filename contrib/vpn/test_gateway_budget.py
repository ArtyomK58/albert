"""Timeout hierarchy, epoch fencing and installer regressions. No OS network command runs."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import gateway_plan
from gateway_fakes import MAC_COMMAND, FakeHost, FakeMac, done
from gateway_hook import NetworkHook
from gateway_mac import MacNetwork
from gateway_plan import render
from install_gateway_mac import install
from mac_agent import Controller
from targets import Targets
from test_gateway import fixture


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
        # Contract: the client hint is the fixed neutral sentence, never a product name.
        self.assertEqual(render(fixture())['mac']['interface_selection'],
                         'find the configured personal VPN source address; never pin an utun number')



if __name__ == '__main__':
    unittest.main()
