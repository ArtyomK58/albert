"""Local-egress routes and read-only checks on fully simulated hosts. No OS command runs."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gateway_mac
from gateway_fakes import World, retention_clock
from gateway_plan import validate
from gateway_restore import REPAIRABLE
from gateway_restore_mac import restore as restore_mac
import install_gateway_mac
from test_gateway import fixture

SITE = '198.51.100.64/32'


class EgressTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.w = World(d.name)
        self.w.spec.update(local_egress_prefixes=[SITE], local_egress_interface='en0')
        for cfg in (self.w.mac_cfg, self.w.hook_cfg):
            self.w.edit(cfg, network=self.w.spec)
        self.w.mac.native_routes = {p: self.w.mac.native for p in self.w.spec['corporate_prefixes']}

    def switch(self, ident, **kw):
        with retention_clock():
            return self.w.modes().switch('vps', ident, **kw)

    def ready(self):
        self.assertTrue(self.switch('vpn:123456789:10')['ok'])
        self.w.targets.states = {'vps': 'connected', 'mac': 'disconnected'}
        self.w.mac.native_routes = {}

    def test_validation_accepts_only_narrow_public_destinations(self):
        ok = dict(fixture(), local_egress_prefixes=[SITE], local_egress_interface='en0')
        validate(ok)
        for bad in (['0.0.0.0/0'], ['198.0.0.0/8'], ['10.60.1.0/24'], ['192.168.1.1/32'],
                    ['100.100.1.1/32'], ['203.0.113.1/32'], ['224.0.0.1/32']):
            with self.assertRaises(ValueError, msg=bad):
                validate(dict(ok, local_egress_prefixes=bad))
        with self.assertRaises(ValueError):
            validate(dict(ok, local_egress_interface='en0; true'))

    def egress(self):
        return self.w.helper('egress')

    def test_activation_routes_site_through_uplink_and_recovery_withdraws_it(self):
        w = self.w
        self.ready()
        self.assertEqual(w.mac.egress, {SITE: '192.0.2.1'})
        self.assertEqual(w.mac.routes, {p: 'utun3' for p in w.spec['corporate_prefixes']})
        self.assertEqual(self.switch('vpn:123456789:11')['code'], 'already_connected')
        self.assertEqual(self.egress()['code'], 'egress_synced')
        self.assertEqual(w.mac.egress, {SITE: '192.0.2.1'})
        self.assertTrue(w.modes().recover('vpn:123456789:12')['ok'])
        self.assertEqual(w.mac.egress, {})
        self.assertEqual(self.egress()['routes'], 0)
        self.assertEqual(w.mac.egress, {})
        self.assertEqual(w.mac.forbidden, [])

    def test_foreign_route_for_site_never_blocks_corporate_activation(self):
        w = self.w
        w.mac.foreign_egress = {SITE: '192.0.2.99'}
        self.ready()
        self.assertFalse(w.mac.corporate_blocked_on('utun3'))
        self.assertEqual(self.egress()['kept'], ['foreign_route'])
        self.assertEqual((w.mac.foreign_egress, w.mac.egress), ({SITE: '192.0.2.99'}, {}))
        self.assertEqual(w.mac.forbidden, [])

    def test_sync_follows_uplink_changes_without_touching_corporate_state(self):
        w = self.w
        self.ready()
        anchor, routes, events = list(w.mac.anchor), dict(w.mac.routes), len(w.mac.calls)
        w.mac.uplink = ('en0', '192.0.2.254')
        self.assertEqual(self.switch('vpn:123456789:30', repair_reasons=REPAIRABLE)['code'], 'already_connected')
        self.assertEqual(self.egress()['routes'], 1)
        self.assertEqual(w.mac.egress, {SITE: '192.0.2.254'})
        w.mac.uplink, w.mac.egress = None, {}  # The uplink went down with its routes.
        self.assertFalse(self.egress()['uplink'])
        self.assertEqual(w.mac.egress, {})
        self.assertEqual((w.mac.anchor, w.mac.routes), (anchor, routes))
        self.assertFalse(any('pfctl' in c[0][0] for c in w.mac.calls[events:]))

    def test_failed_verify_reports_reason_and_changes_nothing(self):
        w = self.w
        self.ready()
        anchor, chains = list(w.mac.anchor), w.host.snapshot()
        del w.mac.routes[w.spec['corporate_prefixes'][0]]
        result = w.hook('verify', 'vps')
        self.assertFalse(result['ok'])
        self.assertEqual(json.loads(w.hook_reply)['reason'], 'route_verification_failed')
        self.assertEqual(w.mac.anchor, anchor)
        self.assertFalse(w.mac.corporate_blocked_on('utun3'))
        self.assertEqual(w.host.snapshot(), chains)
        state = json.loads(Path(json.loads(w.mac_cfg.read_text())['state_file']).read_text())
        self.assertEqual(state['phase'], 'ready')

    def test_lost_routes_are_repaired_without_login(self):
        w = self.w
        self.ready()
        w.mac.routes, w.mac.egress, events = {}, {}, len(w.targets.events)
        result = self.switch('vpn:123456789:35', repair_reasons=REPAIRABLE)
        self.assertEqual(result['code'], 'network_restored', result)
        self.assertEqual(w.mac.egress, {SITE: '192.0.2.1'})
        self.assertFalse(any(e.startswith(('start_', 'stop_')) for e in w.targets.events[events:]))

    def test_unattended_restore_ignores_inconclusive_probe_failures(self):
        w = self.w
        self.ready()
        anchor, chains, events = list(w.mac.anchor), w.host.snapshot(), len(w.targets.events)

        def refused(address, timeout):
            raise OSError('synthetic refusal')
        init = gateway_mac.MacNetwork.__init__
        def failing(obj, *a, **kw):
            init(obj, *a, **kw)
            obj.connect = refused
        with patch.object(gateway_mac.MacNetwork, '__init__', failing):
            result = self.switch('vpn:123456789:40', repair_reasons=REPAIRABLE)
        self.assertEqual((result['code'], result['reason']), ('verify_inconclusive', 'probe_connect_failed'))
        self.assertEqual([e for e in w.targets.events[events:] if e != 'snapshot'], ['verify'])
        self.assertEqual(w.mac.anchor, anchor)
        self.assertEqual(w.host.snapshot(), chains)

    def test_preflight_failure_carries_its_reason(self):
        w = self.w
        self.ready()
        w.mac.personal = None
        del w.mac.routes[w.spec['corporate_prefixes'][0]]
        result = self.switch('vpn:123456789:50')
        self.assertEqual((result['code'], result['reason']), ('network_preflight_failed', 'personal_vpn_source_absent'))


class MacRestoreEgressTests(unittest.TestCase):
    def test_egress_sync_runs_every_time_and_survives_restore_failures(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / 'link'
            link.write_text(json.dumps({'tailnet_source': '100.70.80.90'}))
            c = {'link_config': str(link), 'restore_state': str(Path(d) / 'state'),
                 'restore_command': ['synthetic-restore'], 'egress_command': ['synthetic-egress']}
            calls = []

            def run(argv, **kw):
                calls.append(argv[0])
                if argv == ['/sbin/ifconfig']:
                    return subprocess.CompletedProcess(argv, 0, 'utun3: flags\n\tinet 100.70.80.90 --> x\n', '')
                if argv[0] == 'synthetic-restore':
                    raise subprocess.TimeoutExpired(argv, 1)
                if argv[0] == 'synthetic-egress':
                    return subprocess.CompletedProcess(argv, 0, '{"ok": true, "code": "egress_synced"}', '')
                return subprocess.CompletedProcess(argv, 0, 'boot-1', '')
            out = restore_mac(c, run)
            self.assertEqual((out['code'], out['egress']), ('network_restore_unconfirmed', 'egress_synced'))
            self.assertFalse(out['authentication_started'])
            Path(c['restore_state']).write_text(json.dumps({'boot': 'boot-1', 'interface': 'utun3'}))
            calls.clear()
            out = restore_mac(c, run)
            self.assertEqual((out['code'], out['egress']), ('generation_already_verified', 'egress_synced'))
            self.assertNotIn('synthetic-restore', calls)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root, self.data = Path(d.name) / 'root', Path(d.name) / 'data'
        self.root.mkdir()
        self.data.mkdir()
        (self.root / 'run').write_text(install_gateway_mac.PREVIOUS_LAUNCHER)
        for name in install_gateway_mac.MODULES:
            (self.root / name).write_text('# previous ' + name)
        self.config = {'enabled': True, 'prepare_only': False, 'network': fixture(), 'operator_key': 'kept'}
        (self.data / 'gateway.json').write_text(json.dumps(self.config))
        self.egress = Path(d.name) / 'egress.json'

    def test_upgrade_merges_only_egress_keys_and_rolls_back(self):
        self.egress.write_text(json.dumps({'local_egress_prefixes': [SITE], 'local_egress_interface': 'en0'}))
        out = install_gateway_mac.upgrade(str(self.egress), self.root, self.data)
        self.assertFalse(out['network_commands_executed'])
        merged = json.loads((self.data / 'gateway.json').read_text())
        self.assertEqual(merged['network']['local_egress_prefixes'], [SITE])
        self.assertEqual(merged['operator_key'], 'kept')
        self.assertIn('local_egress', (self.root / 'gateway_plan.py').read_text())
        self.assertIn('"egress"', (self.root / 'run').read_text())
        install_gateway_mac.rollback(self.root, self.data)
        self.assertEqual((self.root / 'run').read_text(), install_gateway_mac.PREVIOUS_LAUNCHER)
        self.assertEqual(json.loads((self.data / 'gateway.json').read_text()), self.config)
        self.assertEqual((self.root / 'gateway_mac.py').read_text(), '# previous gateway_mac.py')

    def test_upgrade_refuses_other_keys_invalid_prefixes_and_changed_launcher(self):
        for patch_value in ({'enabled': True}, {'local_egress_prefixes': ['10.60.0.0/24'], 'local_egress_interface': 'en0'}):
            self.egress.write_text(json.dumps(patch_value))
            with self.assertRaises((SystemExit, ValueError)):
                install_gateway_mac.upgrade(str(self.egress), self.root, self.data)
            self.assertEqual(json.loads((self.data / 'gateway.json').read_text()), self.config)
            self.assertEqual((self.root / 'gateway_mac.py').read_text(), '# previous gateway_mac.py')
        (self.root / 'run').write_text('#!/bin/sh\n')
        with self.assertRaises(SystemExit):
            install_gateway_mac.upgrade(None, self.root, self.data)


if __name__ == '__main__':
    unittest.main()
