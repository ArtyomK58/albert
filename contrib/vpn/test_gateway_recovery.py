"""Recovery regressions on fully simulated hosts. No OS network command runs."""
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from broker import Broker
from gateway_fakes import World, retention_clock
from gateway_hook import NetworkHook
import modes


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.w = World(d.name)
        self.w.mac.native_routes = {p: self.w.mac.native for p in self.w.spec['corporate_prefixes']}
        self.host_before = self.w.host.snapshot()

    def assert_clean(self):
        w = self.w
        self.assertEqual(w.host.snapshot(), self.host_before)
        self.assertEqual(w.host.forbidden, [])
        self.assertEqual(w.mac.forbidden, [])
        self.assertEqual(w.mac.anchor, [])
        self.assertFalse(w.mac.tables)
        self.assertEqual(w.mac.routes, {})
        self.assertEqual(w.mac.pf_refs, {'other-owner'})
        self.assertFalse(Path(json.loads(w.hook_cfg.read_text())['resource_state']).exists())

    def switch_to_vps(self):
        with retention_clock():
            return self.w.modes().switch('vps', 'vpn:123456789:10')

    def test_happy_switch_then_recover_restores_both_hosts_without_login(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertEqual(w.mac.routes, {p: 'utun3' for p in w.spec['corporate_prefixes']})
        self.assertTrue(w.mac.corporate_blocked_on('en0'))
        self.assertTrue((Path(w.d) / 'resolver' / 'internal.example').exists())
        w.credentials.load.reset_mock()
        events = len(w.targets.events)
        result = w.modes().recover('vpn:123456789:11')
        self.assertTrue(result['ok'], result)
        self.assertEqual(w.targets.events[events:], ['recover'])  # no stop/start/login
        self.assertEqual(w.credentials.load.call_count, 0)
        self.assertEqual(w.phase(), 'recovered')
        self.assertFalse((Path(w.d) / 'resolver' / 'internal.example').exists())
        self.assertIn('новой явной команде', result['text'])
        self.assert_clean()

    def test_failure_after_block_freezes_then_recover_restores_native_access_without_mfa(self):
        w = self.w
        w.targets.mode_start = Mock(return_value={'ok': False, 'state': 'unknown'})  # MFA timeout
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:20')['code'], 'outcome_unknown')
        self.assertTrue(w.mac.corporate_blocked_on(w.mac.native))  # fail-closed everywhere
        status = w.modes().status()
        self.assertIn('/vpn_recover', status['text'])
        self.assertEqual(w.modes().switch('mac', 'vpn:123456789:21')['code'], 'operator_reconciliation_required')
        # The user brings the native client back by hand; only the gateway block is in the way.
        w.mac.native_routes = {p: w.mac.native for p in w.spec['corporate_prefixes']}
        result = w.modes().recover('vpn:123456789:22')
        self.assertTrue(result['ok'], result)
        self.assertFalse(w.mac.corporate_blocked_on(w.mac.native))
        self.assertEqual(w.mac.native_routes, {p: w.mac.native for p in w.spec['corporate_prefixes']})
        self.assertEqual(w.targets.mode_start.call_count, 1)  # no second login
        self.assertEqual(w.credentials.load.call_count, 1)
        self.assert_clean()

    def test_hook_timeout_freezes_and_recover_withdraws(self):
        w = self.w
        w.targets.hook_override['activate'] = {'ok': False, 'code': 'network_hook_timeout'}
        self.assertEqual(self.switch_to_vps()['code'], 'outcome_unknown')
        self.assertEqual(w.phase(), 'outcome_unknown')
        self.assertTrue(w.modes().recover('vpn:123456789:31')['ok'])
        self.assert_clean()

    def test_recover_after_feature_disabled_removes_only_own_resources(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.disable_everywhere()
        self.assertEqual(w.hook('activate', 'vps')['code'], 'gateway_disabled')
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:41')['code'], 'gateway_disabled')
        self.assertTrue(w.modes().recover('vpn:123456789:42')['ok'])
        self.assert_clean()

    def test_disabled_without_own_state_creates_nothing_and_runs_nothing(self):
        w = self.w
        w.disable_everywhere()
        before = sorted(p.name for p in Path(w.d).iterdir())
        result = w.modes().recover('vpn:123456789:50')
        self.assertEqual(result['code'], 'nothing_to_recover')
        self.assertEqual(w.targets.events, [])
        hook = w.hook('recover', 'mac')
        self.assertEqual(hook['code'], 'nothing_owned')
        out = w.mac_link(['mac-link', '/operator/run', '--phase', 'recover', '--target', 'mac', '--epoch', '1'], 10)
        self.assertEqual(json.loads(json.loads(out.stdout)['result']['stdout'])['code'], 'nothing_owned')
        self.assertEqual(w.host.calls + w.mac.calls, [])
        self.assertEqual(sorted(p.name for p in Path(w.d).iterdir()), before)

    def test_foreign_changes_are_kept(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        h, s = w.host, w.spec
        resolver = Path(w.d) / 'resolver' / 'internal.example'
        resolver.write_text('nameserver 192.0.2.53\n')              # edited by another owner
        foreign_rule = {'priority': s['rule_priority'], 'src': '10.9.0.0', 'srclen': 24, 'dst': '10.60.0.0',
                        'dstlen': 16, 'iif': s['host_bridge'], 'table': str(s['table'])}
        h.rules.append(foreign_rule)
        foreign_route = {'dst': '192.168.55.0/24', 'gateway': '192.0.2.9', 'dev': 'eth0', 'table': str(s['table'])}
        h.routes['host'].append(foreign_route)
        w.mac.native_routes['10.200.0.0/16'] = w.mac.native
        result = w.modes().recover('vpn:123456789:60')
        self.assertTrue(result['ok'], result)
        self.assertIn('Чужие изменения сохранены', result['text'])
        self.assertEqual(resolver.read_text(), 'nameserver 192.0.2.53\n')
        self.assertIn(foreign_rule, h.rules)
        self.assertIn(foreign_route, h.routes['host'])
        self.assertIn('10.200.0.0/16', w.mac.native_routes)
        self.assertEqual(w.mac.anchor, [])
        self.assertEqual(h.forbidden + w.mac.forbidden, [])

    def test_foreign_return_route_is_neither_replaced_nor_deleted(self):
        w = self.w
        s = w.spec
        foreign = {'dst': '10.9.0.2', 'gateway': '198.51.100.99', 'dev': s['host_bridge'], 'table': 'main'}
        w.host.routes['host'].append(foreign)
        self.assertEqual(self.switch_to_vps()['code'], 'network_preflight_failed')
        self.assertIn(foreign, w.host.routes['host'])
        # Appearing after ownership was established: activation refuses instead of replacing it.
        w.host.routes['host'].remove(foreign)
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertTrue(w.modes().recover('vpn:123456789:70')['ok'])
        w.host.routes['host'].append(foreign)
        w.mode_state.unlink()
        self.host_before = w.host.snapshot()
        hook = NetworkHook(json.loads(w.hook_cfg.read_text()), w.host)
        hook.record(return_route=False)
        self.assertFalse(hook.execute('activate', 'vps', 9)['ok'])
        self.assertIn(foreign, w.host.routes['host'])

    def test_mac_unreachable_keeps_peer_blocked_and_recovery_can_be_retried(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.mac_down = True
        result = w.modes().recover('vpn:123456789:80')
        self.assertEqual(result['code'], 'recovery_incomplete')
        self.assertEqual(w.phase(), 'recovery_incomplete')
        host_rules = w.host.chains[('host', 'filter', 'FROG_CG_HOST')]
        self.assertFalse(any('--mac-source' in r for r in host_rules))   # peer no longer exposed
        self.assertIn('FROG_CG_HOST', w.host.jumps[('host', 'filter', 'DOCKER-USER')])
        self.assertEqual(w.modes().switch('vps', 'vpn:123456789:81')['code'], 'operator_reconciliation_required')
        w.mac_down = False
        self.assertTrue(w.modes().recover('vpn:123456789:82')['ok'])
        self.assert_clean()

    def test_recreated_namespace_and_restarted_container_are_left_alone(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        w.host.sysctl['ns'] = {'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.rp_filter': '0'}  # new namespace
        for key in list(w.host.chains):
            if key[0] in ('ns', 'container'):
                del w.host.chains[key]
        for key in w.host.jumps:
            if key[0] in ('ns', 'container'):
                w.host.jumps[key] = [j for j in w.host.jumps[key] if not j.startswith('FROG_CG_')]
        w.host.routes['ns'] = [r for r in w.host.routes['ns'] if r['dst'] == 'default']
        self.assertTrue(w.modes().recover('vpn:123456789:90')['ok'])
        self.assert_clean()

    def test_recovery_epoch_fences_a_delayed_apply(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        old = json.loads(w.mode_state.read_text())['epoch']
        self.assertTrue(w.modes().recover('vpn:123456789:95')['ok'])
        out = w.mac_link(['mac-link', '/operator/run', '--phase', 'activate', '--target', 'vps', '--epoch', str(old)], 10)
        self.assertEqual(json.loads(json.loads(out.stdout)['result']['stdout'])['code'], 'stale_mode_epoch')
        self.assertEqual(w.mac.anchor, [])

    def test_recover_never_issues_broad_or_shared_operations(self):
        w = self.w
        self.assertTrue(self.switch_to_vps()['ok'])
        self.assertTrue(w.modes().recover('vpn:123456789:96')['ok'])
        for args, _, _ in w.host.calls:
            if args[:3] == ['ip', 'rule', 'del']:
                self.assertIn('from', args)
                self.assertIn('to', args)
            if any(x.startswith('net.ipv4.ip_forward=') for x in args):
                self.assertEqual(args[:3], ['ip', 'netns', 'exec'])  # namespace-local only
        for args, _, _ in w.mac.calls:
            self.assertNotIn('-d', args)
            self.assertNotIn('all', args)
        self.assertEqual(w.host.forbidden + w.mac.forbidden, [])

    def test_broker_recover_is_owner_only_and_never_loads_credentials(self):
        w = self.w
        with tempfile.TemporaryDirectory() as d:
            cfg = dict(w.config, credential_file='unused', state_file=str(Path(d) / 'b.json'), maintenance=True)
            cfg['gateway_option'] = dict(cfg['gateway_option'], enabled=False, prepare_only=True)
            credentials = Mock()
            broker = Broker(cfg, w.targets, credentials)
            self.assertFalse(broker.handle({'actor': '2', 'action': 'mode_recover', 'request_id': 'vpn:2:12345'})['ok'])
            with patch('threading.Thread', side_effect=AssertionError('no worker without state')):
                result = broker.handle({'actor': '1', 'action': 'mode_recover', 'request_id': 'vpn:1:12345'})
            self.assertEqual(result['code'], 'nothing_to_recover')
            self.assertEqual(credentials.mock_calls, [])
            self.assertFalse(Path(cfg['gateway_option']['state_file']).exists())




class FollowUpTests(unittest.TestCase):
    """Re-apply after recovery, ambiguous kernel rules and unreadable state."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.w = World(d.name)
        self.w.mac.native_routes = {p: self.w.mac.native for p in self.w.spec['corporate_prefixes']}

    def switch(self, target, ident, force=False):
        with retention_clock():
            return self.w.modes().switch(target, ident, force)

    def candidate(self, **extra):
        s = self.w.spec
        dst = ipaddress.ip_network(s['corporate_prefixes'][0])
        return dict({'priority': s['rule_priority'], 'src': str(ipaddress.ip_network(s['mac_peer']).network_address),
                     'dst': str(dst.network_address), 'dstlen': dst.prefixlen, 'iif': s['host_bridge'],
                     'table': str(s['table'])}, **extra)

    def own_rules(self):
        return [x for x in self.w.host.rules if x.get('priority') == self.w.spec['rule_priority']]

    # N1: configured is not active; an explicit command re-applies the network without a login.
    def test_status_after_recover_is_truthful_and_explicit_command_reapplies_without_login(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:100')['ok'])
        self.assertTrue(w.modes().status()['gateway']['active'])
        self.assertTrue(w.modes().recover('vpn:123456789:101')['ok'])
        status = w.modes().status()
        self.assertFalse(status['gateway']['active'])
        self.assertIn('не применена', status['text'])
        self.assertNotIn('/vpn_recover', status['text'])
        loads, epoch = w.credentials.load.call_count, json.loads(w.mode_state.read_text())['epoch']
        w.targets.mode_start, w.targets.mode_stop = Mock(), Mock()
        events = len(w.targets.events)
        result = self.switch('vps', 'vpn:123456789:102')
        self.assertEqual(result['code'], 'network_restored', result)
        self.assertIn('MFA не выполнялись', result['text'])
        self.assertEqual([e for e in w.targets.events[events:] if e != 'snapshot'], ['preflight', 'block', 'activate', 'verify'])
        self.assertEqual(w.targets.mode_start.call_count + w.targets.mode_stop.call_count, 0)
        self.assertEqual(w.credentials.load.call_count, loads)
        self.assertGreater(json.loads(w.mode_state.read_text())['epoch'], epoch)
        self.assertEqual(w.mac.routes, {p: 'utun3' for p in w.spec['corporate_prefixes']})
        self.assertTrue(any('--mac-source' in r for r in w.host.chains[('host', 'filter', 'FROG_CG_HOST')]))
        self.assertTrue(w.modes().status()['gateway']['active'])
        events = len(w.targets.events)
        self.assertEqual(self.switch('vps', 'vpn:123456789:103')['code'], 'already_connected')
        self.assertEqual([e for e in w.targets.events[events:] if e != 'snapshot'], ['verify'])
        self.assertEqual(self.switch('vps', 'vpn:123456789:102')['code'], 'already_seen')

    def test_reapply_freezes_if_the_session_drops_and_reconnect_stays_an_explicit_login(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:110')['ok'])
        self.assertTrue(w.modes().recover('vpn:123456789:111')['ok'])
        snapshots = iter([{'vps': {'ok': True, 'state': 'connected'}, 'mac': {'ok': True, 'state': 'disconnected'}},
                          {'vps': {'ok': True, 'state': 'disconnected'}, 'mac': {'ok': True, 'state': 'disconnected'}}])
        w.targets.mode_snapshot = lambda: next(snapshots)
        w.targets.mode_start = Mock()
        self.assertEqual(self.switch('vps', 'vpn:123456789:112')['code'], 'outcome_unknown')
        self.assertEqual(w.targets.mode_start.call_count, 0)
        self.assertEqual(w.phase(), 'outcome_unknown')
        self.assertTrue(w.modes().recover('vpn:123456789:113')['ok'])
        w.targets = type(w.targets)(w)  # fresh live view: vps connected, mac disconnected
        w.targets.states = {'mac': 'disconnected', 'vps': 'connected'}
        # Each load returns fresh credentials; a switch clears its copy in place.
        w.credentials.load.side_effect = lambda: {'username': 'synthetic-user', 'password': 'synthetic-password'}
        loads = w.credentials.load.call_count
        self.assertEqual(self.switch('vps', 'vpn:123456789:114', force=True)['code'], 'switched')
        self.assertIn('start_vps', w.targets.events)  # forced reauthentication remains explicit
        self.assertEqual(w.credentials.load.call_count, loads + 1)

    # N2: a delete request could match a foreign rule with extra selectors.
    def test_foreign_rule_appended_after_ours_is_never_deleted(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:120')['ok'])
        foreign = self.candidate(fwmark='0x7')
        w.host.rules.append(foreign)
        before = list(self.own_rules())
        result = w.modes().recover('vpn:123456789:121')
        self.assertEqual(result['code'], 'recovery_incomplete')
        self.assertIn('проверка оператором', result['text'])  # no circular retry advice
        self.assertEqual(self.own_rules(), before)  # nothing deleted at all
        self.assertIn('FROG_CG_HOST', w.host.jumps[('host', 'filter', 'DOCKER-USER')])
        w.host.rules.remove(foreign)  # operator reconciles the foreign rule
        self.assertTrue(w.modes().recover('vpn:123456789:122')['ok'])
        self.assertEqual(self.own_rules(), [])

    def test_foreign_rule_before_ours_blocks_reactivation_without_deleting(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:130')['ok'])
        ours = self.own_rules()[0]
        foreign = self.candidate(uidrange='1000-1000')
        w.host.rules.insert(w.host.rules.index(ours), foreign)  # foreign is first in kernel order
        self.assertFalse(w.hook('activate', 'vps')['ok'])
        self.assertEqual(self.own_rules(), [foreign, ours])
        self.assertFalse(any(c[0][:3] == ['ip', 'rule', 'del'] for c in w.host.calls))
        self.assertEqual(w.modes().recover('vpn:123456789:131')['code'], 'recovery_incomplete')
        self.assertIn(foreign, w.host.rules)
        self.assertIn(ours, w.host.rules)

    def test_recorded_kernel_default_attributes_and_differing_protocol(self):
        w = self.w
        w.host.rule_defaults = {'protocol': 'boot'}
        self.assertTrue(self.switch('vps', 'vpn:123456789:140')['ok'])
        self.assertTrue(w.hook('activate', 'vps')['ok'])  # re-activation keeps the recorded rule
        self.assertEqual(len(self.own_rules()), 1)
        self.assertFalse(any(c[0][:3] == ['ip', 'rule', 'del'] for c in w.host.calls))
        twin = self.candidate(protocol='static')  # same selectors, another owner's protocol
        w.host.rules.append(twin)
        self.assertEqual(w.modes().recover('vpn:123456789:141')['code'], 'recovery_incomplete')
        self.assertIn(twin, w.host.rules)
        w.host.rules.remove(twin)
        self.assertTrue(w.modes().recover('vpn:123456789:142')['ok'])
        self.assertEqual(self.own_rules(), [])

    # N3: unreadable state is reported, never rewritten, and never crashes the worker.
    def test_unreadable_state_is_operator_reconciliation_not_a_recover_promise(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:150')['ok'])
        for broken in ('{truncated', '[]', '{"epoch": "1", "requests": {}}'):
            w.mode_state.write_text(broken)
            w.targets.events.clear()
            loads = w.credentials.load.call_count
            status = w.modes().status()
            self.assertEqual(status['gateway']['phase'], 'unreadable')
            self.assertNotIn('/vpn_recover', status['text'])
            self.assertIn('оператор', status['text'])
            self.assertEqual(w.modes().recover('vpn:123456789:151')['code'], 'operator_reconciliation_required')
            self.assertEqual(self.switch('mac', 'vpn:123456789:152')['code'], 'operator_reconciliation_required')
            self.assertEqual(w.mode_state.read_text(), broken)
            self.assertEqual(w.targets.events, [])
            self.assertEqual(w.credentials.load.call_count, loads)

    def test_permission_error_on_state_is_handled(self):
        w = self.w
        self.assertTrue(self.switch('vps', 'vpn:123456789:160')['ok'])
        original = Path.read_text

        def read_text(path, *a, **k):
            if path == w.mode_state:
                raise PermissionError('denied')
            return original(path, *a, **k)
        with patch.object(Path, 'read_text', read_text):
            self.assertEqual(w.modes().status()['gateway']['phase'], 'unreadable')
            self.assertEqual(w.modes().recover('vpn:123456789:161')['code'], 'operator_reconciliation_required')
        self.assertEqual(w.targets.events[-1], 'verify')

    def test_broker_workers_always_notify_and_release_the_lock(self):
        w = self.w
        cfg = dict(w.config, credential_file='unused', state_file=str(Path(w.d) / 'broker.json'))
        broker = Broker(cfg, w.targets, Mock())
        broker.notify = Mock(return_value=True)
        self.assertTrue(self.switch('vps', 'vpn:123456789:170')['ok'])
        for action, method in (('mode_recover', 'recover'), ('mode_mac', 'switch')):
            with patch('threading.Thread') as thread, \
                    patch.object(modes.Modes, method, side_effect=RuntimeError('synthetic')):
                self.assertTrue(broker.handle({'actor': '1', 'action': action, 'request_id': 'vpn:1:171' + method})['ok'])
                thread.call_args.kwargs['target']()
            self.assertIn('внутренней ошибки', broker.notify.call_args.args[0])
            self.assertTrue(broker.lock.acquire(blocking=False))
            broker.lock.release()

if __name__ == '__main__':
    unittest.main()
