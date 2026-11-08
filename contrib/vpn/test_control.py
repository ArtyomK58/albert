import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from broker import Broker
from mac_agent import Controller
from targets import Targets, validate_credentials
from enrollment import start_web
from auth_failure import auth_failure_code


class Store:
    def __init__(self):
        self.value = {'username': 'test-user', 'password': 'test-secret'}

    def load(self):
        return dict(self.value) if self.value else None

    def save(self, value):
        self.value = validate_credentials(value)


class FakeTargets:
    def __init__(self):
        self.calls = []
        self.gate = threading.Event()
        self.gate.set()

    def vps_status(self):
        return {'ok': True, 'state': 'connected'}

    def vps_login(self, credentials, force, on_pending=None):
        self.calls.append(('vps', force))
        self.gate.wait(2)
        return {'ok': True, 'state': 'connected', 'changed': True}

    def mac(self, action, credentials=None, request_id=None):
        if action != 'status':
            self.calls.append(('mac', action))
        return {'ok': True, 'state': 'connected', 'changed': action != 'status'}


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.targets = FakeTargets()
        self.store = Store()
        self.config = {'owner_id': 7, 'state_file': self.tmp.name + '/state.json',
                       'public_url': 'https://vpn.example.com', 'session_seconds': 43200,
                       'warning_seconds': 1800, 'telegram_token_env': 'UNSET_TEST_TOKEN'}
        self.config.update(verification_delay_seconds=0,simultaneous_verified=True)
        self.broker = Broker(self.config, self.targets, self.store)
        self.notifications = []
        self.broker.notify = lambda text, setup_url=None: self.notifications.append((text, setup_url)) or True

    def tearDown(self):
        self.targets.gate.set()
        self.tmp.cleanup()

    def request(self, ident='request-one', actor=7):
        return {'actor': actor, 'action': 'reconnect', 'request_id': ident}

    def wait_job(self):
        limit = time.monotonic() + 3
        while self.broker.lock.locked() and time.monotonic() < limit:
            time.sleep(.01)
        self.assertFalse(self.broker.lock.locked())

    def test_non_owner_cannot_start_or_request_credential_links(self):
        self.assertFalse(self.broker.handle(self.request(actor=8))['ok'])
        self.assertFalse(self.broker.handle({'actor': 8, 'action': 'setup'})['ok'])
        self.assertEqual(self.targets.calls, [])
        self.assertEqual(self.notifications, [])

    def test_single_flight_and_replayed_message_do_not_repeat_mfa(self):
        self.targets.gate.clear()
        self.assertTrue(self.broker.handle(self.request())['ok'])
        self.broker.handle(self.request())
        self.broker.handle(self.request('request-two'))
        self.targets.gate.set()
        self.wait_job()
        self.assertEqual(self.targets.calls, [('vps', True), ('mac', 'reconnect')])
        self.assertEqual(self.broker.state['requests']['request-one']['state'], 'done')
        self.assertNotIn('test-secret', Path(self.config['state_file']).read_text())
        self.assertNotIn('test-secret', json.dumps(self.notifications))

    def test_credentials_required_prevents_any_connection(self):
        self.store.value = None
        self.assertFalse(self.broker.handle(self.request())['ok'])
        self.assertEqual(self.targets.calls, [])

    def test_incident_maintenance_blocks_actions_and_alerts(self):
        self.config['maintenance']=True
        self.assertFalse(self.broker.handle(self.request())['ok'])
        self.broker.state['sessions']['mac']={'started_at':0,'warned':False}
        self.broker.tick()
        self.assertEqual(self.targets.calls,[])
        self.assertEqual(self.notifications,[])

    def test_unverified_simultaneous_sessions_never_start(self):
        self.config['simultaneous_verified']=False
        self.assertFalse(self.broker.handle(self.request())['ok'])
        self.assertEqual(self.targets.calls,[])

    def test_connect_does_not_chase_a_peer_dropped_by_the_first_login(self):
        class Conflict(FakeTargets):
            def vps_status(self):return {'ok':True,'state':'connected' if self.calls else 'disconnected'}
            def vps_login(self,credentials,force,on_pending=None):
                self.calls.append(('vps',force));return {'ok':True,'state':'connected','changed':True}
            def mac(self,action,credentials=None,request_id=None):
                if action!='status':self.calls.append(('mac',action))
                return {'ok':True,'state':'disconnected' if self.calls else 'connected'}
        target=Conflict();self.broker.targets=target
        request=self.request();request['action']='connect'
        self.broker.handle(request);self.wait_job()
        self.assertEqual(target.calls,[('vps',False)])

    def test_one_time_enrollment_expires_and_is_consumed_only_after_save(self):
        self.broker.setup()
        token = self.notifications[-1][1].split('#')[1]
        self.assertTrue(self.broker.enrollment_valid(token))
        self.assertNotIn(token, self.broker.handle({'actor': 7, 'action': 'status'})['text'])
        self.broker.enroll(token, {'username': 'fixture', 'password': 'fixture-password'})
        self.assertFalse(self.broker.enrollment_valid(token))
        with self.assertRaises(ValueError):
            self.broker.enroll(token, {'username': 'fixture', 'password': 'fixture-password'})
        self.broker.setup()
        token = self.notifications[-1][1].split('#')[1]
        self.broker.enrollment = (self.broker.enrollment[0], time.time() - 1)
        self.assertFalse(self.broker.enrollment_valid(token))

    def test_warning_is_once_per_session_and_does_not_start_authentication(self):
        self.broker.state['sessions']['mac'] = {'started_at': time.time()-42000, 'warned': False}
        self.broker.tick()
        self.broker.tick()
        self.assertEqual(len(self.notifications), 1)
        self.assertEqual(self.targets.calls, [])

    def test_crash_does_not_replay_running_authentication(self):
        self.broker.state['requests']['request-one'] = {'state': 'running'}
        self.broker.persist()
        other = Broker(self.config, self.targets, self.store)
        self.assertEqual(other.state['requests']['request-one']['state'], 'outcome_unknown')
        other.handle(self.request())
        self.assertEqual(self.targets.calls, [])

    def test_credentials_reject_terminal_injection_and_missing_values(self):
        for value in [{}, {'username': 'user\nother', 'password': 'x'},
                      {'username': 'user', 'password': 'x\rcommand'},
                      {'username': 'user', 'password': ''}]:
            with self.assertRaises(ValueError): validate_credentials(value)

    def test_target_subset_does_not_restart_the_other_device(self):
        request=self.request();request['targets']=['vps']
        self.broker.handle(request);self.wait_job()
        self.assertEqual(self.targets.calls,[('vps',True)])

    def test_second_login_cannot_hide_a_dropped_first_connection(self):
        class Dropped(FakeTargets):
            def vps_status(self):
                return {'ok': True, 'state': 'disconnected' if any(c[0]=='mac' for c in self.calls) else 'connected'}
        self.broker.targets = Dropped()
        self.broker.handle(self.request())
        self.wait_job()
        result = self.broker.state['requests']['request-one']['results']['vps']
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'connection_not_retained')
        self.assertNotIn('vps', self.broker.state['sessions'])


class TerminalTests(unittest.TestCase):
    def test_instruction_mentions_success_before_credentials_and_must_not_end_login(self):
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/'supervisor'
            script.write_text('''#!/usr/bin/env python3
import sys
from pathlib import Path
flag=Path(__file__).with_name('connected')
if sys.argv[1]=='stop':
    if flag.exists():flag.unlink()
elif sys.argv[1]=='status':
    print('OK state=up owned=yes tcp=estab' if flag.exists() else 'OK state=down owned=no tcp=none')
else:
    print('After Initialization Sequence Completed, this terminal may close.',flush=True)
    user=input('Enter Auth Username:')
    password=input('Enter Auth Password:')
    if user=='fixture-user' and password=='fixture-password':
        print('AUTH_PENDING',flush=True)
        flag.touch()
        print('Initialization Sequence Completed',flush=True)
''')
            script.chmod(0o700)
            result=Targets({'vps_command':str(script),'auth_timeout_seconds':3}).vps_login(
                {'username':'fixture-user','password':'fixture-password'},True)
            self.assertTrue(result['ok'])
            self.assertTrue(result['mfa_observed'])

    def test_authentication_reason_tags_never_include_response_or_credentials(self):
        samples=[(b'AUTH_FAILED,Maximum concurrent sessions exceeded','auth-session-limit'),
                 (b'AUTH_FAILED,Username/password verification failed fixture-secret','auth-credentials-rejected'),
                 (b'AUTH_FAILED,MFA timed out','auth-mfa-timeout'),
                 (b'AUTH_FAILED,Data channel cipher negotiation failed','auth-cipher-negotiation'),
                 (b'AUTH_FAILED,opaque token fixture-secret','auth-failure')]
        for line,expected in samples:
            self.assertEqual(auth_failure_code(line),expected)


class MacTests(unittest.TestCase):
    def test_local_maintenance_never_mutates_the_native_client(self):
        with tempfile.TemporaryDirectory() as folder:
            controller=Controller({'state_file':folder+'/state.json','maintenance':True})
            with patch('mac_agent.subprocess.run') as run:
                self.assertEqual(controller.execute({'action':'reconnect'})['code'],'maintenance')
                run.assert_not_called()

    def test_os_tunnel_does_not_hide_reconnecting_vpn_transport(self):
        with tempfile.TemporaryDirectory() as folder:
            log=Path(folder)/'core.log'
            log.write_text('EVENT: CONNECTED\nSession token: fixture-secret\nEVENT: TRANSPORT_ERROR\nEVENT: RECONNECTING\n')
            controller=Controller({'state_file':folder+'/state.json','network_binary':'/unused',
                                   'service_id':'fixture','core_log_file':str(log)})
            with patch('mac_agent.subprocess.run') as run:
                run.return_value.stdout='{"ok":true,"state":"connected"}'
                result=controller.execute({'action':'status'})
                self.assertEqual(result['state'],'connecting')
                self.assertNotIn('fixture-secret',json.dumps(result))
    def test_changed_saved_credentials_are_refused_before_disconnect(self):
        with tempfile.TemporaryDirectory() as folder:
            controller=Controller({'state_file':folder+'/state.json','network_binary':'/unused',
                                   'service_id':'fixture','use_saved_credentials':True,
                                   'token':'fixture-control-token','credentials_digest':'previous'})
            with patch('mac_agent.subprocess.run') as run:
                result=controller.execute({'action':'reconnect','request_id':'fixture-rotation',
                                           'username':'fixture','password':'fixture-secret'})
                self.assertEqual(result['code'],'native_credential_update_required')
                run.assert_not_called()

    def test_credentials_travel_only_on_stdin_and_are_absent_from_response(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller({'state_file': folder+'/state.json', 'network_binary': '/unused',
                                     'service_id': 'fixture'})
            with patch('mac_agent.subprocess.run') as run:
                run.return_value.stdout = '{"ok":true,"state":"connected","changed":true}'
                result = controller.execute({'action':'reconnect','request_id':'fixture-store-request',
                                             'username':'fixture','password':'fixture-secret'})
                self.assertTrue(result['ok'])
                self.assertEqual(run.call_count,1)
                self.assertNotIn('fixture-secret',str(run.call_args.args))
                self.assertNotIn('fixture-secret',json.dumps(result))
                self.assertIn('fixture-secret',run.call_args.kwargs['input'])

    def test_unknown_outcome_is_persisted_before_dispatch_and_never_repeated(self):
        with tempfile.TemporaryDirectory() as folder:
            controller = Controller({'state_file': folder+'/state.json',
                                     'network_binary': '/unused', 'service_id': 'fixture'})
            request = {'action': 'reconnect', 'request_id': 'fixture-request'}
            with patch('mac_agent.subprocess.run', side_effect=OSError):
                controller.execute(request)
            self.assertEqual(controller.execute(request)['code'], 'outcome_unknown')
            restarted = Controller(controller.config)
            with patch('mac_agent.subprocess.run') as run:
                self.assertEqual(restarted.execute(request)['code'], 'outcome_unknown')
                run.assert_not_called()


class WebTests(unittest.TestCase):
    def setUp(self):
        BrokerTests.setUp(self)
        self.config['web_port'] = 0
        self.server = start_web(self.config, self.broker)
        self.base = 'http://127.0.0.1:' + str(self.server.server_address[1])
        self.broker.setup()
        self.token = self.notifications[-1][1].split('#')[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        BrokerTests.tearDown(self)

    def post(self, token, body, origin='https://vpn.example.com', path='/vpn/enroll'):
        request = Request(self.base + path, data=json.dumps(body).encode(),
                          headers={'Authorization': 'Bearer ' + token,
                                   'Origin': origin, 'Content-Type': 'application/json'})
        return urlopen(request, timeout=2)

    def test_web_rejects_wrong_capability_or_origin_without_saving(self):
        before = dict(self.store.value)
        for token, origin in [('wrong', 'https://vpn.example.com'), (self.token, 'https://other.example.com')]:
            with self.assertRaises(HTTPError) as error:
                self.post(token, {'username': 'other', 'password': 'other'}, origin)
            self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.store.value, before)

    def test_web_one_time_save_returns_no_credential_material(self):
        with self.post(self.token, {'username': 'fixture', 'password': 'fixture-secret'}) as response:
            body = response.read()
            self.assertEqual(json.loads(body), {'ok': True})
            self.assertNotIn(b'fixture-secret', body)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with self.assertRaises(HTTPError) as error:
            self.post(self.token, {'username': 'other', 'password': 'other'})
        self.assertEqual(error.exception.code, 403)

    def test_web_rejects_large_payload_and_serves_locked_page_without_token(self):
        with self.assertRaises(HTTPError) as error:
            self.post(self.token, {'username': 'x'*9000, 'password': 'x'})
        self.assertEqual(error.exception.code, 400)
        with urlopen(self.base+'/vpn/', timeout=2) as response:
            page = response.read()
            self.assertIn(b'fieldset disabled', page)
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])


if __name__ == '__main__':
    unittest.main()
