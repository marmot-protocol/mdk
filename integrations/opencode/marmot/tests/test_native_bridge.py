"""Native transport regressions with a deterministic model/HTTP boundary."""
import importlib.util
import io
from pathlib import Path
import queue
import threading
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('native_bridge', Path(__file__).parents[1] / 'src/native_bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

class Input:
    def __init__(self):
        self.buffer = self
        self.q = queue.Queue()
    def readline(self, limit):
        return self.q.get(timeout=5)
    def put(self, value):
        self.q.put((bridge.json.dumps(value) + '\n').encode())

class FakeServer:
    race = False
    ambiguous = False
    permission = False
    partial = False
    idle = False
    question = False
    large_history = False
    instances = []
    def __init__(self, binary):
        self.release = threading.Event()
        self.messages = []
        self.posts = []
        self.reads = 0
        self.history_reads = 0
        self.initial_timeout = "unset"
        self.closed = False
        self.instances.append(self)
    def call(self, method, path, body=None, timeout=10):
        if path == '/session': return {'id': 'ses_fixture'}
        if path == '/question': return [{'id':'que_fixture','sessionID':'ses_fixture'},{'id':'que_other','sessionID':'ses_other'}] if self.question else []
        if path == '/question/que_fixture/reject':
            self.posts.append({'reject_question':True})
            return True
        if path == '/permission': return [{'id':'per_fixture','sessionID':'ses_fixture'},{'id':'per_other','sessionID':'ses_other'}] if self.permission else []
        if path == '/permission/per_fixture/reply':
            self.posts.append(body)
            return True
        if method == 'POST':
            self.posts.append(body)
            message = {'info': {'id': body['messageID'], 'role': 'user'}, 'parts': body['parts']}
            self.messages.append(message)
            if body.get('noReply'):
                self.release.set()
                if self.ambiguous: raise TimeoutError('Response lost after persistence')
                return message
            self.initial_timeout=timeout
            if not self.idle: self.release.wait(5)
            parent = self.messages[0 if self.race else -1]['info']['id']
            self.messages.append({'info': {'id':'msg_answer','role':'assistant','parentID':parent,'time':{'completed':1},'finish':'stop'},'parts':[{'type':'reasoning','text':'PRIVATE_REASONING','time':{'end':1}},{'type':'text','text':'ANSWER','time':{'end':1}}]})
            return self.messages[-1]
        self.reads+=1
        if '/message?' in path:
            self.history_reads += 1
            if self.large_history:
                raise ValueError('Response too large: previous attachment batches')
        if '/message/' in path:
            mid = path.rsplit('/', 1)[-1]
            message = next((m for m in self.messages if m['info']['id'] == mid), None)
            if self.partial and self.reads < 3 and message:
                return {'info': message['info'], 'parts': []}
            return message
        if self.partial and self.reads<3 and self.messages:
            return [{'info':self.messages[0]['info'],'parts':[]}]
        return list(self.messages)
    def close(self):
        self.closed = True
        self.release.set()

class NativeTests(unittest.TestCase):
    def exercise(self, race=False, ambiguous=False, permission=False, partial=False, idle=False, question=False, failure=False, large_history=False):
        stdin = Input()
        stdin.put({'bin':'fixture','prompt':'FIRST','files':[]})
        stdin.put({'type':'steer','id':7,'prompt':'FOLLOWUP','files':[]})
        events=[]
        def emit(kind, **fields):
            events.append(dict(type=kind, **fields))
            if kind=='finishing':stdin.put({'type':'finish'})
        FakeServer.large_history=large_history
        FakeServer.race=race;FakeServer.ambiguous=ambiguous;FakeServer.permission=permission;FakeServer.partial=partial;FakeServer.idle=idle;FakeServer.question=question
        with patch.object(bridge,'Server',FakeServer), patch.object(bridge.sys,'stdin',stdin),patch.object(bridge,'emit',emit):
            if race or ambiguous or failure:
                with self.assertRaises(ValueError): bridge.run()
            else: bridge.run()
        return FakeServer.instances[-1],events
    def test_followup_persisted_before_completion_same_session(self):
        server, events=self.exercise()
        self.assertEqual([e for e in events if e['type']=='ack'],[{'type':'ack','id':7,'persisted':True}])
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
        self.assertEqual(len(server.posts),2)
        self.assertTrue(server.posts[1]['noReply'])
        self.assertTrue(server.closed)
        self.assertNotIn('PRIVATE_REASONING',str(events))
    def test_ambiguous_post_is_never_replayed(self):
        server, events=self.exercise(ambiguous=True)
        self.assertEqual(len(server.posts),2)
        self.assertEqual([e['persisted'] for e in events if e['type']=='ack'],[False])
        ack = next(i for i, e in enumerate(events) if e['type'] == 'ack')
        stopping = next(i for i, e in enumerate(events) if e['type'] == 'stopping')
        self.assertLess(ack, stopping, 'An attempted POST must stay uncertain before unsent controls are released')
        self.assertFalse(any(e['type']=='text' for e in events))
    def test_late_append_cannot_report_old_answer_as_success(self):
        server,events=self.exercise(race=True)
        self.assertEqual(len(server.posts),2)
        self.assertFalse(any(e['type']=='text' for e in events))
        self.assertTrue(server.closed)
    def test_autonomous_permission_answer_once_and_only_this_session(self):
        with patch.dict(bridge.os.environ, {'WN_OPENCODE_NATIVE_APPROVALS':'once'}):
            server,events=self.exercise(permission=True)
        self.assertEqual([p for p in server.posts if 'reply' in p],[{'reply':'once'}])
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
    def test_partial_initial_persistence_waits_and_lifetime_stays_with_runner(self):
        server,events=self.exercise(partial=True)
        self.assertGreaterEqual(server.reads,3)
        self.assertIsNone(server.initial_timeout)
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
    def test_completed_loop_declines_without_posting_followup(self):
        server,events=self.exercise(idle=True)
        self.assertEqual(len(server.posts),1)
        self.assertEqual([e for e in events if e['type']=='ack'],[{'type':'ack','id':7,'inactive':True}])
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
    def test_inherited_permission_fails_without_grant(self):
        with patch.dict(bridge.os.environ, {'WN_OPENCODE_NATIVE_APPROVALS':'inherit'}):
            server,events=self.exercise(permission=True,failure=True)
        self.assertFalse(any('reply' in p for p in server.posts))
        self.assertFalse(any(e['type']=='text' for e in events))
    def test_headless_question_rejected_once_for_this_session(self):
        server,events=self.exercise(question=True)
        self.assertEqual([p for p in server.posts if 'reject_question' in p],[{'reject_question':True}])
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
    def test_fast_completed_post_does_not_reject_partial_readback(self):
        server,events=self.exercise(partial=True,idle=True)
        self.assertGreaterEqual(server.reads,3)
        self.assertEqual([e['text'] for e in events if e['type']=='text'],['ANSWER'])
        self.assertEqual(len(server.posts),1)
    def test_resumed_turn_avoids_history_pages_with_previous_large_batches(self):
        # A history page containing two admitted batches exceeds one response
        # budget. Run the real turn route against that HTTP failure boundary.
        server, events = self.exercise(large_history=True)
        self.assertEqual([e['text'] for e in events if e['type'] == 'text'], ['ANSWER'])
        self.assertEqual(server.history_reads, 0)
        self.assertTrue(any(e['type'] == 'stopping' for e in events))

    def test_startup_error_closes_admission_before_error_event(self):
        import subprocess
        result = subprocess.run([bridge.sys.executable, str(Path(bridge.__file__))],
                                input=b'not-json\n', capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual([bridge.json.loads(line)['type'] for line in result.stdout.splitlines()],
                         ['stopping', 'error'])

    def test_message_ids_sort_in_generation_order(self):
        values=[bridge.message_id() for _ in range(200)]
        self.assertEqual(values,sorted(values))
        self.assertEqual(len(values),len(set(values)))
    def test_concurrent_servers_reserve_distinct_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            auth=Path(directory)/'password';auth.write_text('x'*40);auth.chmod(0o600)
            process=MagicMock();process.poll.return_value=None
            def stop(): process.poll.return_value=0
            process.terminate.side_effect=stop
            with patch.dict(bridge.os.environ, {'WN_OPENCODE_NATIVE_PASSWORD_FILE':str(auth)}),patch.object(bridge.subprocess,'Popen',return_value=process),patch.object(bridge.Server,'call',return_value={'healthy':True}),patch.object(bridge.socket,'socket') as sockets:
                sockets.return_value.__enter__.return_value.bind.return_value=None
                first=bridge.Server('fixture');second=bridge.Server('fixture')
                try:self.assertNotEqual(first.base,second.base)
                finally:first.close();second.close()
    def test_text_attachments_use_native_read_and_require_each_result(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'input.json';file.write_text('{"marker":42}')
            expected=bridge.parts('prompt',[str(file)])
            self.assertEqual(expected[1]['mime'],'text/plain')
            result={'info':{'id':'msg_fixture'},'parts':list(expected)}
            self.assertTrue(bridge.persisted_message(result,'msg_fixture','prompt',expected))
            result['parts']=expected[:1]
            self.assertFalse(bridge.persisted_message(result,'msg_fixture','prompt',expected))
            result['parts']=expected+[{'type':'text','synthetic':True,'text':'Read tool failed to read fixture'}]
            self.assertFalse(bridge.persisted_message(result,'msg_fixture','prompt',expected))
    def test_http_budget_accepts_inline_media_for_initial_readback_and_followup(self):
        # Exercise Server.call itself: FakeServer bypasses its response guard.
        server = bridge.Server.__new__(bridge.Server)
        server.child = MagicMock()
        server.child.poll.return_value = None
        server.base = 'http://127.0.0.1:700'
        server.headers = {}
        server.http = MagicMock()
        media = 'data:image/png;base64,' + bridge.base64.b64encode(b'x' * (4 * 1024 * 1024)).decode()
        message = {'info': {'id': 'msg_media'}, 'parts': [
            {'type': 'text', 'text': 'prompt'},
            {'type': 'file', 'filename': 'image.png', 'url': media}]}
        expected = [{'type': 'text', 'text': 'prompt'},
                    {'filename': 'image.png', 'url': 'file:///image.png'}]
        for method, path, body, result in [
            ('GET', '/session/ses_fixture/message/msg_media', None, message),
            ('POST', '/session/ses_fixture/message', {'noReply': True}, message),
        ]:
            with self.subTest(method=method):
                response = io.BytesIO(bridge.json.dumps(result).encode())
                server.http.open.return_value = response
                observed = server.call(method, path, body)
                self.assertTrue(bridge.persisted_message(observed, 'msg_media', 'prompt', expected))

    def test_http_budget_still_rejects_oversized_responses_without_retry(self):
        server = bridge.Server.__new__(bridge.Server)
        server.child = MagicMock()
        server.child.poll.return_value = None
        server.base = 'http://127.0.0.1:700'
        server.headers = {}
        server.http = MagicMock()
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'x' * 33
        server.http.open.return_value = response
        with patch.object(bridge, 'RESPONSE_LIMIT', 32):
            with self.assertRaisesRegex(ValueError, '^Response too large$'):
                server.call('POST', '/session/ses_fixture/message', {'noReply': True})
        response.read.assert_called_once_with(33)
        server.http.open.assert_called_once()

    def test_relative_attachment_rejected(self):
        with self.assertRaises(ValueError):bridge.parts('prompt',['relative.txt'])

if __name__=='__main__':unittest.main()
