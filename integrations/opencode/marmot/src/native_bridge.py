"""Private JSONL adapter for a per-invocation OpenCode server, Python standard library only.
The enclosing Rust process owns timeouts, routing environment and process-group teardown.
Never resend a POST after an ambiguous result. Only completed assistant text is emitted.
"""
import base64
import fcntl
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 4 * 1024 * 1024
# JSONL carries file paths; HTTP readback can contain the whole admitted batch
# encoded as data URLs. Keep a separate bounded budget with base64 expansion
# and the existing 4 MiB allowance for JSON, text and message metadata.
ATTACHMENT_LIMIT = int(os.environ.get('WN_OPENCODE_MAX_ATTACHMENT_BYTES', str(64 * 1024 * 1024)))
RESPONSE_LIMIT = LIMIT + 4 * ((ATTACHMENT_LIMIT + 2) // 3)

def emit(kind, **fields):
    """Emit one bounded-protocol event for the enclosing Rust runner."""
    print(json.dumps(dict(type=kind, **fields), separators=(",", ":")), flush=True)

def message_id():
    """Generate unique IDs in the chronological order expected by OpenCode."""
    # Same chronological prefix as OpenCode Identifier.ascending; unique per bridge.
    global last_tick
    tick = max(int(time.time() * 1000) * 4096, last_tick + 1)
    last_tick = tick
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "msg_" + format(tick, "012x") + "".join(secrets.choice(alphabet) for _ in range(14))

last_tick = 0

def parts(prompt, files):
    """Reference staged absolute files for native Read processing."""
    result = [{"type": "text", "text": prompt}]
    for file in files:
        p = Path(file)
        if not p.is_absolute() or not p.is_file():
            raise ValueError("Invalid attachment")
        result.append({"type": "file", "mime": "text/plain", "url": p.as_uri(), "filename": p.name})
    return result

def persisted_message(result, mid, prompt, expected):
    """Require exact prompt and every attachment before acknowledging persistence."""
    if result.get('info', {}).get('id') != mid:
        return False
    actual = result.get('parts', [])
    if not any(p.get('type') == 'text' and not p.get('synthetic') and p.get('text') == prompt for p in actual):
        return False
    if any(p.get('synthetic') and p.get('text', '').startswith('Read tool failed to read ') for p in actual):
        return False
    # Native Read preserves a text file part, or replaces media with a data
    # attachment. Require evidence for every staged input, in addition to text.
    for file in expected[1:]:
        if not any(p.get('type') == 'file' and p.get('filename') == file['filename'] and (p.get('url') == file['url'] or p.get('url', '').startswith('data:')) for p in actual):
            return False
    return True

class Server:
    def __init__(self, binary):
        """Start one authenticated server on a protected, exclusively reserved port."""
        # Below the host's unprivileged threshold: another Unix user cannot take
        # the listener after server death and capture authenticated prompt traffic.
        threshold = int(Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text())
        low = int(os.environ.get('WN_OPENCODE_NATIVE_PORT_FIRST', '700'))
        high = int(os.environ.get('WN_OPENCODE_NATIVE_PORT_LAST', '799'))
        if not 1 <= low <= high < threshold or high - low > 255:
            raise ValueError('Native server requires protected ports')
        auth_path = Path(os.environ['WN_OPENCODE_NATIVE_PASSWORD_FILE'])
        fd = os.open(auth_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 4096:
                raise ValueError('Unsafe authentication file')
            password = os.read(fd, 4097).decode().strip()
        finally:
            os.close(fd)
        if len(password) < 32 or '\n' in password or '\r' in password:
            raise ValueError('Invalid authentication')
        username = os.environ.get('WN_OPENCODE_NATIVE_USERNAME', 'opencode')
        token = base64.b64encode((username + ':' + password).encode()).decode()
        self.headers = {'Authorization': 'Basic ' + token, 'Content-Type': 'application/json', 'x-opencode-directory': urllib.parse.quote(os.getcwd(), safe='')}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        lock_dir = auth_path.parent / 'native-listeners'
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        info = lock_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Unsafe listener lock directory')
        self.port_lock = None
        port = None
        for candidate in range(low, high + 1):
            fd = os.open(lock_dir / str(candidate), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                os.close(fd)
                raise ValueError('Unsafe listener lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', candidate))
                self.port_lock = fd
                port = candidate
                break
            except OSError:
                os.close(fd)
        if port is None:
            raise ValueError('No protected listener available')
        self.base = 'http://127.0.0.1:' + str(port)
        env = os.environ.copy()
        env['OPENCODE_SERVER_PASSWORD'] = password
        env['OPENCODE_SERVER_USERNAME'] = username
        self.child = subprocess.Popen([binary, 'serve', '--hostname', '127.0.0.1', '--port', str(port)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        deadline = time.monotonic() + 15
        while True:
            if self.child.poll() is not None:
                raise ValueError('Native server exited')
            try:
                self.call('GET', '/global/health', timeout=1)
                break
            except Exception:
                if time.monotonic() > deadline:
                    emit('stopping')
                    self.close()
                    raise
                time.sleep(.1)
    def call(self, method, path, body=None, timeout=10):
        """Make one HTTP attempt and decode a bounded response without retrying."""
        if self.child.poll() is not None:
            raise ValueError('Native server exited')
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=self.headers, method=method)
        with self.http.open(req, timeout=timeout) as response:
            raw = response.read(RESPONSE_LIMIT + 1)
            if len(raw) > RESPONSE_LIMIT:
                raise ValueError('Response too large')
            return json.loads(raw) if raw else None
    def close(self):
        """Stop the owned server before releasing its exclusive listener lock."""
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()
        if self.port_lock is not None:
            os.close(self.port_lock)
            self.port_lock = None

def run():
    """Persist ordered inputs and emit only a completed answer to the latest input."""
    # Unbuffered FileIO avoids a daemon holding Python buffered-stdin locks
    # during interpreter shutdown. Also avoids prefetching later JSONL frames.
    stream = getattr(sys.stdin.buffer, "raw", sys.stdin.buffer)
    initial = stream.readline(LIMIT + 1)
    if len(initial) > LIMIT:
        raise ValueError('Initial input too large')
    config = json.loads(initial)
    server = Server(config['bin'])
    try:
        session = config.get('session')
        if session:
            server.call('GET', '/session/' + urllib.parse.quote(session, safe=''))
        else:
            session = server.call('POST', '/session', {})['id']
        route = '/session/' + urllib.parse.quote(session, safe='')
        emit('session', session=session)
        first = message_id()
        wanted = parts(config['prompt'], config.get('files', []))
        done = threading.Event()
        failure = []
        completed = []
        def start():
            """Keep the initial model call alive until it completes or the runner stops."""
            try:
                completed.append(server.call('POST', route + '/message', {'messageID': first, 'parts': wanted}, timeout=None))
            except Exception:
                failure.append(True)
            finally:
                done.set()
        threading.Thread(target=start, daemon=True).start()
        # Do not append follow-ups before the initial user message is persisted.
        deadline = time.monotonic() + 15
        while True:
            try:
                observed = server.call('GET', route + '/message/' + first)
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
                observed = None
            if observed is not None and persisted_message(observed, first, config['prompt'], wanted):
                break
            if observed is not None and any(p.get('synthetic') and p.get('text', '').startswith('Read tool failed to read ') for p in observed.get('parts', [])):
                raise ValueError('Initial attachment processing failed')
            # Native persistence writes header and parts separately. Partial
            # readback is pending, not proof of a failed or missing message.
            if failure or time.monotonic() > deadline:
                raise ValueError('Initial persistence unconfirmed')
            time.sleep(.05)
        incoming = queue.Queue(maxsize=64)
        def read_input():
            """Read complete bounded control frames without buffered-stdin shutdown locks."""
            while True:
                raw = stream.readline(LIMIT + 1)
                if not raw or len(raw) > LIMIT:
                    incoming.put({'type': 'closed'})
                    return
                try:
                    incoming.put(json.loads(raw))
                except Exception:
                    incoming.put({'type': 'closed'})
                    return
        threading.Thread(target=read_input, daemon=True).start()
        latest = first
        permission_check = 0.0
        replied = set()
        while True:
            if time.monotonic() >= permission_check:
                permission_check = time.monotonic() + .5
                for request in server.call('GET', '/permission'):
                    if request.get('sessionID') != session or request['id'] in replied:
                        continue
                    if os.environ.get('WN_OPENCODE_NATIVE_APPROVALS', 'inherit') != 'once':
                        raise ValueError('Interactive permission request unavailable')
                    replied.add(request['id'])
                    # Mirrors run --auto: answer an ask once. Native hard denies
                    # never reach this request list and remain enforced.
                    server.call('POST', '/permission/' + urllib.parse.quote(request['id'], safe='') + '/reply', {'reply': 'once'})
                for request in server.call('GET', '/question'):
                    if request.get('sessionID') == session:
                        # The backend has no interactive question UI. Reject
                        # once so the model can ask in its normal chat reply.
                        key = 'question:' + request['id']
                        if key not in replied:
                            replied.add(key)
                            server.call('POST', '/question/' + urllib.parse.quote(request['id'], safe='') + '/reject', {})

            try:
                command = incoming.get(timeout=.1)
            except queue.Empty:
                if done.is_set():
                    emit('finishing')
                continue
            kind = command.get('type')
            if kind == 'closed':
                raise ValueError('Control input closed')
            if kind == 'steer':
                if done.is_set():
                    # No submission was attempted: normal same-session next
                    # turn is safe once the active loop has already ended.
                    emit('ack', id=command['id'], inactive=True)
                    continue
                mid = message_id()
                try:
                    expected = parts(command['prompt'], command.get('files', []))
                except (OSError, ValueError):
                    emit('ack', id=command['id'], inactive=True)
                    continue
                try:
                    # Sync noReply persists through the native createUserMessage
                    # path without waiting for the existing model/tool loop.
                    result = server.call('POST', route + '/message', {'messageID': mid, 'parts': expected, 'noReply': True})
                    persisted = persisted_message(result, mid, command['prompt'], expected)
                    if not persisted:
                        raise ValueError('Persistence not acknowledged')
                    latest = mid
                    emit('ack', id=command['id'], persisted=True)
                except Exception:
                    emit('ack', id=command['id'], persisted=False)
                    raise ValueError('Follow-up outcome uncertain')
            elif kind == 'finish':
                if not done.is_set() or failure:
                    raise ValueError('Native completion failed')
                # The original prompt POST returns the loop's final assistant
                # message. Reuse it rather than loading unrelated media history.
                answer = completed[0] if completed else None
                info = answer.get('info', {}) if isinstance(answer, dict) else {}
                if (info.get('role') != 'assistant' or info.get('parentID') != latest
                        or not info.get('time', {}).get('completed')
                        or info.get('finish') in (None, 'tool-calls', 'unknown')):
                    # A native late-append race must never silently lose/replay
                    # the saved follow-up. Preserve session and fail explicitly.
                    raise ValueError('Saved follow-up has no completed answer')
                if answer['info'].get('error'):
                    raise ValueError('Native model error')
                for part in answer.get('parts', []):
                    if part.get('type') == 'text' and not part.get('synthetic') and part.get('time', {}).get('end') and part.get('text'):
                        emit('text', text=part['text'])
                return
    finally:
        # Pending controls have not been processed once this loop exits.
        emit('stopping')
        server.close()

if __name__ == '__main__':
    try:
        run()
    except Exception:
        emit('error')
        sys.exit(1)
