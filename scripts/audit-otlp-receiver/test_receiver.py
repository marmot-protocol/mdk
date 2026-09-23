"""Synthetic HTTP contract tests; both services bind ephemeral loopback ports."""

import http.client
import json
import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from receiver import (
    MAX_BODY_BYTES,
    MAX_WIRE_BYTES,
    encode_batch,
    encoded,
    make_server,
    make_sink,
)


def synthetic(seq):
    return json.dumps(
        {
            "schema_version": "marmot-forensics-audit/v4",
            "seq": seq,
            "wall_time_ms": 1,
            "engine_id": "synthetic-engine",
            "recorder_session_id": "synthetic-session",
            "kind": {"type": "recorder_started", "recorder": "test"},
        },
        separators=(",", ":"),
    )


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.rows = []
        self.calls = 0
        self.mode = "normal"
        owner = self

        class DisposableSink(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path != "/readback":
                    self.send_error(404)
                    return
                raw = encoded(owner.rows)
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                if self.path != "/loki/api/v1/push":
                    self.send_error(404)
                    return
                owner.calls += 1
                payload = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                rows = [
                    row for stream in payload["streams"] for row in stream["values"]
                ]
                if owner.mode in {"partial", "partial_throttle"}:
                    owner.rows.extend(rows[:-1])
                    raw = b"synthetic downstream rejection"
                    self.send_response(400 if owner.mode == "partial" else 429)
                elif owner.mode == "fail_after_prefix":
                    owner.rows.extend(rows[:1])
                    raw = b""
                    self.send_response(503)
                elif owner.mode == "invalid_success":
                    owner.rows.extend(rows)
                    raw = b'{"partialSuccess":{"rejectedLogRecords":"0"}}'
                    self.send_response(200)
                elif owner.mode == "drop_after_write":
                    owner.rows.extend(rows)
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                elif owner.mode == "malformed_http":
                    self.wfile.write(b"invalid status line\r\n\r\n")
                    self.close_connection = True
                    return
                else:
                    owner.rows.extend(rows)
                    raw = b""
                    self.send_response(204)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.sink = HTTPServer(("127.0.0.1", 0), DisposableSink)
        self.sink_thread = threading.Thread(target=self.sink.serve_forever, daemon=True)
        self.sink_thread.start()
        sink_url = f"http://127.0.0.1:{self.sink.server_port}/loki/api/v1/push"
        self.receipt = 1_789_930_378_758_060_000
        self.receiver = make_server(
            "test-token", make_sink(sink_url), clock_ns=lambda: self.receipt
        )
        self.receiver_thread = threading.Thread(
            target=self.receiver.serve_forever, daemon=True
        )
        self.receiver_thread.start()
        self.url = f"http://127.0.0.1:{self.receiver.server_port}/v1/logs"

    def tearDown(self):
        for server, thread in (
            (self.receiver, self.receiver_thread),
            (self.sink, self.sink_thread),
        ):
            server.shutdown()
            server.server_close()
            thread.join()

    def post(self, raw, *, token="test-token", headers=None):
        request = urllib.request.Request(
            self.url,
            data=raw,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                **(headers or {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def readback(self):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.sink.server_port}/readback", timeout=3
        ) as response:
            return json.loads(response.read())

    def test_valid_batch_exact_body_readback_and_trusted_receipt(self):
        body = synthetic(1).replace('"seq":1', '"seq" : 1')
        self.assertEqual(self.post(encode_batch([body])), (200, {}))
        self.assertEqual(self.calls, 1)
        rows = self.readback()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], body)
        self.assertEqual(rows[0][0], str(self.receipt))
        self.assertNotEqual(rows[0][0], str(json.loads(body)["wall_time_ms"]))
        self.assertEqual(rows[0][2]["audit_kind"], "recorder_started")

    def test_duplicate_retry_keeps_exact_body_and_gets_new_receipt(self):
        raw = encode_batch([synthetic(1)])
        self.assertEqual(self.post(raw)[0], 200)
        self.receipt += 1
        self.assertEqual(self.post(raw)[0], 200)
        rows = self.readback()
        self.assertEqual([row[1] for row in rows], [synthetic(1)] * 2)
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertEqual(rows[0][2]["audit_sha256"], rows[1][2]["audit_sha256"])

    def test_limit_boundaries_accept_96_records_and_a_64k_line(self):
        bodies = [synthetic(i) for i in range(96)]
        self.assertEqual(self.post(encode_batch(bodies)), (200, {}))
        self.assertEqual(len(self.readback()), 96)
        body = synthetic(100)
        padding = MAX_BODY_BYTES - len(body.encode("utf-8")) + len("test")
        body = body.replace('"recorder":"test"', '"recorder":"' + "x" * padding + '"')
        self.assertEqual(len(body.encode("utf-8")), MAX_BODY_BYTES)
        self.assertEqual(self.post(encode_batch([body])), (200, {}))
        self.assertEqual(self.readback()[-1][1], body)

    def test_invalid_records_and_mixed_batch_make_no_downstream_call(self):
        bad = [
            "{",
            synthetic(1).replace(
                "marmot-forensics-audit/v4", "marmot-forensics-audit/v3"
            ),
            synthetic(1).replace("recorder_started", "future_kind"),
            synthetic(1).replace('"seq":1', '"seq":1,"seq":2'),
            synthetic(1).replace(
                '"recorder":"test"', '"recorder":"test","recorder":"again"'
            ),
            synthetic(1).replace('"recorder":"test"', '"recorder":"test","unknown":1'),
            synthetic(1).replace("synthetic-engine", r"\ud800"),
        ]
        for body in bad:
            with self.subTest(body=body):
                self.assertEqual(self.post(encode_batch([synthetic(0), body]))[0], 400)
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.readback(), [])

    def test_invalid_envelopes_and_limits_make_no_downstream_call(self):
        valid = encode_batch([synthetic(1)])
        variants = [
            valid.replace(b'"resourceLogs":', b'"resourceLogs":[],"resourceLogs":', 1),
            valid.replace(b'"scopeLogs":', b'"scopeLogs":[],"scopeLogs":', 1),
            valid.replace(b'"logRecords":', b'"logRecords":[],"logRecords":', 1),
            valid.replace(b'"resourceLogs"', b'"unknown"', 1),
            valid.replace(b'"marmot.audit"', b'"other"', 1),
            valid.replace(b'"scopeLogs"', b'"resource":{},"scopeLogs"', 1),
            encode_batch([]),
            encode_batch([synthetic(i) for i in range(97)]),
            encode_batch(
                [
                    synthetic(1).replace(
                        '"recorder":"test"', '"recorder":"' + "x" * MAX_BODY_BYTES + '"'
                    )
                ]
            ),
        ]
        for raw in variants:
            with self.subTest(length=len(raw)):
                self.assertEqual(self.post(raw)[0], 400)
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.receiver.server_port, timeout=3
        )
        connection.putrequest("POST", "/v1/logs")
        connection.putheader("Authorization", "Bearer test-token")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(MAX_WIRE_BYTES + 1))
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 413)
        connection.close()
        self.assertEqual(self.post(valid, headers={"Content-Encoding": "gzip"})[0], 400)
        self.assertEqual(self.calls, 0)

    def test_authentication_failure_makes_no_downstream_call(self):
        self.assertEqual(
            self.post(encode_batch([synthetic(1)]), token="wrong"), (401, {})
        )
        self.assertEqual(
            self.post(encode_batch([synthetic(1)]), token="\u00ff"), (401, {})
        )
        self.assertEqual(self.calls, 0)

    def test_partial_acceptance_never_reports_full_success(self):
        self.mode = "partial"
        bodies = [synthetic(i) for i in range(3)]
        self.assertEqual(self.post(encode_batch(bodies)), (409, {}))
        self.assertEqual([row[1] for row in self.readback()], bodies[:-1])

    def test_downstream_429_with_accepted_prefix_blocks_the_batch(self):
        self.mode = "partial_throttle"
        bodies = [synthetic(i) for i in range(3)]
        self.assertEqual(self.post(encode_batch(bodies)), (409, {}))
        self.assertEqual([row[1] for row in self.readback()], bodies[:-1])

    def test_uncertain_downstream_acceptance_is_retryable_and_can_duplicate(self):
        self.mode = "fail_after_prefix"
        bodies = [synthetic(i) for i in range(3)]
        raw = encode_batch(bodies)
        self.assertEqual(self.post(raw), (503, {}))
        self.assertEqual([row[1] for row in self.readback()], bodies[:1])
        self.mode = "normal"
        self.assertEqual(self.post(raw), (200, {}))
        self.assertEqual([row[1] for row in self.readback()], bodies[:1] + bodies)

    def test_lost_downstream_receipt_retains_batch_for_duplicate_retry(self):
        self.mode = "drop_after_write"
        raw = encode_batch([synthetic(7)])
        self.assertEqual(self.post(raw), (503, {}))
        self.assertEqual(len(self.readback()), 1)
        self.mode = "normal"
        self.assertEqual(self.post(raw), (200, {}))
        self.assertEqual([row[1] for row in self.readback()], [synthetic(7)] * 2)

    def test_unrecognized_downstream_2xx_cannot_become_full_success(self):
        self.mode = "invalid_success"
        self.assertEqual(self.post(encode_batch([synthetic(1)])), (503, {}))
        self.assertEqual(self.calls, 1)

    def test_malformed_downstream_http_is_uncertain(self):
        self.mode = "malformed_http"
        self.assertEqual(self.post(encode_batch([synthetic(1)])), (503, {}))
        self.assertEqual(self.calls, 1)


if __name__ == "__main__":
    unittest.main()
