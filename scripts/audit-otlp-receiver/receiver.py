"""Isolated, loopback-only audit OTLP receiver contract. No production wiring."""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

MAX_WIRE_BYTES = 1024 * 1024
MAX_BODY_BYTES = 65535  # The source's body plus its LF fits a 64 KiB cursor line.
MAX_RECORDS = 96
MAX_U64 = (1 << 64) - 1
SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "crates/marmot-forensics/schema/audit-log-event.v4.schema.json"
)
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("nonfinite_json")

    def unsigned_u64(number):
        # AuditEvent's numeric fields are u64 or u16. JSON Schema considers
        # 1.0 an integer and has no u64 ceiling, unlike Rust typed decoding.
        if number.startswith("-"):
            raise ValueError("negative_integer")
        value = int(number)
        if value > MAX_U64:
            raise ValueError("integer_exceeds_u64")
        return value

    def reject_float(_):
        raise ValueError("noninteger_number")

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=reject_constant,
        parse_int=unsigned_u64,
        parse_float=reject_float,
    )


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encode_batch(bodies):
    """The restricted OTLP/HTTP JSON producer shape."""
    return encoded(
        {
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "scope": {"name": "marmot.audit"},
                            "logRecords": [
                                {"body": {"stringValue": body}} for body in bodies
                            ],
                        }
                    ]
                }
            ]
        }
    )


def validate_batch(raw):
    """Return original body strings only after every event passes v4 validation."""
    try:
        if not 0 < len(raw) <= MAX_WIRE_BYTES:
            raise ValueError
        value = strict_json(raw.decode("utf-8"))
        if type(value) is not dict or set(value) != {"resourceLogs"}:
            raise ValueError
        resources = value["resourceLogs"]
        if type(resources) is not list or len(resources) != 1:
            raise ValueError
        resource = resources[0]
        if type(resource) is not dict or set(resource) != {"scopeLogs"}:
            raise ValueError
        scopes = resource["scopeLogs"]
        if type(scopes) is not list or len(scopes) != 1:
            raise ValueError
        scope = scopes[0]
        if (
            type(scope) is not dict
            or set(scope) != {"scope", "logRecords"}
            or scope["scope"] != {"name": "marmot.audit"}
        ):
            raise ValueError
        records = scope["logRecords"]
        if type(records) is not list or not 1 <= len(records) <= MAX_RECORDS:
            raise ValueError
        bodies = []
        for record in records:
            if type(record) is not dict or set(record) != {"body"}:
                raise ValueError
            body_field = record["body"]
            if type(body_field) is not dict or set(body_field) != {"stringValue"}:
                raise ValueError
            body = body_field["stringValue"]
            if (
                type(body) is not str
                or not 0 < len(body.encode("utf-8")) <= MAX_BODY_BYTES
                or "\n" in body
                or "\r" in body
            ):
                raise ValueError
            event = strict_json(body)
            if type(event) is not dict or not VALIDATOR.is_valid(event):
                raise ValueError
            # Escaped JSON can decode to lone surrogates, which Loki cannot encode.
            encoded(event)
            bodies.append((body, event))
        return bodies
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError("invalid_otlp_batch") from None


def bucket(group, engine, account):
    key = ["group", group] if group else ["context", engine, account]
    digest = hashlib.sha256(encoded(key)).digest()
    return f"b{int.from_bytes(digest[:8], 'big') % 64:02x}"


def loki_payload(bodies, receipt_ns):
    streams = defaultdict(list)
    for body, event in bodies:
        group = event.get("group_ref", "")
        account = event.get("account_ref", "")
        metadata = {
            "audit_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "audit_group": group,
            "audit_engine": event["engine_id"],
            "audit_account": account,
            "audit_session": event.get("recorder_session_id", ""),
            "audit_kind": event["kind"]["type"],
        }
        streams[bucket(group, event["engine_id"], account)].append(
            [str(receipt_ns), body, metadata]
        )
    return encoded(
        {
            "streams": [
                {
                    "stream": {
                        "service_name": "marmot-audit-receiver-contract",
                        "deployment_environment_name": "isolated-test",
                        "audit_bucket": key,
                    },
                    "values": values,
                }
                for key, values in sorted(streams.items())
            ]
        }
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def make_sink(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.path != "/loki/api/v1/push"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or parsed.port is None
    ):
        raise ValueError("isolated_sink_must_be_loopback_loki_push")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def write(payload):
        request = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with opener.open(request, timeout=3) as response:
                raw = response.read(65537)
                if response.status == 204 and not raw:
                    return "full"
        except urllib.error.HTTPError as error:
            # Ordinary rate-limit 429 drops the request; rare 429 paths can
            # accept a prefix, so a retry may duplicate that prefix.
            if 400 <= error.code < 500 and error.code != 429:
                return "blocked"
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            pass
        return "uncertain"

    return write


def make_server(token, sink, *, clock_ns=time.time_ns):
    if not token or not token.isascii() or "\n" in token or "\r" in token:
        raise ValueError("invalid_test_token")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Never log request paths, headers, or rejected bodies.

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def reply(self, status, value):
            raw = encoded(value)
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                pass

        def do_POST(self):
            if self.path != "/v1/logs":
                self.reply(404, {})
                return
            if not hmac.compare_digest(
                self.headers.get("Authorization", "").encode("latin-1"),
                ("Bearer " + token).encode("ascii"),
            ):
                self.reply(401, {})
                return
            try:
                if (
                    self.headers.get("Content-Type") != "application/json"
                    or self.headers.get("Content-Encoding")
                    or self.headers.get("Transfer-Encoding")
                ):
                    raise ValueError
                length_headers = self.headers.get_all("Content-Length", [])
                if (
                    len(length_headers) != 1
                    or not length_headers[0].isascii()
                    or not length_headers[0].isdecimal()
                ):
                    raise ValueError
                length = int(length_headers[0])
                if not 0 < length <= MAX_WIRE_BYTES:
                    self.reply(413 if length > MAX_WIRE_BYTES else 400, {})
                    return
            except (ValueError, OSError):
                self.reply(400, {})
                return
            try:
                raw = self.rfile.read(length)
            except OSError:
                self.reply(503, {})
                return
            if len(raw) != length:
                self.reply(503, {})
                return
            try:
                bodies = validate_batch(raw)
            except ValueError:
                self.reply(400, {})
                return
            # This is the only side-effect boundary. All records are validated first.
            receipt_ns = clock_ns()
            try:
                outcome = sink(loki_payload(bodies, receipt_ns))
            except (OSError, RuntimeError, UnicodeError, http.client.HTTPException):
                outcome = "uncertain"
            if outcome == "full":
                self.reply(200, {})
            elif outcome == "blocked":
                self.reply(409, {})
            else:
                self.reply(503, {})

    return HTTPServer(("127.0.0.1", 0), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sink-url", required=True, help="loopback Loki push URL")
    parser.add_argument(
        "--token-env",
        required=True,
        help="name of environment variable holding test token",
    )
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        parser.error("test token environment variable is unset")
    server = make_server(token, make_sink(args.sink_url))
    print(
        f"isolated receiver listening on http://127.0.0.1:{server.server_port}/v1/logs",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
