#!/usr/bin/env python3
"""Two-host application-level benchmark over the real ``wn`` CLI.

Run one responder beside the remote client and one initiator beside the other
client. Both roles consume ``wn messages subscribe`` and publish ordinary
encrypted Marmot messages. The initiator measures round trips with its local
monotonic clock; neither role needs synchronized clocks for the primary metric.

The JSONL output is deliberately redacted: it contains caller-supplied client,
relay, build, and transport labels, but no account ids, group ids, relay URLs,
message ids, socket paths, or plaintext probe bodies.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import queue
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


SCHEMA = "marmot-relay-benchmark-v1"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_SUBSCRIPTION_SETTLE_SECONDS = 2.0


def compact_json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def build_probe(
    run_id: str,
    sequence: int,
    kind: str,
    warmup: bool,
    payload_bytes: int,
    sent_wall_ns: int,
    responder_wall_ns: int = 0,
) -> str:
    probe: dict[str, Any] = {
        "kind": kind,
        "padding": "",
        "responder_wall_ns": f"{responder_wall_ns:020d}",
        "run_id": run_id,
        "schema": SCHEMA,
        "sent_wall_ns": f"{sent_wall_ns:020d}",
        "sequence": sequence,
        "warmup": warmup,
    }
    base = compact_json(probe)
    if payload_bytes > len(base.encode("utf-8")):
        probe["padding"] = "x" * (payload_bytes - len(base.encode("utf-8")))
    encoded = compact_json(probe)
    # The padding field itself is already present in `base`, so adding one ASCII
    # byte adds exactly one encoded byte.
    if len(encoded.encode("utf-8")) < payload_bytes:
        raise RuntimeError("failed to construct requested benchmark payload")
    return encoded


def parse_probe(plaintext: str, run_id: str) -> dict[str, Any] | None:
    try:
        probe = json.loads(plaintext)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(probe, dict):
        return None
    if probe.get("schema") != SCHEMA or probe.get("run_id") != run_id:
        return None
    if probe.get("kind") not in {"ping", "pong"}:
        return None
    if not isinstance(probe.get("sequence"), int):
        return None
    if not isinstance(probe.get("warmup"), bool):
        return None
    try:
        int(probe["sent_wall_ns"])
        int(probe["responder_wall_ns"])
    except (KeyError, TypeError, ValueError):
        return None
    return probe


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]


class JsonlWriter:
    def __init__(self, path: str) -> None:
        self._owned: TextIO | None = None
        if path == "-":
            self._stream = sys.stdout
        else:
            output = Path(path)
            output.parent.mkdir(parents=True, exist_ok=True)
            self._owned = output.open("x", encoding="utf-8")
            self._stream = self._owned

    def write(self, record: dict[str, Any]) -> None:
        self._stream.write(compact_json(record) + "\n")
        self._stream.flush()

    def close(self) -> None:
        if self._owned is not None:
            self._owned.close()


@dataclass(frozen=True)
class WnConfig:
    executable: str
    home: str
    account: str
    group: str
    socket: str | None

    def base_command(self) -> list[str]:
        command = [self.executable, "--home", self.home]
        if self.socket:
            command.extend(["--socket", self.socket])
        command.extend(["--account", self.account, "--json"])
        return command


@dataclass(frozen=True)
class ReceivedProbe:
    probe: dict[str, Any]
    received_wall_ns: int
    received_monotonic_ns: int


class MessageSubscription:
    def __init__(self, config: WnConfig, run_id: str) -> None:
        command = config.base_command() + [
            "messages",
            "subscribe",
            config.group,
            "--limit",
            "20",
        ]
        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        if self._process.stdout is None:
            raise RuntimeError("wn subscription stdout was not captured")
        self._run_id = run_id
        self._messages: queue.Queue[ReceivedProbe | BaseException] = queue.Queue()
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                received_monotonic_ns = time.monotonic_ns()
                received_wall_ns = time.time_ns()
                try:
                    frame = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if frame.get("ok") is False:
                    raise RuntimeError("wn message subscription returned an error")
                result = frame.get("result")
                if not isinstance(result, dict):
                    continue
                message = result.get("message")
                if not isinstance(message, dict):
                    continue
                probe = parse_probe(message.get("plaintext"), self._run_id)
                if probe is not None:
                    self._messages.put(
                        ReceivedProbe(probe, received_wall_ns, received_monotonic_ns)
                    )
            if self._process.poll() not in {None, 0}:
                raise RuntimeError("wn message subscription exited unsuccessfully")
            raise RuntimeError("wn message subscription ended")
        except BaseException as error:  # Propagate reader failures to the main role.
            self._messages.put(error)

    def receive(self, timeout_seconds: float) -> ReceivedProbe:
        received = self._messages.get(timeout=timeout_seconds)
        if isinstance(received, BaseException):
            raise received
        return received

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
        self._thread.join(timeout=1)


def send_message(config: WnConfig, plaintext: str) -> tuple[float, int]:
    started = time.monotonic_ns()
    completed = subprocess.run(
        config.base_command() + ["messages", "send", config.group, plaintext],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        check=False,
    )
    duration_ms = (time.monotonic_ns() - started) / 1_000_000
    if completed.returncode != 0:
        raise RuntimeError("wn message publication failed")
    try:
        frame = json.loads(completed.stdout)
        published = int(frame["result"]["published"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("wn message publication returned invalid JSON") from error
    if frame.get("ok") is not True or published <= 0:
        raise RuntimeError("wn message publication was not acknowledged")
    return duration_ms, published


def wn_version(executable: str) -> str:
    completed = subprocess.run(
        [executable, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def start_record(args: argparse.Namespace, role: str) -> dict[str, Any]:
    return {
        "build_id": args.build_id,
        "client_label": args.client_label,
        "event": "run_start",
        "platform": platform.platform(),
        "relay_label": args.relay_label,
        "role": role,
        "run_id": args.run_id,
        "schema": SCHEMA,
        "started_wall_ns": time.time_ns(),
        "transport": args.transport,
        "wn_version": wn_version(args.wn),
    }


def run_responder(args: argparse.Namespace) -> int:
    config = WnConfig(args.wn, args.home, args.account, args.group, args.socket)
    writer = JsonlWriter(args.output)
    subscription = MessageSubscription(config, args.run_id)
    responded: set[int] = set()
    duplicates = 0
    failures = 0
    writer.write(start_record(args, "responder"))
    print("benchmark responder is listening", file=sys.stderr, flush=True)
    try:
        while len(responded) < args.expected:
            try:
                received = subscription.receive(args.idle_timeout_seconds)
            except queue.Empty:
                writer.write(
                    {
                        "event": "run_end",
                        "reason": "idle_timeout",
                        "responded": len(responded),
                        "run_id": args.run_id,
                        "schema": SCHEMA,
                    }
                )
                return 2
            probe = received.probe
            if probe["kind"] != "ping":
                continue
            sequence = int(probe["sequence"])
            if sequence in responded:
                duplicates += 1
                continue
            responded.add(sequence)
            sent_wall_ns = int(probe["sent_wall_ns"])
            probe["kind"] = "pong"
            probe["responder_wall_ns"] = f"{received.received_wall_ns:020d}"
            pong = compact_json(probe)
            try:
                publish_ms, published = send_message(config, pong)
                outcome = "success"
            except (RuntimeError, subprocess.TimeoutExpired):
                publish_ms = None
                published = 0
                outcome = "publish_failed"
                failures += 1
            writer.write(
                {
                    "approx_sender_to_responder_ms": (
                        received.received_wall_ns - sent_wall_ns
                    )
                    / 1_000_000,
                    "duplicate_pings": duplicates,
                    "event": "probe",
                    "outcome": outcome,
                    "payload_bytes": len(pong.encode("utf-8")),
                    "response_publish_ms": publish_ms,
                    "response_published": published,
                    "run_id": args.run_id,
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "warmup": bool(probe["warmup"]),
                }
            )
        writer.write(
            {
                "duplicate_pings": duplicates,
                "event": "run_end",
                "failures": failures,
                "reason": "complete",
                "responded": len(responded),
                "run_id": args.run_id,
                "schema": SCHEMA,
            }
        )
        return 0 if failures == 0 else 2
    finally:
        subscription.close()
        writer.close()


def wait_for_pong(
    subscription: MessageSubscription,
    sequence: int,
    timeout_seconds: float,
) -> ReceivedProbe:
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise queue.Empty
        received = subscription.receive(remaining)
        if received.probe["kind"] == "pong" and received.probe["sequence"] == sequence:
            return received


def run_initiator(args: argparse.Namespace) -> int:
    config = WnConfig(args.wn, args.home, args.account, args.group, args.socket)
    writer = JsonlWriter(args.output)
    subscription = MessageSubscription(config, args.run_id)
    writer.write(start_record(args, "initiator"))
    time.sleep(args.subscription_settle_seconds)
    total = args.warmups + args.samples
    measured_rtts: list[float] = []
    measured_publish: list[float] = []
    failures = 0
    try:
        for sequence in range(total):
            warmup = sequence < args.warmups
            sent_wall_ns = time.time_ns()
            ping = build_probe(
                args.run_id,
                sequence,
                "ping",
                warmup,
                args.payload_bytes,
                sent_wall_ns,
            )
            round_trip_started = time.monotonic_ns()
            publish_ms = None
            published = 0
            try:
                publish_ms, published = send_message(config, ping)
                pong = wait_for_pong(subscription, sequence, args.timeout_seconds)
                rtt_ms = (pong.received_monotonic_ns - round_trip_started) / 1_000_000
                outcome = "success"
                if not warmup:
                    measured_rtts.append(rtt_ms)
                    measured_publish.append(publish_ms)
            except queue.Empty:
                rtt_ms = None
                outcome = "response_timeout"
                if not warmup:
                    failures += 1
            except (RuntimeError, subprocess.TimeoutExpired):
                publish_ms = None
                published = 0
                rtt_ms = None
                outcome = "publish_failed"
                if not warmup:
                    failures += 1
            writer.write(
                {
                    "event": "probe",
                    "outcome": outcome,
                    "payload_bytes": len(ping.encode("utf-8")),
                    "published": published,
                    "publish_ack_ms": publish_ms,
                    "round_trip_ms": rtt_ms,
                    "run_id": args.run_id,
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "warmup": warmup,
                }
            )

        summary = {
            "event": "summary",
            "failures": failures,
            "payload_bytes": args.payload_bytes,
            "publish_ack_mean_ms": (
                statistics.fmean(measured_publish) if measured_publish else None
            ),
            "publish_ack_p50_ms": percentile(measured_publish, 0.50),
            "publish_ack_p95_ms": percentile(measured_publish, 0.95),
            "round_trip_mean_ms": statistics.fmean(measured_rtts) if measured_rtts else None,
            "round_trip_p50_ms": percentile(measured_rtts, 0.50),
            "round_trip_p95_ms": percentile(measured_rtts, 0.95),
            "round_trip_p99_ms": percentile(measured_rtts, 0.99),
            "run_id": args.run_id,
            "samples_requested": args.samples,
            "samples_successful": len(measured_rtts),
            "schema": SCHEMA,
            "transport": args.transport,
            "warmups": args.warmups,
        }
        writer.write(summary)
        if args.output != "-":
            print(compact_json(summary))
        return 0 if failures == 0 else 2
    finally:
        subscription.close()
        writer.close()


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--wn", default="wn", help="wn executable")
    parser.add_argument("--home", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--socket", help=argparse.SUPPRESS)
    parser.add_argument("--account", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--group", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--run-id", required=True, help="Shared synthetic benchmark run id")
    parser.add_argument(
        "--transport", required=True, choices=("websocket", "fips"), help="Result label"
    )
    parser.add_argument("--client-label", required=True, help="Non-sensitive client label")
    parser.add_argument("--relay-label", default="demo-wok", help="Non-sensitive relay label")
    parser.add_argument(
        "--build-id", default=os.environ.get("MDK_BUILD_ID", "unknown"), help="Commit or artifact id"
    )
    parser.add_argument("--output", required=True, help="New JSONL output path, or - for stdout")


def load_successful_probes(paths: list[str]) -> tuple[list[float], list[float], int]:
    round_trips: list[float] = []
    publish_acks: list[float] = []
    failures = 0
    for path in paths:
        with Path(path).open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                if record.get("schema") != SCHEMA or record.get("event") != "probe":
                    continue
                if record.get("warmup") is True:
                    continue
                if record.get("outcome") != "success":
                    failures += 1
                    continue
                if isinstance(record.get("round_trip_ms"), (int, float)):
                    round_trips.append(float(record["round_trip_ms"]))
                if isinstance(record.get("publish_ack_ms"), (int, float)):
                    publish_acks.append(float(record["publish_ack_ms"]))
    return round_trips, publish_acks, failures


def metric_summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "mean_ms": statistics.fmean(values) if values else None,
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
    }


def run_summarize(args: argparse.Namespace) -> int:
    summaries: dict[str, dict[str, Any]] = {}
    for transport, paths in (("websocket", args.websocket), ("fips", args.fips)):
        round_trips, publish_acks, failures = load_successful_probes(paths)
        summaries[transport] = {
            "failures": failures,
            "publish_ack": metric_summary(publish_acks),
            "round_trip": metric_summary(round_trips),
        }

    websocket_p50 = summaries["websocket"]["round_trip"]["p50_ms"]
    fips_p50 = summaries["fips"]["round_trip"]["p50_ms"]
    comparison = {
        "round_trip_p50_delta_ms": None,
        "round_trip_p50_ratio_fips_to_websocket": None,
    }
    if isinstance(websocket_p50, (int, float)) and isinstance(fips_p50, (int, float)):
        comparison["round_trip_p50_delta_ms"] = fips_p50 - websocket_p50
        if websocket_p50 > 0:
            comparison["round_trip_p50_ratio_fips_to_websocket"] = (
                fips_p50 / websocket_p50
            )

    result = {
        "comparison": comparison,
        "event": "comparison_summary",
        "schema": SCHEMA,
        "transports": summaries,
    }
    writer = JsonlWriter(args.output)
    try:
        writer.write(result)
    finally:
        writer.close()
    if args.output != "-":
        print(compact_json(result))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    roles = root.add_subparsers(dest="role", required=True)

    responder = roles.add_parser("responder", help="Echo matching benchmark probes")
    add_common_arguments(responder)
    responder.add_argument("--expected", type=int, required=True, help="Expected ping count")
    responder.add_argument(
        "--idle-timeout-seconds", type=float, default=120.0, help="Exit after this idle period"
    )

    initiator = roles.add_parser("initiator", help="Send probes and measure monotonic RTT")
    add_common_arguments(initiator)
    initiator.add_argument("--warmups", type=int, default=5)
    initiator.add_argument("--samples", type=int, default=50)
    initiator.add_argument("--payload-bytes", type=int, default=512)
    initiator.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    initiator.add_argument(
        "--subscription-settle-seconds",
        type=float,
        default=DEFAULT_SUBSCRIPTION_SETTLE_SECONDS,
    )

    summarize = roles.add_parser(
        "summarize", help="Aggregate initiator JSONL and compare transports"
    )
    summarize.add_argument(
        "--websocket", action="append", required=True, help="WebSocket initiator JSONL"
    )
    summarize.add_argument(
        "--fips", action="append", required=True, help="FIPS initiator JSONL"
    )
    summarize.add_argument("--output", required=True, help="New JSONL output path, or -")
    return root


def validate_args(args: argparse.Namespace) -> None:
    if args.role == "summarize":
        return
    for field in ("run_id", "client_label", "relay_label", "build_id"):
        if not getattr(args, field).strip():
            raise SystemExit(f"--{field.replace('_', '-')} cannot be empty")
    if args.role == "responder" and args.expected <= 0:
        raise SystemExit("--expected must be positive")
    if args.role == "initiator":
        if args.samples <= 0 or args.warmups < 0:
            raise SystemExit("--samples must be positive and --warmups cannot be negative")
        if args.payload_bytes <= 0 or args.payload_bytes > 65_536:
            raise SystemExit("--payload-bytes must be in 1..=65536")


def main() -> int:
    args = parser().parse_args()
    validate_args(args)
    if args.role == "responder":
        return run_responder(args)
    if args.role == "initiator":
        return run_initiator(args)
    return run_summarize(args)


if __name__ == "__main__":
    raise SystemExit(main())
