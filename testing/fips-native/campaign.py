#!/usr/bin/env python3
"""Stage and run a two-host WebSocket/FIPS Marmot comparison campaign."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "marmot-dual-relay-campaign-v1"
DISCOVERY_RELAY = "wss://relay.fips.whitenoise.chat"
FIPS_ENDPOINT = "fips://npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg"
FIPS_RELAY_NPUB = "npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg"
CLIENT_CONTAINER = "wn-client"
FIPS_CONTAINER = "wn-fips-client"
DEFAULT_REMOTE = "root@95.216.204.149"
DEFAULT_MANIFEST = "/tmp/mdk-fips-campaign/manifest.json"
DEFAULT_RESULTS_ROOT = "/tmp/mdk-fips-campaign/results"


class CampaignError(RuntimeError):
    pass


def compact_json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class Host:
    label: str
    ssh_target: str | None = None

    def _docker_command(
        self, container: str, args: list[str], *, detached: bool = False
    ) -> list[str]:
        docker = ["docker", "exec"]
        if detached:
            docker.append("-d")
        docker.extend([container, *args])
        if self.ssh_target is None:
            return docker
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            self.ssh_target,
            shlex.join(docker),
        ]

    def run(
        self,
        args: list[str],
        *,
        container: str = CLIENT_CONTAINER,
        timeout: float = 60,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            self._docker_command(container, args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise CampaignError(f"{self.label} command failed: {detail}")
        return completed

    def run_detached(
        self, args: list[str], *, container: str = CLIENT_CONTAINER
    ) -> None:
        completed = subprocess.run(
            self._docker_command(container, args, detached=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise CampaignError(f"{self.label} detached command failed: {detail}")

    def popen(self, args: list[str]) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self._docker_command(CLIENT_CONTAINER, args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def json(self, args: list[str], *, timeout: float = 60) -> dict[str, Any]:
        completed = self.run(args, timeout=timeout)
        try:
            frame = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise CampaignError(f"{self.label} returned invalid JSON") from error
        if frame.get("ok") is not True:
            raise CampaignError(f"{self.label} returned an application error")
        return frame


@dataclass(frozen=True)
class Account:
    host: Host
    lane: str
    home: str
    socket: str
    npub: str

    def wn_args(
        self,
        *command: str,
        relay: str | None = None,
        use_socket: bool = True,
    ) -> list[str]:
        args = [
            "wn",
            "--home",
            self.home,
            "--secret-store",
            "file",
            "--account",
            self.npub,
            "--json",
        ]
        if use_socket:
            args[3:3] = ["--socket", self.socket]
        if relay is not None:
            args.extend(["--relay", relay])
        args.extend(command)
        return args


class RecordWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("x", encoding="utf-8")

    def write(self, event: str, **fields: Any) -> None:
        self._stream.write(
            compact_json(
                {
                    "event": event,
                    "recorded_wall_ns": time.time_ns(),
                    "schema": SCHEMA,
                    **fields,
                }
            )
            + "\n"
        )
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


def timed_json(host: Host, args: list[str], timeout: float = 60) -> tuple[dict[str, Any], float]:
    started = time.monotonic_ns()
    frame = host.json(args, timeout=timeout)
    elapsed_ms = (time.monotonic_ns() - started) / 1_000_000
    return frame, elapsed_ms


def create_account(host: Host, campaign_id: str, lane: str) -> dict[str, str]:
    home = f"/var/lib/mdk/campaigns/{campaign_id}/{lane}"
    socket = f"/run/mdk/{campaign_id}-{lane}.sock"
    existing = host.json(
        [
            "wn",
            "--home",
            home,
            "--secret-store",
            "file",
            "--json",
            "accounts",
            "list",
        ]
    )["result"].get("accounts", [])
    if len(existing) == 1:
        return {"home": home, "socket": socket, "npub": existing[0]["npub"]}
    if len(existing) > 1:
        raise CampaignError(f"{host.label} {lane} account home is not isolated")
    frame = host.json(
        [
            "wn",
            "--home",
            home,
            "--secret-store",
            "file",
            "--json",
            "--relay",
            DISCOVERY_RELAY,
            "create-identity",
        ],
        timeout=120,
    )
    return {"home": home, "socket": socket, "npub": frame["result"]["npub"]}


def account_from_manifest(host: Host, lane: str, value: dict[str, str]) -> Account:
    return Account(host, lane, value["home"], value["socket"], value["npub"])


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("schema") != SCHEMA:
        raise CampaignError("campaign manifest has an unknown schema")
    return manifest


def configure_inbox(account: Account, endpoint: str) -> None:
    frame = account.host.json(
        account.wn_args(
            "relays",
            "set",
            endpoint,
            "--type",
            "inbox",
            relay=DISCOVERY_RELAY,
            use_socket=False,
        ),
        timeout=120,
    )
    if frame["result"].get("relays") != [endpoint]:
        raise CampaignError(f"{account.host.label} {account.lane} inbox did not converge")


def verify_inbox(account: Account, endpoint: str) -> None:
    frame = account.host.json(account.wn_args("relays", "list", "--type", "inbox"))
    if frame["result"].get("relays") != [endpoint]:
        raise CampaignError(f"{account.host.label} {account.lane} inbox route changed")


def socket_ready(account: Account) -> bool:
    return account.host.run(["test", "-S", account.socket], check=False).returncode == 0


def start_daemon(account: Account, endpoint: str) -> None:
    if socket_ready(account):
        return
    account.host.run(["rm", "-f", account.socket])
    account.host.run_detached(
        [
            "wnd",
            "--home",
            account.home,
            "--socket",
            account.socket,
            "--secret-store",
            "file",
            "--relay",
            endpoint,
            "--discovery-relays",
            DISCOVERY_RELAY,
            "--default-account-relays",
            DISCOVERY_RELAY,
        ]
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if socket_ready(account):
            return
        time.sleep(0.2)
    raise CampaignError(f"{account.host.label} {account.lane} daemon did not start")


def wait_fips_ready(account: Account) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        completed = account.host.run(account.wn_args("relay-stats"), check=False)
        if completed.returncode == 0:
            try:
                result = json.loads(completed.stdout)["result"]["fips"]
            except (KeyError, TypeError, json.JSONDecodeError):
                result = {}
            if (
                result.get("enabled") is True
                and result.get("connected_endpoints", 0) > 0
                and result.get("reconnecting_endpoints") == 0
            ):
                return
        time.sleep(0.5)
    raise CampaignError(f"{account.host.label} FIPS adapter did not become ready")


def preflight(hosts: list[Host]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for host in hosts:
        version = host.run(["wn", "--version"]).stdout.strip()
        fips_version = host.run(["fips", "--version"]).stdout.strip().splitlines()[0]
        peer_frame = host.run(
            ["fipsctl", "--socket", "/run/fips/control.sock", "show", "peers"],
            container=FIPS_CONTAINER,
            timeout=20,
        )
        peer_state = json.loads(peer_frame.stdout)
        connected = any(
            peer.get("npub") == FIPS_RELAY_NPUB and peer.get("connectivity") == "connected"
            for peer in peer_state.get("peers", [])
        )
        if not connected:
            raise CampaignError(f"{host.label} FIPS peer is not connected")
        smoke_args = [
            "mdk-fips-relay-smoke",
            "/run/fips/api.sock",
            FIPS_ENDPOINT,
            "--read-only",
            "--websocket",
            DISCOVERY_RELAY,
        ]
        smoke: subprocess.CompletedProcess[str] | None = None
        last_error: Exception | None = None
        for _ in range(2):
            try:
                smoke = host.run(smoke_args, timeout=60)
                break
            except (CampaignError, subprocess.TimeoutExpired) as error:
                last_error = error
                time.sleep(1)
        if smoke is None:
            raise CampaignError(f"{host.label} relay smoke failed twice: {last_error}")
        evidence[host.label] = {
            "fips_version": fips_version,
            "smoke": smoke.stdout.strip().splitlines(),
            "wn_version": version,
        }
    return evidence


def stage(args: argparse.Namespace, local: Host, remote: Host) -> dict[str, Any]:
    manifest_path = Path(args.manifest)
    if manifest_path.exists():
        manifest = load_manifest(manifest_path)
        start_manifest_daemons(manifest, local, remote)
        return manifest
    campaign_id = args.campaign_id or f"demo-{utc_timestamp().lower()}"
    lanes: dict[str, Any] = {}
    for lane in ("websocket", "fips"):
        lanes[lane] = {
            "local": create_account(local, campaign_id, lane),
            "remote": create_account(remote, campaign_id, lane),
        }

    # Nostr replaceable events have one-second timestamp precision. Ensure the
    # lane-specific kind-10050 publication is later than account creation.
    time.sleep(1.1)
    for lane, endpoint in (("websocket", DISCOVERY_RELAY), ("fips", FIPS_ENDPOINT)):
        for host, host_key in ((local, "local"), (remote, "remote")):
            configure_inbox(account_from_manifest(host, lane, lanes[lane][host_key]), endpoint)

    manifest = {
        "campaign_id": campaign_id,
        "created_at": utc_timestamp(),
        "discovery_relay": DISCOVERY_RELAY,
        "fips_endpoint": FIPS_ENDPOINT,
        "lanes": lanes,
        "remote": args.remote,
        "schema": SCHEMA,
    }
    write_manifest(manifest_path, manifest)

    start_manifest_daemons(manifest, local, remote)
    return manifest


def start_manifest_daemons(manifest: dict[str, Any], local: Host, remote: Host) -> None:
    for lane, endpoint in (("websocket", DISCOVERY_RELAY), ("fips", FIPS_ENDPOINT)):
        for host, host_key in ((local, "local"), (remote, "remote")):
            account = account_from_manifest(host, lane, manifest["lanes"][lane][host_key])
            start_daemon(account, endpoint)
            if lane == "fips":
                wait_fips_ready(account)
            verify_inbox(account, endpoint)


def poll_json(
    account: Account,
    command: tuple[str, ...],
    predicate: Any,
    *,
    timeout: float = 45,
) -> tuple[dict[str, Any], float]:
    started = time.monotonic_ns()
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            frame = account.host.json(account.wn_args(*command), timeout=20)
            if predicate(frame):
                return frame, (time.monotonic_ns() - started) / 1_000_000
        except (CampaignError, KeyError, TypeError) as error:
            last_error = error
        time.sleep(0.25)
    suffix = f": {last_error}" if last_error else ""
    raise CampaignError(f"timed out waiting for {account.host.label} state{suffix}")


def assert_group_route(account: Account, group_id: str, endpoint: str) -> None:
    frame = account.host.json(account.wn_args("groups", "relays", group_id))
    if frame["result"].get("relays") != [endpoint]:
        raise CampaignError(f"{account.host.label} group route is not {endpoint}")


def fetch_key_package(inviter: Account, invitee: Account, endpoint: str) -> None:
    frame = inviter.host.json(
        inviter.wn_args(
            "keys",
            "fetch",
            invitee.npub,
            "--bootstrap-relays",
            DISCOVERY_RELAY,
            relay=DISCOVERY_RELAY,
        ),
        timeout=120,
    )
    inbox = frame["result"]["relay_lists"]["inbox"].get("relays")
    if inbox != [endpoint]:
        raise CampaignError(f"inviter discovered the wrong {inviter.lane} inbox route")


def parse_summary(output: str) -> dict[str, Any]:
    summary: dict[str, Any] | None = None
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event") == "summary":
            summary = record
    if summary is None:
        raise CampaignError("benchmark initiator produced no summary")
    return summary


def validate_benchmark_summary(summary: dict[str, Any], samples: int) -> None:
    requested = summary.get("samples_requested")
    successful = summary.get("samples_successful")
    failures = summary.get("failures")
    if requested != samples:
        raise CampaignError("benchmark summary has the wrong requested sample count")
    if not isinstance(successful, int) or not isinstance(failures, int):
        raise CampaignError("benchmark summary has invalid outcome counts")
    if successful < 0 or failures < 0 or successful + failures != samples:
        raise CampaignError("benchmark summary does not account for every measured sample")


def run_benchmark_direction(
    lane: str,
    direction: str,
    initiator: Account,
    responder: Account,
    group_id: str,
    run_id: str,
    output_dir: Path,
    warmups: int,
    samples: int,
    payload_bytes: int,
) -> dict[str, Any]:
    expected = warmups + samples
    common = [
        "--home",
        responder.home,
        "--socket",
        responder.socket,
        "--account",
        responder.npub,
        "--group",
        group_id,
        "--run-id",
        run_id,
        "--transport",
        lane,
        "--client-label",
        responder.host.label,
        "--relay-label",
        "demo-wok",
        "--build-id",
        os.environ.get("MDK_BUILD_ID", "b103de45"),
        "--output",
        "-",
    ]
    responder_process = responder.host.popen(
        [
            "mdk-relay-benchmark",
            "responder",
            *common,
            "--expected",
            str(expected),
            "--idle-timeout-seconds",
            "60",
        ]
    )
    time.sleep(2.5)
    initiator_args = [
        "mdk-relay-benchmark",
        "initiator",
        "--home",
        initiator.home,
        "--socket",
        initiator.socket,
        "--account",
        initiator.npub,
        "--group",
        group_id,
        "--run-id",
        run_id,
        "--transport",
        lane,
        "--client-label",
        initiator.host.label,
        "--relay-label",
        "demo-wok",
        "--build-id",
        os.environ.get("MDK_BUILD_ID", "b103de45"),
        "--output",
        "-",
        "--warmups",
        str(warmups),
        "--samples",
        str(samples),
        "--payload-bytes",
        str(payload_bytes),
        "--timeout-seconds",
        "30",
    ]
    initiator_result = initiator.host.run(
        initiator_args, timeout=max(120, expected * 35), check=False
    )
    try:
        responder_stdout, responder_stderr = responder_process.communicate(timeout=75)
    except subprocess.TimeoutExpired as error:
        responder_process.terminate()
        responder_process.wait(timeout=10)
        raise CampaignError("benchmark responder did not finish") from error
    if responder_process.returncode not in {0, 2}:
        raise CampaignError(f"benchmark responder failed: {responder_stderr.strip()}")

    prefix = run_id
    (output_dir / f"{prefix}-initiator.jsonl").write_text(
        initiator_result.stdout, encoding="utf-8"
    )
    (output_dir / f"{prefix}-responder.jsonl").write_text(
        responder_stdout, encoding="utf-8"
    )
    summary = parse_summary(initiator_result.stdout)
    if initiator_result.returncode not in {0, 2}:
        detail = initiator_result.stderr.strip() or "unexpected initiator exit"
        raise CampaignError(f"{lane} {direction} benchmark failed: {detail}")
    validate_benchmark_summary(summary, samples)
    if responder_process.returncode == 2 and summary["failures"] == 0:
        raise CampaignError(f"{lane} {direction} responder was incomplete")
    return summary


def run_lane(
    lane: str,
    iteration: int,
    manifest: dict[str, Any],
    local: Host,
    remote: Host,
    output_dir: Path,
    writer: RecordWriter,
    args: argparse.Namespace,
) -> None:
    endpoint = DISCOVERY_RELAY if lane == "websocket" else FIPS_ENDPOINT
    local_account = account_from_manifest(local, lane, manifest["lanes"][lane]["local"])
    remote_account = account_from_manifest(remote, lane, manifest["lanes"][lane]["remote"])
    start_daemon(local_account, endpoint)
    start_daemon(remote_account, endpoint)
    if lane == "fips":
        wait_fips_ready(local_account)
        wait_fips_ready(remote_account)

    fetch_key_package(local_account, remote_account, endpoint)
    group_name = f"benchmark-{lane}-{iteration}"
    create, create_ms = timed_json(
        local,
        local_account.wn_args("groups", "create", group_name, remote_account.npub),
        timeout=180,
    )
    group_id = create["result"]["group_id"]
    writer.write("group_created", lane=lane, iteration=iteration, command_ms=create_ms)

    _, welcome_ms = poll_json(
        remote_account,
        ("groups", "invites"),
        lambda frame: any(
            invite.get("group_id") == group_id for invite in frame["result"].get("invites", [])
        ),
        timeout=60,
    )
    _, accept_ms = timed_json(
        remote,
        remote_account.wn_args("groups", "accept", group_id),
        timeout=120,
    )
    writer.write(
        "welcome_accepted",
        lane=lane,
        iteration=iteration,
        invite_arrival_ms=welcome_ms,
        accept_command_ms=accept_ms,
    )
    assert_group_route(local_account, group_id, endpoint)
    assert_group_route(remote_account, group_id, endpoint)

    for commit_index in (1, 2):
        name = f"benchmark-{lane}-{iteration}-commit-{commit_index}"
        commit, command_ms = timed_json(
            local,
            local_account.wn_args("groups", "rename", group_id, name),
            timeout=120,
        )
        if commit["result"].get("published", 0) <= 0:
            raise CampaignError("group commit was not acknowledged")
        state, convergence_ms = poll_json(
            remote_account,
            ("groups", "show", group_id),
            lambda frame, expected=name: frame["result"]["group"]["profile"]["name"]
            == expected,
            timeout=60,
        )
        writer.write(
            "commit_converged",
            lane=lane,
            iteration=iteration,
            commit_index=commit_index,
            command_ms=command_ms,
            convergence_ms=convergence_ms,
            observed_epoch=state["result"]["mls"]["epoch"],
        )

        if commit_index == 1:
            for direction, initiator, responder in (
                ("local-to-remote", local_account, remote_account),
                ("remote-to-local", remote_account, local_account),
            ):
                run_id = f"{manifest['campaign_id']}-{lane}-{iteration}-{direction}"
                summary = run_benchmark_direction(
                    lane,
                    direction,
                    initiator,
                    responder,
                    group_id,
                    run_id,
                    output_dir,
                    args.warmups,
                    args.samples,
                    args.payload_bytes,
                )
                writer.write(
                    "message_summary",
                    lane=lane,
                    iteration=iteration,
                    direction=direction,
                    failures=summary["failures"],
                    payload_bytes=summary["payload_bytes"],
                    publish_ack_p50_ms=summary["publish_ack_p50_ms"],
                    publish_ack_p95_ms=summary["publish_ack_p95_ms"],
                    round_trip_p50_ms=summary["round_trip_p50_ms"],
                    round_trip_p95_ms=summary["round_trip_p95_ms"],
                    round_trip_p99_ms=summary["round_trip_p99_ms"],
                    samples_requested=summary["samples_requested"],
                    samples_successful=summary["samples_successful"],
                )

    removal, removal_ms = timed_json(
        local,
        local_account.wn_args(
            "groups", "remove-members", group_id, remote_account.npub
        ),
        timeout=120,
    )
    if removal["result"].get("published", 0) <= 0:
        raise CampaignError("member-removal commit was not acknowledged")
    state, removal_convergence_ms = poll_json(
        remote_account,
        ("groups", "show", group_id),
        lambda frame: frame["result"]["mls"]["member_count"] == 1,
        timeout=60,
    )
    writer.write(
        "member_removal_converged",
        lane=lane,
        iteration=iteration,
        command_ms=removal_ms,
        convergence_ms=removal_convergence_ms,
        observed_epoch=state["result"]["mls"]["epoch"],
    )
    for account in (local_account, remote_account):
        account.host.run(account.wn_args("chats", "archive", group_id), check=False)


def run_campaign(args: argparse.Namespace, local: Host, remote: Host) -> Path:
    manifest = load_manifest(Path(args.manifest))
    output_dir = Path(args.results_root) / f"{manifest['campaign_id']}-{utc_timestamp().lower()}"
    output_dir.mkdir(parents=True, exist_ok=False)
    writer = RecordWriter(output_dir / "campaign.jsonl")
    try:
        evidence = preflight([local, remote])
        writer.write(
            "campaign_start",
            campaign_id=manifest["campaign_id"],
            lane_order=args.lane_order,
            repeats=args.repeats,
            warmups=args.warmups,
            samples=args.samples,
            payload_bytes=args.payload_bytes,
            clients={
                label: {
                    "wn_version": value["wn_version"],
                    "fips_version": value["fips_version"],
                }
                for label, value in evidence.items()
            },
        )
        order = [lane.strip() for lane in args.lane_order.split(",") if lane.strip()]
        if not order or any(lane not in {"websocket", "fips"} for lane in order):
            raise CampaignError("--lane-order must contain only websocket and fips")
        for iteration in range(1, args.repeats + 1):
            for lane in order:
                run_lane(lane, iteration, manifest, local, remote, output_dir, writer, args)
        summarize = [
            sys.executable,
            str(Path(__file__).with_name("benchmark.py")),
            "summarize",
        ]
        for lane in ("websocket", "fips"):
            initiators = sorted(output_dir.glob(f"*-{lane}-*-initiator.jsonl"))
            if not initiators:
                raise CampaignError(f"campaign produced no {lane} initiator evidence")
            for path in initiators:
                summarize.extend([f"--{lane}", str(path)])
        summarize.extend(["--output", str(output_dir / "comparison.jsonl")])
        completed = subprocess.run(
            summarize,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise CampaignError(f"comparison summary failed: {completed.stderr.strip()}")
        writer.write("campaign_complete", campaign_id=manifest["campaign_id"])
    finally:
        writer.close()
    return output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", default=DEFAULT_REMOTE)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    subcommands = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subcommands.add_parser("preflight")
    preflight_parser.set_defaults(action="preflight")

    stage_parser = subcommands.add_parser("stage")
    stage_parser.add_argument("--campaign-id")
    stage_parser.set_defaults(action="stage")

    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--results-root", default=DEFAULT_RESULTS_ROOT)
    run_parser.add_argument("--lane-order", default="websocket,fips")
    run_parser.add_argument("--repeats", type=int, default=1)
    run_parser.add_argument("--warmups", type=int, default=5)
    run_parser.add_argument("--samples", type=int, default=50)
    run_parser.add_argument("--payload-bytes", type=int, default=512)
    run_parser.set_defaults(action="run")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    local = Host("local-docker")
    remote = Host("remote-vm", args.remote)
    try:
        if args.action == "preflight":
            print(json.dumps(preflight([local, remote]), indent=2, sort_keys=True))
        elif args.action == "stage":
            manifest = stage(args, local, remote)
            print(
                compact_json(
                    {
                        "campaign_id": manifest["campaign_id"],
                        "manifest": args.manifest,
                        "ready": True,
                    }
                )
            )
        else:
            output = run_campaign(args, local, remote)
            print(compact_json({"complete": True, "results": str(output)}))
        return 0
    except (CampaignError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(f"campaign failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
