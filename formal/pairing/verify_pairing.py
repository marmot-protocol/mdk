#!/usr/bin/env python3
"""Check each pairing lemma and require three named model counterexamples."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

TERMINATION_GRACE_SECONDS = 2


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError(f"mutation requires one exact source match: {before!r}")
    return source.replace(before, after, 1)


def mutations(source):
    without_mac_sender = replace_once(source, "<gid,pk(leaf_key)>)", "gid)")
    without_mac_sender = replace_once(without_mac_sender, "<gid,sender_key>)", "gid)")
    without_welcome_guard = replace_once(
        source, "Eq(actual_sender,expected_sender),\n      ", ""
    )
    early = """rule NewConfirmBeforePeerVerification:
  let reply = mac(kdf(shared,<'mac','new',sid,a,ref,slot,'key_package_ref'>),ref)
  in
  [ NewApproved(sid,a,event,ref,nx,slot,ekey,shared) ]
  --[ NewConfirmSent(sid,a,event,ref,slot,'not_yet_known','not_yet_known') ]->
  [ Out(<'new_confirm',sid,reply>) ]

"""
    without_confirmation_order = replace_once(
        source, "rule NewVerifyAndConfirm:", early + "rule NewVerifyAndConfirm:"
    )
    return (
        (
            "omit-confirmation-signer",
            without_mac_sender,
            "pairing_confirmed_group_and_sender_agree",
        ),
        (
            "omit-welcome-sender-guard",
            without_welcome_guard,
            "pairing_welcome_sender_matches_confirmation",
        ),
        (
            "send-new-confirmation-early",
            without_confirmation_order,
            "pairing_new_confirmation_follows_existing_confirmation",
        ),
    )


def check(tamarin, model, folder, name, expected, timeout):
    command = [
        tamarin,
        str(model),
        "--prove" if name is None else f"--prove={name}",
        "--quit-on-warning",
        "--derivcheck-timeout=60",
    ]
    start = time.monotonic()
    timed_out = False
    termination = None
    log = folder / "prover.log"
    with log.open("w") as output:
        process = subprocess.Popen(
            command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            termination = "SIGTERM"
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                status = process.wait(timeout=TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                termination = "SIGKILL"
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                status = process.wait(timeout=TERMINATION_GRACE_SECONDS)
    text = log.read_text()
    marker = "summary of summaries:"
    summary = text.split(marker, 1)[1] if marker in text else ""
    outcomes = dict(
        re.findall(r"^  (\w+) \((?:all-traces|exists-trace)\): (.+)$", summary, re.M)
    )
    passed = (
        status == 0
        and not timed_out
        and bool(summary)
        and all(outcomes.get(lemma, "").startswith(result) for lemma, result in expected.items())
    )
    if name is None:
        passed = passed and outcomes.keys() == expected.keys()
    result = {
        "command": command,
        "exit": status,
        "timed_out": timed_out,
        "termination": termination,
        "termination_grace_seconds": TERMINATION_GRACE_SECONDS,
        "timeout_seconds": timeout,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "model_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "expected": expected,
        "outcomes": outcomes,
        "passed": passed,
    }
    (folder / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tamarin", default=os.environ.get("TAMARIN", "tamarin-prover"))
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--control-timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    if min(args.timeout_seconds, args.control_timeout_seconds) <= 0:
        parser.error("timeouts must be positive")
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.out / stamp
    output.mkdir(parents=True)
    model = Path(__file__).with_name("device_pairing_v1.spthy")
    source = model.read_text()
    names = re.findall(r"^lemma\s+(\w+)", source, re.M)
    if not names or len(names) != len(set(names)):
        raise ValueError("model needs a nonempty, uniquely named lemma inventory")
    version = subprocess.run(
        [args.tamarin, "--version"], capture_output=True, text=True, check=True
    )
    (output / "tool-version.txt").write_text(version.stdout + version.stderr)
    baseline = output / "baseline"
    baseline.mkdir()
    results = {}

    def record(label, result):
        results[label] = result
        print(
            json.dumps(
                {
                    "check": label,
                    "exit": result["exit"],
                    "timed_out": result["timed_out"],
                    "elapsed_seconds": result["elapsed_seconds"],
                    "model_sha256": result["model_sha256"],
                    "log_sha256": result["log_sha256"],
                    "outcomes": {
                        name: result["outcomes"].get(name, "missing")
                        for name in result["expected"]
                    },
                    "passed": result["passed"],
                }
            ),
            flush=True,
        )

    record(
        "baseline",
        check(
            args.tamarin,
            model,
            baseline,
            None,
            dict.fromkeys(names, "verified"),
            args.timeout_seconds,
        ),
    )
    if results["baseline"]["passed"]:
        for label, mutant, lemma in mutations(source):
            folder = output / label
            folder.mkdir()
            variant = folder / "device_pairing_v1.spthy"
            variant.write_text(mutant)
            record(
                label,
                check(
                    args.tamarin,
                    variant,
                    folder,
                    lemma,
                    {lemma: "falsified"},
                    args.control_timeout_seconds,
                ),
            )
    passed = len(results) == 4 and all(result["passed"] for result in results.values())
    report = {"passed": passed, "model": str(model), "results": results}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": passed, "evidence": str(output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
