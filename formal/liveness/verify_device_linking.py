#!/usr/bin/env python3
"""Run pinned TLC and require named model defects and reachability witnesses."""

import argparse
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser(description="Check bounded linking safety, progress and sensitivity.")
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--jar", type=Path)
parser.add_argument("--timeout-seconds", type=int, default=300)
args = parser.parse_args()
if args.timeout_seconds <= 0:
    parser.error("timeout must be positive")
os.umask(0o077)
worktree = Path(__file__).resolve().parents[2]
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
output = args.out.resolve() / stamp
output.mkdir(parents=True)
model = (worktree / 'formal/liveness/DeviceLinking.tla').read_text()
jar = (args.jar or worktree / "target/tla/tla2tools-v1.7.4.jar").resolve()
jar_sha256 = hashlib.sha256(jar.read_bytes()).hexdigest()
if jar_sha256 != "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88":
    raise SystemExit("Use the repository-pinned TLC v1.7.4 jar; run just _tla-tools first")
version = subprocess.run(["java", "-version"], capture_output=True, text=True, check=True)
(output / "tool-version.txt").write_text(version.stdout + version.stderr)
cases = [
    ('positive', model, (worktree / 'formal/liveness/DeviceLinking.fair.cfg').read_text(),
     'Model checking completed. No error has been found.', False),
    ('unfair', model, (worktree / 'formal/liveness/DeviceLinking.unfair.cfg').read_text(),
     'Temporal properties were violated.', True),
]
mutations = [
    ('signer', ' /\\ signer = 1 /\\ roster', ' /\\ roster', 'WelcomeBound'),
    ('fresh-ref', 'ref = s.expectedRef /\\ group = 1', 'group = 1', 'WelcomeBound'),
    ('roster', ' /\\ signer = 1 /\\ roster', ' /\\ signer = 1', 'WelcomeBound'),
    ('durable',
     "s.waiting /\\ s.expected /\\ ~s.cancel /\\ ~s.expired\n                     /\\ s' = [s EXCEPT !.newConfirmSent",
     "~s.cancel /\\ ~s.expired\n                     /\\ s' = [s EXCEPT !.newConfirmSent",
     'DurableBeforeNewConfirm'),
    ('order', 's.newTap /\\ s.verifiedExisting', 's.newTap', 'OrderedConfirm'),
    ('withdrawal', 'IF s.expected /\\ ~s.expired', 'IF ~s.expired',
     'AdmissionRequiresLiveExpectation'),
]
for name, old, new, prop in mutations:
    assert model.count(old) == 1, (name, model.count(old))
    config = 'SPECIFICATION Spec\nCONSTANT FairRun = FALSE\nINVARIANT ' + prop + '\n'
    cases.append(('mutant-' + name, model.replace(old, new), config,
                  'Invariant ' + prop + ' is violated.', True))
cross_action_mutations = [
    ('restart-resets-expiry',
     "s' = [s EXCEPT !.crashed = FALSE,",
     "s' = [s EXCEPT !.crashed = FALSE, !.expired = FALSE,",
     'AdmissionRespectsAttemptHistory'),
    ('restart-rearms-withdrawn',
     "s' = [s EXCEPT !.crashed = FALSE,",
     "s' = [s EXCEPT !.crashed = FALSE, !.expected = s.waiting,",
     'AdmissionRespectsAttemptHistory'),
    ('withdraw-keeps-expectation',
     "s' = [s EXCEPT !.expected = FALSE,\n                                      !.retired",
     "s' = [s EXCEPT !.expected = TRUE,\n                                      !.retired",
     'AdmissionRespectsAttemptHistory'),
    ('record-stale-ref',
     "!.expected = TRUE, !.expectedRef = s.attempt,",
     "!.expected = TRUE, !.expectedRef = 1,",
     'AdmissionRespectsAttemptHistory'),
]
for name, old, new, prop in cross_action_mutations:
    assert model.count(old) == 1, (name, model.count(old))
    cases.append(('mutant-' + name, model.replace(old, new),
                  'SPECIFICATION Spec\nCONSTANT FairRun = FALSE\nINVARIANT ' + prop + '\n',
                  'Invariant ' + prop + ' is violated.', True))
cleanup_guard = 'CleanWaitingRow == /\\ Live /\\ s.waiting /\\ ~s.expected /\\ ~s.joined'
assert model.count(cleanup_guard) == 1
blocked_cleanup = model.replace(cleanup_guard, cleanup_guard.replace('~s.expected', 's.expected'))
cases.append(('mutant-cleanup', blocked_cleanup,
              (worktree / 'formal/liveness/DeviceLinking.fair.cfg').read_text(),
              'Temporal properties were violated.', True))
for name, prop in [('join', 'NoSuccessfulJoin'),
                   ('fresh-same-group', 'NoFreshSameGroupJoin'),
                   ('partial-record-crash', 'NoPartialRecordCrash'),
                   ('pending-old-peer-work', 'NoLateOldPeerWork')]:
    cases.append(('witness-' + name, model,
                  'SPECIFICATION Spec\nCONSTANT FairRun = FALSE\nINVARIANT ' + prop + '\n',
                  'Invariant ' + prop + ' is violated.', True))
results = []
for name, source, config, expected, negative in cases:
    case = output / name
    case.mkdir(exist_ok=True)
    (case / 'DeviceLinking.tla').write_text(source)
    (case / 'DeviceLinking.cfg').write_text(config)
    command = ['java', '-XX:+UseParallelGC', '-Xmx2g',
               '-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.MemFPSet', '-jar', str(jar),
               '-workers', '1', '-deadlock', '-metadir', str(case / 'states'),
               '-config', 'DeviceLinking.cfg', 'DeviceLinking.tla']
    started = time.monotonic()
    expected_exit = (13 if name in {'unfair', 'mutant-cleanup'} else 12) if negative else 0
    result = dict(case=name, command=command, expected_exit=expected_exit,
                  expected_named_result=expected,
                  model_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  cfg_sha256=hashlib.sha256(config.encode()).hexdigest(),
                  workers=1, backend="MemFPSet", jar_sha256=jar_sha256)
    try:
        with (case / 'run.log').open('w') as stream:
            process = subprocess.run(command, cwd=case, stdout=stream,
                                     stderr=subprocess.STDOUT, timeout=args.timeout_seconds)
        log = (case / 'run.log').read_text()
        valid = expected in log and process.returncode == expected_exit
        valid = valid and 'unexpected exception' not in log and 'Parsing or semantic' not in log
        result.update(exit=process.returncode, valid=valid)
    except subprocess.TimeoutExpired:
        result.update(exit=None, valid=False, timeout_seconds=args.timeout_seconds)
    log = (case / 'run.log').read_text()
    counts = re.findall(r'([\d,]+) states generated, ([\d,]+) distinct states found', log)
    result.update(seconds=round(time.monotonic() - started, 3),
                  generated_states=int(counts[-1][0].replace(',', '')) if counts else None,
                  distinct_states=int(counts[-1][1].replace(',', '')) if counts else None)
    results.append(result)
    (output / 'RESULTS.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    if not result['valid']:
        raise SystemExit(1)

print(json.dumps({"passed": True, "evidence": str(output)}))
