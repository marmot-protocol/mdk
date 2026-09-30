#!/usr/bin/env bash
# Runs the per-test scenario body from the invocation working directory. Tests
# write that body as plain data instead of a fresh executable, so a concurrent
# fork elsewhere in the test binary cannot make exec fail with ETXTBSY.
exec bash ./opencode-scenario.sh "$@"
