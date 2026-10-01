# AGENTS.md - integrations/hermes/tests/marmot

## Scope

Tests for the Marmot Hermes plugin in `../../marmot` and its installer/helper scripts.

Keep test-only fixtures outside the plugin source directory so Hermes's standard source installer scans and copies only runtime files. Do not move secrets, fake `nsec` values, subprocess harnesses, or workspace files back under the plugin directory.

## Layout

- `test_*.py` - `unittest` suites discovered by the command below. `test_approval_host_contract.py` runs only with
  `HERMES_APPROVAL_CONTRACT=1` and the pinned Hermes source on `PYTHONPATH` (see the plugin README).
- `test_adapter.py` asserts on the plugin README's source-install section; keep the phrase
  "Install through Hermes's standard plugin flow" before `## Release Install` with its fence intact.
- `test_dev_scripts.sh` - dev-script, installer, `hermes-agent.lock` drift, and systemd-service checks.
- `e2e_deterministic.py`, `e2e_connector.py`, `real_hermes_persisted_config.py` - driven by
  `scripts/hermes_marmot_*.sh` through `just hermes-dev-e2e-deterministic`, `just hermes-dev-e2e-connector`, and
  `just hermes-verify-persisted-config`.
- `test_real_hermes_plugin.py` and `verify_packaged_plugin.py` - real-host install and packaged-asset checks used by
  `.github/workflows/wn-agent-binaries.yml`.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/hermes/tests/marmot
integrations/hermes/tests/marmot/test_dev_scripts.sh
python3 integrations/hermes/tests/marmot/test_real_hermes_plugin.py \
  --hermes-source /path/to/hermes-agent \
  --mdk-source . \
  --mdk-ref HEAD
```
