#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/hermes_marmot_dev_setup.sh [options]

Creates an isolated Hermes development checkout/home for testing the Marmot
Hermes plugin. Defaults keep all mutable state under /tmp/hermes-marmot-test.

Options:
  --root PATH              Dev root (default: ${TMPDIR:-/tmp}/hermes-marmot-test)
  --marmot-home PATH       Marmot/dm-agent home (default: ROOT/marmot-agent-home)
  --hermes-url URL         Hermes repo URL (default: https://github.com/NousResearch/hermes-agent.git)
  --hermes-ref REF         Optional branch, tag, or commit to checkout
  --account-id-hex HEX     Export MARMOT_ACCOUNT_ID_HEX in env.sh
  --group-id-hex HEX       Export MARMOT_GROUP_ID_HEX in env.sh
  --relay URL              Add a dm-agent --relay argument; may be repeated
  --quic-candidate URI     Add a MARMOT_QUIC_CANDIDATES entry; may be repeated
  --quic-candidates CSV    Comma-separated MARMOT_QUIC_CANDIDATES value
  --skip-hermes-install    Create dirs, env, plugin symlink, and helpers only
  --no-enable-plugin       Do not run "hermes plugins enable marmot"
  --install-uv             Install uv with Astral's installer if uv is missing
  --force                  Replace an existing non-symlink plugin path
  --print-env              Print the source command and helper paths at the end
  -h, --help               Show this help

After setup:
  source ROOT/env.sh
  ROOT/smoke-plugin.sh
  ROOT/e2e-deterministic.sh
  ROOT/e2e-connector.sh
  ROOT/run-dm-agent.sh [extra dm-agent flags]
  ROOT/run-hermes-gateway.sh [extra Hermes gateway flags]

USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
default_tmp="${TMPDIR:-/tmp}"
dev_root="${HERMES_MARMOT_DEV_ROOT:-${default_tmp%/}/hermes-marmot-test}"
hermes_url="${HERMES_AGENT_REPO_URL:-https://github.com/NousResearch/hermes-agent.git}"
hermes_ref="${HERMES_AGENT_REF:-}"
marmot_home=""
account_id="${MARMOT_ACCOUNT_ID_HEX:-}"
group_id="${MARMOT_GROUP_ID_HEX:-}"
skip_hermes_install=0
enable_plugin=1
install_uv=0
force=0
print_env=0
relays=()
quic_candidates=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            dev_root="$2"
            shift 2
            ;;
        --marmot-home)
            marmot_home="$2"
            shift 2
            ;;
        --hermes-url)
            hermes_url="$2"
            shift 2
            ;;
        --hermes-ref)
            hermes_ref="$2"
            shift 2
            ;;
        --account-id-hex)
            account_id="$2"
            shift 2
            ;;
        --group-id-hex)
            group_id="$2"
            shift 2
            ;;
        --relay)
            relays+=("$2")
            shift 2
            ;;
        --quic-candidate)
            quic_candidates+=("$2")
            shift 2
            ;;
        --quic-candidates)
            IFS=',' read -r -a parsed_candidates <<<"$2"
            for candidate in "${parsed_candidates[@]}"; do
                candidate="${candidate#"${candidate%%[![:space:]]*}"}"
                candidate="${candidate%"${candidate##*[![:space:]]}"}"
                [ -z "$candidate" ] || quic_candidates+=("$candidate")
            done
            shift 2
            ;;
        --skip-hermes-install)
            skip_hermes_install=1
            shift
            ;;
        --no-enable-plugin)
            enable_plugin=0
            shift
            ;;
        --install-uv)
            install_uv=1
            shift
            ;;
        --force)
            force=1
            shift
            ;;
        --print-env)
            print_env=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

dev_parent="$(dirname "$dev_root")"
dev_base="$(basename "$dev_root")"
mkdir -p "$dev_parent"
dev_root="$(cd "$dev_parent" && pwd)/$dev_base"
hermes_repo="$dev_root/hermes-agent"
hermes_home="$dev_root/hermes-home"
marmot_home="${marmot_home:-$dev_root/marmot-agent-home}"
plugin_source="$repo_root/integrations/hermes/marmot"
plugin_target="$hermes_home/plugins/marmot"
env_file="$dev_root/env.sh"

if [ ! -d "$plugin_source" ]; then
    echo "error: Marmot Hermes plugin not found at $plugin_source" >&2
    exit 1
fi

mkdir -p "$dev_root" "$hermes_home/plugins" "$marmot_home/dev" "$dev_root/logs"

if [ -e "$plugin_target" ] && [ ! -L "$plugin_target" ]; then
    if [ "$force" -ne 1 ]; then
        echo "error: $plugin_target exists and is not a symlink; rerun with --force to replace it" >&2
        exit 1
    fi
    rm -rf "$plugin_target"
fi
ln -sfn "$plugin_source" "$plugin_target"

ensure_uv() {
    if command -v uv >/dev/null 2>&1; then
        return 0
    fi
    if [ "$install_uv" -ne 1 ]; then
        return 1
    fi
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    command -v uv >/dev/null 2>&1
}

install_hermes() {
    if [ ! -d "$hermes_repo/.git" ]; then
        git clone "$hermes_url" "$hermes_repo"
    fi

    if [ -n "$hermes_ref" ]; then
        git -C "$hermes_repo" fetch origin "$hermes_ref" || true
        git -C "$hermes_repo" checkout "$hermes_ref"
    fi

    if ensure_uv; then
        (
            cd "$hermes_repo"
            uv venv .venv --python 3.11
            uv pip install -e ".[all,dev]"
        )
        return 0
    fi

    if command -v python3.11 >/dev/null 2>&1; then
        (
            cd "$hermes_repo"
            python3.11 -m venv .venv
            . .venv/bin/activate
            python -m pip install --upgrade pip
            python -m pip install -e ".[all,dev]"
        )
        return 0
    fi

    cat >&2 <<'ERROR'
error: need either uv or python3.11 to create the isolated Hermes venv.
Install uv, or rerun this script with --install-uv.
ERROR
    exit 1
}

write_env_file() {
    local quic_csv=""
    local candidate
    if [ "${#quic_candidates[@]}" -gt 0 ]; then
        for candidate in "${quic_candidates[@]}"; do
            if [ -z "$quic_csv" ]; then
                quic_csv="$candidate"
            else
                quic_csv="$quic_csv,$candidate"
            fi
        done
    fi

    {
        echo "# Generated by scripts/hermes_marmot_dev_setup.sh"
        echo "# shellcheck shell=bash"
        printf 'export HERMES_MARMOT_DEV_ROOT=%q\n' "$dev_root"
        printf 'export DARKMATTER_REPO=%q\n' "$repo_root"
        printf 'export HERMES_AGENT_REPO=%q\n' "$hermes_repo"
        printf 'export HERMES_HOME=%q\n' "$hermes_home"
        printf 'export MARMOT_HOME=%q\n' "$marmot_home"
        printf 'export MARMOT_AGENT_SOCKET=%q\n' "$marmot_home/dev/dm-agent.sock"
        printf 'export MARMOT_ACCOUNT_ID_HEX=%q\n' "$account_id"
        printf 'export MARMOT_GROUP_ID_HEX=%q\n' "$group_id"
        printf 'export MARMOT_QUIC_CANDIDATES=%q\n' "$quic_csv"
        printf 'export PATH=%q:"$PATH"\n' "$hermes_repo/.venv/bin"
        echo 'dm_agent_relay_args=('
        local relay
        if [ "${#relays[@]}" -gt 0 ]; then
            for relay in "${relays[@]}"; do
                printf '  %q\n' "--relay"
                printf '  %q\n' "$relay"
            done
        fi
        echo ')'
    } >"$env_file"
}

write_helper_scripts() {
    cat >"$dev_root/run-dm-agent.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
cd "$DARKMATTER_REPO"
exec cargo run -p agent-connector --bin dm-agent -- --home "$MARMOT_HOME" "${dm_agent_relay_args[@]}" "$@"
SCRIPT

    cat >"$dev_root/run-hermes-gateway.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
cd "$HERMES_AGENT_REPO"
if [ -x .venv/bin/hermes ]; then
    exec .venv/bin/hermes gateway run "$@"
fi
if [ -x ./hermes ]; then
    exec ./hermes gateway run "$@"
fi
echo "error: Hermes launcher not found. Rerun setup without --skip-hermes-install." >&2
exit 1
SCRIPT

    cat >"$dev_root/smoke-plugin.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"

if [ -x "$HERMES_AGENT_REPO/.venv/bin/python" ]; then
    python_bin="$HERMES_AGENT_REPO/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
else
    echo "error: python3 not found" >&2
    exit 1
fi

cd "$HERMES_AGENT_REPO"
export PYTHONDONTWRITEBYTECODE=1
"$python_bin" - <<'PY'
import importlib.util
import os
from pathlib import Path

plugin = Path(os.environ["HERMES_HOME"]) / "plugins" / "marmot" / "adapter.py"
if not plugin.exists():
    raise SystemExit(f"plugin not found: {plugin}")

spec = importlib.util.spec_from_file_location("marmot_hermes_adapter", plugin)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

print("plugin:", plugin)
print("check_requirements:", module.check_requirements())
print("socket:", module.resolve_socket_path({}))
PY
SCRIPT

    cat >"$dev_root/e2e-deterministic.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dev_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$dev_root/env.sh"
exec "$DARKMATTER_REPO/scripts/hermes_marmot_deterministic_e2e.sh" --root "$dev_root"
SCRIPT

    cat >"$dev_root/e2e-connector.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dev_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$dev_root/env.sh"
exec "$DARKMATTER_REPO/scripts/hermes_marmot_connector_e2e.sh" --root "$dev_root"
SCRIPT

    cat >"$dev_root/start-dm-agent.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dev_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pid_file="$dev_root/dm-agent.pid"
if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "dm-agent already running: $(cat "$pid_file")"
    exit 0
fi
nohup "$dev_root/run-dm-agent.sh" "$@" >"$dev_root/logs/dm-agent.log" 2>&1 &
echo "$!" >"$pid_file"
echo "dm-agent pid: $(cat "$pid_file")"
echo "log: $dev_root/logs/dm-agent.log"
SCRIPT

    cat >"$dev_root/start-hermes-gateway.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dev_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pid_file="$dev_root/hermes-gateway.pid"
if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "Hermes gateway already running: $(cat "$pid_file")"
    exit 0
fi
nohup "$dev_root/run-hermes-gateway.sh" "$@" >"$dev_root/logs/hermes-gateway.log" 2>&1 &
echo "$!" >"$pid_file"
echo "Hermes gateway pid: $(cat "$pid_file")"
echo "log: $dev_root/logs/hermes-gateway.log"
SCRIPT

    cat >"$dev_root/stop-dev-processes.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dev_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for name in hermes-gateway dm-agent; do
    pid_file="$dev_root/$name.pid"
    if [ ! -f "$pid_file" ]; then
        continue
    fi
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        echo "stopped $name pid $pid"
    fi
    rm -f "$pid_file"
done
SCRIPT

    chmod +x \
        "$dev_root/run-dm-agent.sh" \
        "$dev_root/run-hermes-gateway.sh" \
        "$dev_root/smoke-plugin.sh" \
        "$dev_root/e2e-deterministic.sh" \
        "$dev_root/e2e-connector.sh" \
        "$dev_root/start-dm-agent.sh" \
        "$dev_root/start-hermes-gateway.sh" \
        "$dev_root/stop-dev-processes.sh"
}

enable_hermes_plugin() {
    if [ "$skip_hermes_install" -eq 1 ] || [ "$enable_plugin" -ne 1 ]; then
        return 0
    fi
    if [ ! -x "$hermes_repo/.venv/bin/hermes" ]; then
        echo "warning: Hermes launcher not found; skipping plugin enable" >&2
        return 0
    fi
    (
        export HERMES_HOME="$hermes_home"
        export MARMOT_HOME="$marmot_home"
        export MARMOT_AGENT_SOCKET="$marmot_home/dev/dm-agent.sock"
        cd "$hermes_repo"
        .venv/bin/hermes plugins enable marmot
    )
}

if [ "$skip_hermes_install" -ne 1 ]; then
    install_hermes
fi

write_env_file
write_helper_scripts
enable_hermes_plugin

echo "Hermes Marmot dev root: $dev_root"
echo "Hermes home: $hermes_home"
echo "Marmot home: $marmot_home"
echo "Plugin symlink: $plugin_target -> $plugin_source"

if [ "$skip_hermes_install" -eq 1 ]; then
    echo "Hermes install skipped. Rerun without --skip-hermes-install to clone/install Hermes."
fi

if [ "$print_env" -eq 1 ]; then
    echo
    echo "Next commands:"
    echo "  source $(printf '%q' "$env_file")"
    echo "  $(printf '%q' "$dev_root/smoke-plugin.sh")"
    echo "  $(printf '%q' "$dev_root/e2e-deterministic.sh")"
    echo "  $(printf '%q' "$dev_root/e2e-connector.sh")"
    echo "  $(printf '%q' "$dev_root/run-dm-agent.sh")"
    echo "  $(printf '%q' "$dev_root/run-hermes-gateway.sh")"
    echo "  scripts/hermes_marmot_dev_teardown.sh --root $(printf '%q' "$dev_root") --force"
fi
