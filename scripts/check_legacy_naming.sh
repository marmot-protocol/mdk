#!/usr/bin/env bash
set -euo pipefail

# Naming regression gate for the darkmatter -> mdk/wn rename (PR #725).
#
# Fails if retired "darkmatter"-era tokens reappear outside the documented
# exceptions. Direct-message semantics ("dm" config keys, "effective DM"
# prose, is_dm fields, MARMOT_DM_ALLOW_FROM) are intentionally allowed.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Historical records keep their original wording; this script matches itself.
HISTORY_EXCLUDES=(
    --glob '!Cargo.lock'
    --glob '!docs/learnings.md'
    --glob '!crates/cli/CHANGELOG.md'
    --glob '!scripts/check_legacy_naming.sh'
)

fail=0

report() {
    echo "error: retired naming found ($1):" >&2
    echo "$2" >&2
    fail=1
}

# One-word and two-word project-name forms, any case.
if hits="$(rg --hidden --glob '!.git' -n -i 'dark[- ]?matter' "${HISTORY_EXCLUDES[@]}" . 2>/dev/null)" && [ -n "$hits" ]; then
    report 'darkmatter / dark matter' "$hits"
fi

# Retired binary/artifact tokens. No legitimate uses remain anywhere.
if hits="$(rg --hidden --glob '!.git' -n '\bdmd\b|dm-agent|dm_agent|\bDM Agent\b|\bDM_[A-Z]' "${HISTORY_EXCLUDES[@]}" . 2>/dev/null)" && [ -n "$hits" ]; then
    report 'dmd / dm-agent / DM_* tokens' "$hits"
fi

# Bare "dm" word (the retired CLI binary). Excluded under integrations/,
# where standalone `dm` keys mean direct-message config (dm.allowFrom).
if hits="$(rg --hidden --glob '!.git' -n '\bdm\b' "${HISTORY_EXCLUDES[@]}" --glob '!integrations/**' . 2>/dev/null)" && [ -n "$hits" ]; then
    report 'bare dm word' "$hits"
fi

# Retired Rust identifier prefix (DmError, DmClient, ...).
if hits="$(rg -n '\bDm[A-Z]' crates/ 2>/dev/null)" && [ -n "$hits" ]; then
    report 'Dm-prefixed identifiers' "$hits"
fi

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo 'See the rename conventions in crates/cli/CHANGELOG.md (Unreleased) and PR #725.' >&2
    exit 1
fi

echo 'naming gate: clean'
