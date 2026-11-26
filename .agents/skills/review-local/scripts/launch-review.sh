#!/usr/bin/env bash
# Run one read-only reviewer seat against a round made by prepare-round.sh.
# The review goes to <out-dir>/<seat>.md, its first line stamped with the seat
# and model, and the CLI's noise to <out-dir>/<seat>.log. Exits with the
# reviewer's exit code.
#
# usage: launch-review.sh <seat> <review-dir> <out-dir>
#
# Redirects and model lookups stay inside this script so the caller's command
# is a bare script path with literal arguments: no pipe, substitution or
# redirect for a permission rule to trip on.
#
# Keep every restriction flag. Without them (checked 2026-10-17/18):
# - Claude without --restricted --tools could write into the checkout, and
#   without --strict-mcp-config still had the user's MCP servers and claude.ai
#   connectors (Drive, Docs, Gmail), which edit or share outside it.
# - Cursor without --sandbox enabled could write into the checkout. Ask mode
#   refuses MCP tools that write.
# - Codex without --ignore-user-config loaded MCP servers from
#   ~/.codex/config.toml, which run outside its read-only sandbox.
# - Antigravity (checked 2026-11-26): without --settings, agy defaults to auto
#   mode (approving workspace edits and sandboxed commands) and uses the user's
#   allow rules and MCP servers. A round-local --settings file sets default mode
#   with request-review, disables non-workspace access, and denies write_file,
#   command, unsandboxed, mcp, read_url and execute_url (deny overrides any user
#   allow rule). --add-dir exposes only the read-only input dir, --sandbox turns
#   on OS containment, and --disable-slash-commands keeps prompt text raw.
# - OpenCode (checked 2026-11-17, under numes): ~/.config/opencode holds
#   the user's MCP servers, custom tools and plugins, so OPENCODE_CONFIG_DIR
#   replaces it with a round-local one whose only agent denies every tool but
#   read, grep and glob. --standalone keeps the run off the background
#   service, which loads the user's config instead.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: launch-review.sh <seat> <review-dir> <out-dir>" >&2
  exit 2
fi

seat=$1
review_dir=$2
out_dir=$3
checkout="$review_dir/$seat"
input="$review_dir/$seat-input"

for path in "$checkout" "$input/prompt.md" "$out_dir"; do
  if [[ ! -e "$path" ]]; then
    echo "missing $path; run prepare-round.sh first" >&2
    exit 2
  fi
done

rc=0
case "$seat" in
  codex)
    model=gpt-6.1-sol
    # --ignore-user-config also drops model_reasoning_effort, leaving effort none.
    codex exec --ignore-user-config -c model_reasoning_effort='"medium"' -s read-only -m "$model" \
      -C "$checkout" -o "$out_dir/codex.md" - \
      < "$input/prompt.md" > "$out_dir/codex.log" 2>&1 || rc=$?
    ;;

  claude)
    # Pin the exact id: the `opus` alias tracks the newest Opus.
    # Use -p (print and exit), never --bg, which leaves a session running.
    model=claude-opus-5-5
    (cd "$checkout" && claude -p --restricted --tools Read Grep Glob --strict-mcp-config \
      --add-dir "$input" --model "$model" --effort medium \
      < "$input/prompt.md") > "$out_dir/claude.md" 2> "$out_dir/claude.log" || rc=$?
    ;;

  antigravity)
    model=gemini-4-neon
    settings_file="$review_dir/antigravity-settings.json"
    cat > "$settings_file" <<'EOF'
{
  "agentMode": "",
  "toolPermission": "request-review",
  "allowNonWorkspaceAccess": false,
  "enableTerminalSandbox": true,
  "permissions": {
    "deny": [
      "write_file(*)",
      "command(*)",
      "unsandboxed(*)",
      "mcp(*)",
      "read_url(*)",
      "execute_url(*)"
    ]
  }
}
EOF
    (cd "$checkout" && agy -p "$(cat "$input/prompt.md")" --model "$model" --effort medium \
      --disable-slash-commands --sandbox --settings "$settings_file" --add-dir "$input" \
      --output-format text) < /dev/null > "$out_dir/antigravity.md" 2> "$out_dir/antigravity.log" || rc=$?
    ;;

  cursor)
    # Cursor names the reasoning level in the model id, not a flag. Newest
    # grok-*-medium-fast (older builds: cursor-grok-*-medium-fast).
    model="$(agent --list-models | awk '
      $1 ~ /^(cursor-)?grok-[0-9.]+-medium-fast$/ {
        ver = $1
        sub(/^(cursor-)?grok-/, "", ver)
        sub(/-medium-fast$/, "", ver)
        print ver "\t" $1
      }
    ' | sort -V | tail -1 | cut -f2)"
    if [[ -z "$model" ]]; then
      echo "no grok-*-medium-fast model from agent --list-models" >&2
      exit 1
    fi
    agent -p --mode ask --sandbox enabled --trust --workspace "$checkout" \
      --add-dir "$input" --model "$model" --output-format text \
      "$(cat "$input/prompt.md")" > "$out_dir/cursor.md" 2> "$out_dir/cursor.log" || rc=$?
    ;;

  opencode)
    # Free Numes models, in order: each later one runs only when the one
    # before it exits nonzero or ends without a VERDICT line (usage limits).
    config_dir="$review_dir/opencode-config"
    mkdir -p "$config_dir"
    cat > "$config_dir/opencode.json" <<EOF
{
  "agents": {
    "review": {
      "description": "Read-only reviewer",
      "mode": "primary",
      "permissions": [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "read", "resource": "*", "effect": "allow"},
        {"action": "grep", "resource": "*", "effect": "allow"},
        {"action": "glob", "resource": "*", "effect": "allow"},
        {"action": "external_directory", "resource": "$input/*", "effect": "allow"}
      ]
    }
  }
}
EOF
    : > "$out_dir/opencode.log"
    # The reasoning level is the #variant (checked 2026-11-20): GLM 5.3 Flash
    # has only low and high, and DeepSeek V4.1 Flash hung on medium while high
    # answered.
    for model in moonshotai/kimi-k3.1-pro:free#medium z-ai/glm-5.3-flash:free#high \
      deepseek/deepseek-v4.1-flash:free#high nvidia/nemotron-3-ultra-550b-a55b:free#high; do
      echo "=== $model" >> "$out_dir/opencode.log"
      rc=0
      (cd "$checkout" && OPENCODE_CONFIG_DIR="$config_dir" OPENCODE_DISABLE_PROJECT_CONFIG=1 \
        OPENCODE_DISABLE_CLAUDE_CODE=1 numes run opencode run --standalone --agent review \
        -m "numes/$model" "$(cat "$input/prompt.md")") \
        < /dev/null > "$out_dir/opencode.md" 2>> "$out_dir/opencode.log" || rc=$?
      if [[ $rc -eq 0 ]] && grep -v '^[[:space:]]*$' "$out_dir/opencode.md" | tail -1 |
        grep -qE '^[[:space:]]*VERDICT: (merge|changes-needed)[[:space:]]*$'; then
        break
      fi
      echo "=== $model failed (exit $rc or no VERDICT line)" >> "$out_dir/opencode.log"
    done
    ;;

  *)
    echo "unknown seat: $seat (want codex, claude, antigravity, cursor or opencode)" >&2
    exit 2
    ;;
esac

# Stamp the seat and model on the review. The verdict stays the last line.
review="$out_dir/$seat.md"
if [[ -f "$review" ]]; then
  stamped="$(mktemp "$out_dir/.$seat.XXXXXX")"
  # shellcheck disable=SC2016  # the backticks are literal Markdown
  { printf 'Reviewer: %s seat, model `%s`\n\n' "$seat" "$model"; cat "$review"; } > "$stamped"
  mv "$stamped" "$review"
fi
exit "$rc"
