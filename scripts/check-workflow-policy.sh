#!/usr/bin/env bash
set -euo pipefail

if ! command -v ruby >/dev/null 2>&1; then
  echo "Error: Ruby is required to parse GitHub workflow YAML for policy checks." >&2
  exit 1
fi

ruby <<'RUBY'
require "yaml"

workflow_path = ".github/workflows/package-mdk-bindings.yml"
workflow = YAML.load_file(workflow_path, aliases: true)
trigger = workflow.fetch("on") { workflow.fetch(true) { abort "#{workflow_path}: missing on trigger" } }
push = trigger.fetch("push") { abort "#{workflow_path}: missing push trigger" }

allowed_branches = ["master"]
branches = Array(push.fetch("branches") { abort "#{workflow_path}: missing push.branches trigger" }).map(&:to_s)
unless branches == allowed_branches
  abort "#{workflow_path}: push.branches must be #{allowed_branches.inspect}, got #{branches.inspect}"
end

tags = Array(push.fetch("tags") { abort "#{workflow_path}: missing push.tags trigger" }).map(&:to_s)
unless tags == ["v*"]
  abort "#{workflow_path}: push.tags must stay limited to [\"v*\"], got #{tags.inspect}"
end

puts "Package workflow policy OK"
RUBY
