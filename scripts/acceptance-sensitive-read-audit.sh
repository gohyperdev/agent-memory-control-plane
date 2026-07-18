#!/bin/sh
# Verifies that a redacted sensitive live read creates a content-free audit
# entry in the same Controller catalog used by the request.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

for dependency in jq sqlite3; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    echo "$dependency is required for this acceptance script" >&2
    exit 1
  fi
done

cargo build --bin amcp-agent --bin amcp-controller --bin amcp-mcp >/dev/null

acceptance_dir=$(mktemp -d /tmp/amcp-sensitive-read.XXXXXX)
cp -R fixtures/codex "$acceptance_dir/codex"

export AMCP_HOST_ID=amcp-sensitive-read
export AMCP_AGENT_STATE_DIR="$acceptance_dir/agent-state"
export AMCP_AGENT_BACKUP_DIR="$acceptance_dir/backups"

source="$acceptance_dir/codex/config.toml"
target/debug/amcp-controller run-once \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --query gpt \
  --json > "$acceptance_dir/collection.json"
target/debug/amcp-controller read-artifact \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --source "$source" \
  --json > "$acceptance_dir/artifact.json"

# The fixture's API-key-shaped value must be redacted before it can return.
jq -e '.sensitivity == "Sensitive" and (.content | contains("[REDACTED]"))' \
  "$acceptance_dir/artifact.json" >/dev/null
observed_source=$(jq -r '.source_reference' "$acceptance_dir/artifact.json")
target/debug/amcp-controller search \
  --db "$acceptance_dir/controller.sqlite" \
  gpt >/dev/null

sqlite3 "$acceptance_dir/controller.sqlite" \
  "SELECT operation || '|' || result || '|' || target FROM audit_events;" \
  | awk -F'|' -v expected="$observed_source" '
      $1 == "artifact.read_sensitive" &&
      $2 == "redacted artifact returned" &&
      $3 == expected { found = 1 }
      END { exit(found ? 0 : 1) }
    '

controller_audit=$(target/debug/amcp-controller audit-list \
  --db "$acceptance_dir/controller.sqlite" \
  --host-id amcp-sensitive-read \
  --provider-id codex \
  --limit 5 \
  --json)
printf '%s' "$controller_audit" | jq -e --arg source "$observed_source" '
  any(.[]; .operation == "artifact.read_sensitive" and .target == $source and .result == "redacted artifact returned")
' >/dev/null
printf '%s' "$controller_audit" | jq -e --arg source "$observed_source" '
  any(.[]; .operation == "catalog.search_sensitive" and .actor == "controller.run_once" and .target == $source and .result == "redacted catalog search result") and
  any(.[]; .operation == "catalog.search_sensitive" and .actor == "controller.cli" and .target == $source and .result == "redacted catalog search result")
' >/dev/null

mcp_search=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amcp_search","arguments":{"query":"gpt","limit":5,"scope":{"host_id":"amcp-sensitive-read","provider_id":"codex"}}}}' \
  | target/debug/amcp-mcp --db "$acceptance_dir/controller.sqlite")
printf '%s' "$mcp_search" | jq -e --arg source "$observed_source" '
  any(.result.structuredContent.data.results[]; .source_reference == $source and .sensitivity == "Sensitive")
' >/dev/null

mcp_audit=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amcp_audit_events_list","arguments":{"host_id":"amcp-sensitive-read","provider_id":"codex","limit":5}}}' \
  | target/debug/amcp-mcp --db "$acceptance_dir/controller.sqlite")
printf '%s' "$mcp_audit" | jq -e --arg source "$observed_source" '
  any(.result.structuredContent.data.audit_events[]; .operation == "artifact.read_sensitive" and .target == $source and .result == "redacted artifact returned") and
  any(.result.structuredContent.data.audit_events[]; .operation == "catalog.search_sensitive" and .actor == "mcp.search" and .target == $source and .result == "redacted catalog search result")
' >/dev/null

printf 'sensitive live-read audit acceptance passed\n'
printf 'temporary evidence directory: %s\n' "$acceptance_dir"
