#!/bin/sh
# Verifies that the Controller's human-search path and the MCP search tool
# return the same source-linked evidence from one central catalog. It uses a
# copied Codex fixture and a temporary catalog only.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this acceptance script" >&2
  exit 1
fi

cargo build --bin amcp-agent --bin amcp-controller --bin amcp-mcp >/dev/null

acceptance_dir=$(mktemp -d /tmp/amcp-shared-search.XXXXXX)
cp -R fixtures/codex "$acceptance_dir/codex"

export AMCP_HOST_ID=amcp-shared-search
export AMCP_AGENT_STATE_DIR="$acceptance_dir/agent-state"
export AMCP_AGENT_BACKUP_DIR="$acceptance_dir/backups"

controller_result=$(target/debug/amcp-controller run-once \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --query fixture \
  --json)
controller_source=$(printf '%s' "$controller_result" | jq -r '.search[0].source')
controller_preview=$(printf '%s' "$controller_result" | jq -r '.search[0].preview')

if [ -z "$controller_source" ] || [ "$controller_source" = "null" ]; then
  echo "Controller search did not return source-linked evidence" >&2
  exit 1
fi

mcp_result=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"amcp_search","arguments":{"query":"fixture","limit":20,"scope":{"host_id":"amcp-shared-search","provider_id":"codex"}}}}' \
  | target/debug/amcp-mcp --db "$acceptance_dir/controller.sqlite")
mcp_source=$(printf '%s' "$mcp_result" | jq -r '.result.structuredContent.data.results[0].source_reference')
mcp_preview=$(printf '%s' "$mcp_result" | jq -r '.result.structuredContent.data.results[0].preview')
mcp_citation=$(printf '%s' "$mcp_result" | jq -r '.result.structuredContent.data.results[0].citation')
mcp_status=$(printf '%s' "$mcp_result" | jq -r '.result.structuredContent.result_status')
no_match_result=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"amcp_search","arguments":{"query":"amcpnevermatch","limit":20,"scope":{"host_id":"amcp-shared-search","provider_id":"codex"}}}}' \
  | target/debug/amcp-mcp --db "$acceptance_dir/controller.sqlite")
no_match_status=$(printf '%s' "$no_match_result" | jq -r '.result.structuredContent.result_status')

[ "$mcp_source" = "$controller_source" ]
[ "$mcp_preview" = "$controller_preview" ]
[ "${mcp_citation#"$mcp_source"#}" != "$mcp_citation" ]
[ "$mcp_status" = "ok" ]
[ "$no_match_status" = "not_found" ]

printf 'shared Controller/MCP search acceptance passed\n'
printf 'temporary evidence directory: %s\n' "$acceptance_dir"
printf 'source: %s\n' "$mcp_source"
