#!/bin/sh
# Exercises Controller restart, bounded FTS rebuild, and recovery into a fresh
# central catalog. It uses only a copied fixture and a temporary Agent state.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this acceptance script" >&2
  exit 1
fi

cargo build --bin amcp-agent --bin amcp-controller >/dev/null

acceptance_dir=$(mktemp -d /tmp/amcp-recovery.XXXXXX)
cp -R fixtures/codex "$acceptance_dir/codex"

export AMCP_HOST_ID=amcp-recovery
export AMCP_AGENT_STATE_DIR="$acceptance_dir/agent-state"
export AMCP_AGENT_BACKUP_DIR="$acceptance_dir/backups"

run_collection() {
  database=$1
  target/debug/amcp-controller run-once \
    --socket "$acceptance_dir/agent.sock" \
    --codex-home "$acceptance_dir/codex" \
    --db "$database" \
    --agent-bin "$repo_root/target/debug/amcp-agent" \
    --query fixture \
    --json
}

first_database="$acceptance_dir/controller.sqlite"
first=$(run_collection "$first_database")
catalog_backup=$(target/debug/amcp-controller backup \
  --db "$first_database" \
  --reason recovery-acceptance \
  --json)
catalog_backup_path=$(printf '%s' "$catalog_backup" | jq -r '.backup_path')
catalog_backup_diagnostics=$(target/debug/amcp-controller diagnostics \
  --db "$catalog_backup_path" \
  --json)
local_search=$(target/debug/amcp-controller local-search \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --host-id amcp-recovery \
  --json \
  fixture)
second=$(run_collection "$first_database")
rebuild=$(target/debug/amcp-controller rebuild-index \
  --db "$first_database" \
  --batch-size 1 \
  --json)
recovered=$(run_collection "$acceptance_dir/recovered-controller.sqlite")
recovered_diagnostics=$(target/debug/amcp-controller diagnostics \
  --db "$acceptance_dir/recovered-controller.sqlite" \
  --json)

first_discovered=$(printf '%s' "$first" | jq -r '.discovered')
first_inserted=$(printf '%s' "$first" | jq -r '.inserted')
catalog_backup_artifacts=$(printf '%s' "$catalog_backup_diagnostics" | jq -r '.catalog_diagnostics.total_artifact_count')
local_search_count=$(printf '%s' "$local_search" | jq '.results | length')
local_cache_available=$(printf '%s' "$local_search" | jq -r '.cache_available')
local_search_redacted=$(printf '%s' "$local_search" | jq -r '.redacted')
local_search_native_files_opened=$(printf '%s' "$local_search" | jq -r '.native_files_opened')
second_inserted=$(printf '%s' "$second" | jq -r '.inserted')
rebuild_status=$(printf '%s' "$rebuild" | jq -r '.status')
rebuild_indexed=$(printf '%s' "$rebuild" | jq -r '.indexed_count')
recovered_inserted=$(printf '%s' "$recovered" | jq -r '.inserted')
recovered_search=$(printf '%s' "$recovered" | jq '.search | length')
replayed_metric_count=$(printf '%s' "$recovered_diagnostics" | jq '[.recent_collection_runs[] | select(.status == "replayed")] | length')
completed_metric_count=$(printf '%s' "$recovered_diagnostics" | jq '[.recent_collection_runs[] | select(.status == "completed")] | length')
diagnostics_content_included=$(printf '%s' "$recovered_diagnostics" | jq -r '.content_included')

[ "$first_discovered" -gt 0 ]
[ "$first_inserted" -gt 0 ]
[ -f "$catalog_backup_path" ]
[ "$catalog_backup_artifacts" -eq "$first_inserted" ]
[ "$local_search_count" -gt 0 ]
[ "$local_cache_available" = "true" ]
[ "$local_search_redacted" = "true" ]
[ "$local_search_native_files_opened" = "false" ]
[ "$second_inserted" -eq 0 ]
[ "$rebuild_status" = "completed" ]
[ "$rebuild_indexed" -gt 0 ]
[ "$recovered_inserted" -gt 0 ]
[ "$recovered_search" -gt 0 ]
[ "$replayed_metric_count" -gt 0 ]
[ "$completed_metric_count" -gt 0 ]
[ "$diagnostics_content_included" = "false" ]

printf 'recovery acceptance passed\n'
printf 'temporary evidence directory: %s\n' "$acceptance_dir"
printf 'first insert=%s; local cache hits=%s; restart insert=%s; recovery insert=%s; rebuilt=%s; replay metrics=%s\n' \
  "$first_inserted" "$local_search_count" "$second_inserted" "$recovered_inserted" "$rebuild_indexed" "$replayed_metric_count"
