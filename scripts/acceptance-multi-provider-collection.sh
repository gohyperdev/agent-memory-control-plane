#!/usr/bin/env bash
set -euo pipefail

workspace_root=$(cd "$(dirname "$0")/.." && pwd)
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT

result=$(
  cd "$workspace_root"
  AMCP_ENABLE_FUTURE_PROVIDERS=true \
  AMCP_AGENT_STATE_DIR="$temporary_root/agent-state" \
  AMCP_AGENT_BACKUP_DIR="$temporary_root/backups" \
  AMCP_CLAUDE_HOME="$workspace_root/fixtures/claude-code/.claude" \
  AMCP_CLAUDE_PROJECT_ROOTS="$workspace_root/fixtures/claude-code/project" \
  AMCP_KIRO_HOME="$workspace_root/fixtures/kiro/.kiro" \
  AMCP_KIRO_PROJECT_ROOTS="$workspace_root/fixtures/kiro/project" \
  AMCP_ANTIGRAVITY_HOME="$workspace_root/fixtures/antigravity/.gemini/antigravity" \
  AMCP_ANTIGRAVITY_PROJECT_ROOTS="$workspace_root/fixtures/antigravity/project" \
  cargo run -q -p amcp-controller -- run-once \
    --socket "$temporary_root/agent.sock" \
    --db "$temporary_root/catalog.sqlite" \
    --codex-home "$workspace_root/fixtures/codex" \
    --json
)

node -e '
const report = JSON.parse(process.argv[1]);
const expected = ["antigravity", "claude-code", "codex", "kiro"];
const actual = (report.collections || []).map((entry) => entry.provider_id).sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  throw new Error(`expected ${expected.join(", ")}; received ${actual.join(", ")}`);
}
if ((report.failed_providers || []).length !== 0) {
  throw new Error("fixture providers must collect without failures");
}
' "$result"

printf '%s\n' "$result"
