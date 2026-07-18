#!/bin/sh
# End-to-end acceptance for the Controller → Agent safe-change workflow.
# It only changes a copied fixture under /tmp and retains that directory for
# inspection. No user Codex state or repository file is touched.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this acceptance script" >&2
  exit 1
fi

cargo build --bin amcp-agent --bin amcp-controller >/dev/null

acceptance_dir=$(mktemp -d /tmp/amcp-safe-change.XXXXXX)
cp -R fixtures/codex "$acceptance_dir/codex"
cp "$acceptance_dir/codex/AGENTS.md" "$acceptance_dir/replacement.md"

export AMCP_HOST_ID=amcp-safe-change
export AMCP_AGENT_STATE_DIR="$acceptance_dir/agent-state"
export AMCP_AGENT_BACKUP_DIR="$acceptance_dir/backups"

proposal=$(target/debug/amcp-controller propose-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --source "$acceptance_dir/codex/AGENTS.md" \
  --replacement-file "$acceptance_dir/replacement.md" \
  --reason "isolated safe-change acceptance verification" \
  --host-id amcp-safe-change \
  --json)
change_set_id=$(printf '%s' "$proposal" | jq -r '.change_set_id')

if [ -z "$change_set_id" ] || [ "$change_set_id" = "null" ]; then
  echo "Controller did not return a change set identifier" >&2
  exit 1
fi

apply=$(target/debug/amcp-controller approve-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --change-set-id "$change_set_id" \
  --approved-by acceptance-test \
  --json)
rollback=$(target/debug/amcp-controller rollback-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --change-set-id "$change_set_id" \
  --approved-by acceptance-test \
  --json)

apply_status=$(printf '%s' "$apply" | jq -r '.status')
rollback_status=$(printf '%s' "$rollback" | jq -r '.status')
apply_backups=$(printf '%s' "$apply" | jq '.backup_references | length')
rollback_backups=$(printf '%s' "$rollback" | jq '.backup_references | length')

[ "$apply_status" = "Applied" ]
[ "$rollback_status" = "RolledBack" ]
[ "$apply_backups" -ge 1 ]
[ "$rollback_backups" -ge 1 ]

# Root-level Codex profiles are discovered configuration layers and use the
# same TOML validation, approval, backup and rollback workflow as config.toml.
profile_source="$acceptance_dir/codex/review.config.toml"
profile_replacement="$acceptance_dir/review-replacement.config.toml"
printf 'model = "gpt-profile-before"\n' >"$profile_source"
printf 'model = "gpt-profile-after"\n' >"$profile_replacement"
profile_proposal=$(target/debug/amcp-controller propose-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --source "$profile_source" \
  --replacement-file "$profile_replacement" \
  --reason "profile safe-change acceptance verification" \
  --host-id amcp-safe-change \
  --json)
profile_change_set_id=$(printf '%s' "$profile_proposal" | jq -r '.change_set_id')
[ -n "$profile_change_set_id" ]
[ "$profile_change_set_id" != "null" ]
profile_apply=$(target/debug/amcp-controller approve-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --change-set-id "$profile_change_set_id" \
  --approved-by acceptance-test \
  --json)
profile_rollback=$(target/debug/amcp-controller rollback-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --change-set-id "$profile_change_set_id" \
  --approved-by acceptance-test \
  --json)
[ "$(printf '%s' "$profile_apply" | jq -r '.status')" = "Applied" ]
[ "$(printf '%s' "$profile_rollback" | jq -r '.status')" = "RolledBack" ]
[ "$(cat "$profile_source")" = "model = \"gpt-profile-before\"" ]

conflict_proposal=$(target/debug/amcp-controller propose-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --source "$acceptance_dir/codex/AGENTS.md" \
  --replacement-file "$acceptance_dir/replacement.md" \
  --reason "external-edit conflict acceptance verification" \
  --host-id amcp-safe-change \
  --json)
conflict_change_set_id=$(printf '%s' "$conflict_proposal" | jq -r '.change_set_id')

if [ -z "$conflict_change_set_id" ] || [ "$conflict_change_set_id" = "null" ]; then
  echo "Controller did not return a conflict-test change set identifier" >&2
  exit 1
fi

# Simulate a user/editor changing the native source after proposal. The Agent
# must refuse to overwrite this copied fixture when approval is later applied.
printf '\n# external edit after AMCP proposal\n' >>"$acceptance_dir/codex/AGENTS.md"
conflict_apply=$(target/debug/amcp-controller approve-change \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$acceptance_dir/codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$repo_root/target/debug/amcp-agent" \
  --change-set-id "$conflict_change_set_id" \
  --approved-by acceptance-test \
  --json)
conflict_status=$(printf '%s' "$conflict_apply" | jq -r '.status')

[ "$conflict_status" = "Conflict" ]

printf 'safe change acceptance passed\n'
printf 'temporary evidence directory: %s\n' "$acceptance_dir"
printf 'config apply: %s with %s backup(s); rollback: %s with %s backup(s); profile: Applied/RolledBack; external edit: %s\n' \
  "$apply_status" "$apply_backups" "$rollback_status" "$rollback_backups" "$conflict_status"
