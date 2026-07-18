# AMCP production acceptance runbook

This runbook turns the remaining Definition-of-Done evidence into explicit,
repeatable checks. A green fixture test does not prove a real host, production
Codex state, signing identity, or operating-system lifecycle.

Do not save tokens, pairing codes, private source contents, transcript
screenshots, or raw terminal output in the acceptance record. Keep only bounded
JSON receipts, pass/fail results, versions, and timestamps.

## 1. Real local Codex collection

Select at least five existing project roots that may be read. Adding a root
does not grant change permission and collection does not alter the project.

```bash
cargo build --bin amcp-agent --bin amcp-controller
acceptance_dir=$(mktemp -d /tmp/amcp-real-codex.XXXXXX)
export AMCP_HOST_ID=amcp-production-local
export AMCP_AGENT_STATE_DIR="$acceptance_dir/agent-state"
export AMCP_AGENT_BACKUP_DIR="$acceptance_dir/backups"
export AMCP_SCAN_ROOTS="/absolute/project-one:/absolute/project-two:/absolute/project-three:/absolute/project-four:/absolute/project-five"

cargo run -p amcp-controller -- run-once \
  --socket "$acceptance_dir/agent.sock" \
  --codex-home "$HOME/.codex" \
  --db "$acceptance_dir/controller.sqlite" \
  --agent-bin "$PWD/target/debug/amcp-agent" \
  --query codex --json

cargo run -p amcp-controller -- diagnostics \
  --db "$acceptance_dir/controller.sqlite" --json

cargo run -p amcp-controller -- readiness \
  --db "$acceptance_dir/controller.sqlite" --assert-local-codex --json
```

Accept when the response has one healthy Codex provider, five or more distinct
normalized projects, non-zero artifacts, no unexpected parser degradation, and
FTS coverage of 100%. Record only counts and provider/adapter versions.
Re-run this check after a material Codex CLI or state-format upgrade.

## 2. Search and RAG quality

The first-release lexical target is p95 below 300 ms. Measure it against the
catalog created above, then repeat it when the catalog has representative data.

```bash
cargo run -p amcp-controller -- benchmark-search \
  --db "$acceptance_dir/controller.sqlite" --iterations 25 --warmup 3 \
  --assert-p95-ms 300 --json codex
```

The small local smoke catalog is a baseline only. To establish a real RAG
quality gate, create a redacted JSON corpus using the shape of
`fixtures/rag/retrieval-evaluation.json`, with representative scope boundaries,
expected citations, and forbidden/stale records. Then run:

```bash
cargo run -p amcp-controller -- rag-evaluate \
  --fixture /absolute/path/to/redacted-rag-evaluation.json \
  --min-citation-coverage-bps 9500 \
  --min-expected-recall-bps 9000 \
  --max-forbidden-record-hits 0 --assert-targets --json
```

The example thresholds are a starting point, not a product assertion. Approve
the final thresholds and corpus ownership before enabling RAG in regular use.
`rag-evaluate` does not read provider files, write retrieval history, enable
RAG, or make network requests.

## 3. Human-reviewed mutation on a real permitted source

This is the only acceptance step that intentionally changes a native source.
Do it only after a human has selected a harmless, permitted v1 file in an
explicitly trusted project: `AGENTS.md`, `AGENTS.override.md`, `config.toml`,
or a root-level Codex `*.config.toml` profile. Do not choose `auth.json`, a
session JSONL file, generated state, or a file outside the registered roots.

1. Read the source and prepare a harmless replacement in a temporary file.
   Review the diff manually.
2. Use the Desktop or `propose-change`; verify source hash, diff, evidence,
   target path, and project trust state.
3. Approve and apply it once. Verify the backup reference and post-write hash.
4. Recollect the project and verify catalog refresh.
5. Use the separately confirmed rollback action and verify the original hash.
6. Create a second proposal, edit the source outside AMCP, then confirm AMCP
   refuses the stale proposal as a conflict.

The corresponding fixture control is `scripts/acceptance-safe-change.sh`; the
real check must retain only change-set IDs, hashes, status, and backup paths.

## 4. Second physical host

Use a separate macOS or Linux machine. The fixture script proves protocol
behavior only; this check proves a real lifecycle and reconnect.

1. Build/install the Agent remotely and start it with a private TLS
   certificate, short-lived pairing code, and non-public listener. For a
   developer/test macOS distribution, push a `v*` tag to publish the
   target-specific GitHub Release, install it remotely with
   `scripts/install-agent-macos-release.sh`, then use
   `scripts/configure-macos-remote-agent.sh` after enrollment. The release
   archive contains no credentials, keys, pairing codes, or Codex state.
2. Enroll from the Controller with `amcp-controller enroll` or the Desktop
   **Enroll & sync** panel. Supply CA, server name, pairing code, and bootstrap
   token through secure input; do not put them in shell history or logs.
3. Collect one provider, then confirm a second host connection and host-scoped
   artifacts.
4. Stop the Agent. Confirm indexed previews remain searchable but live reads
   and mutations are disabled.
5. Restart the same Agent and use **Sync enrolled host**. Confirm credentials
   are reused, replay is idempotent, and live actions return.

Before this check, `scripts/acceptance-multi-host-tls.sh` provides an isolated
two-Agent TLS rehearsal.

## 5. macOS distributable application

First run the offline development-bundle verification:

```bash
./scripts/acceptance-desktop-bundle.sh
```

For a distributable release, the release owner supplies a Developer ID
Application identity and existing `notarytool` Keychain profile:

```bash
AMCP_CODESIGN_IDENTITY='Developer ID Application: Organization (TEAMID)' \
AMCP_NOTARY_PROFILE='amcp-notary' \
./scripts/release-macos.sh
```

Accept only after `codesign --verify`, notarization, stapling, and
`spctl --assess` pass. Install the resulting bundle normally and smoke test
local collection, catalog search, an evidence-grounded Codex response, and a
proposal review. An ad-hoc signature is not a substitute for this evidence.

## 6. Linux and Windows lifecycle

On a real Linux user account:

```bash
AMCP_AGENT_BIN=/absolute/path/to/amcp-agent \
  ./scripts/install-systemd-user-service.sh
systemctl --user status com.gohyperdev.amcp.agent.service
```

Verify restart/reconnect after a service restart, and verify the Agent is not
public by default. For remote enrollment, set a user-owned
`AMCP_CREDENTIAL_STORE_DIR` before enrolling and verify private permissions.

On a real Windows user account, from PowerShell:

```powershell
.\scripts\install-windows-agent-task.ps1 -AgentBin "$PWD\target\debug\amcp-agent.exe"
Get-ScheduledTask -TaskName "AMCP Agent"
```

Verify the named-pipe Agent starts at logon, uses the current-user task and
Credential Manager, supports remote enrollment/reconnect, and uninstalls
cleanly. Record only task status and AMCP host IDs.

## Final evidence checklist

- [ ] Five real local Codex projects collected and searched.
- [ ] Representative FTS benchmark meets the accepted p95 target.
- [ ] Redacted RAG corpus meets approved quality thresholds, or RAG remains
      disabled by policy.
- [ ] One real, human-reviewed safe change applies, refreshes, rolls back, and
      refuses a post-proposal external edit.
- [ ] A second physical host enrolls, disconnects safely, and reconnects.
- [ ] A Developer ID-signed, notarized macOS bundle passes Gatekeeper and UI
      smoke testing.
- [ ] Linux and Windows lifecycle/enrollment acceptance runs pass on native OS.
