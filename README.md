# AMCP — Agent Memory Control Plane

AMCP manages configuration, guidance, memory, and session state for coding agents across hosts.

The current implementation slice is macOS-first and Codex-first:

- `amcp-agent` is a separate local process that owns native provider-state access.
- `amcp-controller` is the central collector with SQLite/FTS5 storage and scoped search.
- The Agent and Controller communicate over an authenticated JSONL protocol on a Unix socket.
- Before any collection, live read, runtime action or mutation, Controller requires both an exact protocol version and the same Agent binary major/minor release line; patch differences are accepted.
- Shared Rust crates are checked on macOS, Linux, and Windows in CI; host lifecycle and IPC binaries remain platform-specific work.
- The default local socket is `~/Library/Application Support/AMCP/agent.sock` with a `0700` parent directory and `0600` socket permissions; `/tmp` remains available only when explicitly supplied for development.
- Native provider state remains authoritative; AMCP stores normalized, redacted observations and evidence.
- Codex configuration layers and `AGENTS.md`/`AGENTS.override.md` guidance are normalized with explicit precedence and source hashes.
- Root-level Codex profiles such as `review.config.toml` are discovered as separately scoped configuration layers, alongside the user configuration.
- Recognized `rules/`, `skills/*/SKILL.md`, `hooks/`, and `mcp/` files are inventoried as redacted instruction or tooling artifacts; AMCP never executes hooks, skills, or MCP commands during discovery.
- Existing trusted paths from Codex `projects.toml` are discovered as additional project roots, so project `.codex/config.toml` and guidance are inventoried without manual root configuration.
- The Desktop can add local project directories to the next collection (one absolute path per line). They are validated as existing directories, passed only to the local Agent, deduplicated, and remain read-only unless Codex itself marks the project `trusted`.

## Install a remote macOS Agent from GitHub Release

Use this on the **remote Mac**. It installs the correct Apple Silicon or Intel
Agent automatically, and verifies its published SHA-256 checksum. No repository
clone is required. These are developer/test artifacts; they are not Developer
ID-signed or notarized.

```bash
amcp_version=v0.1.6
amcp_bootstrap=$(mktemp -d)
cd "$amcp_bootstrap"
curl --fail --location \
  "https://github.com/gohyperdev/agent-memory-control-plane/releases/download/$amcp_version/amcp-agent-macos-tools.tar.gz" \
  -o amcp-agent-macos-tools.tar.gz
curl --fail --location \
  "https://github.com/gohyperdev/agent-memory-control-plane/releases/download/$amcp_version/SHA256SUMS" \
  -o SHA256SUMS
grep ' amcp-agent-macos-tools.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf amcp-agent-macos-tools.tar.gz
./amcp-agent-macos-tools/scripts/install-agent-macos-release.sh \
  --repo gohyperdev/agent-memory-control-plane --version "$amcp_version"
```

Then provision a TLS certificate/key for the remote Mac, start the Agent once
with a one-time pairing code, enroll it from the Controller Mac, and persist it
as a per-user LaunchAgent:

```bash
# Remote Mac: replace the IP address and certificate paths.
read -r -s AMCP_AGENT_PAIRING_CODE
export AMCP_HOST_ID=mac-2 AMCP_AGENT_PAIRING_CODE
"$HOME/Library/Application Support/AMCP/bin/amcp-agent" \
  --tcp-bind 192.0.2.42:45432 \
  --tls-cert /absolute/path/to/mac-2.crt \
  --tls-key /absolute/path/to/mac-2.key serve

# Controller Mac, while the command above is running:
read -r -s AMCP_CONTROLLER_PAIRING_CODE
./target/release/amcp-controller enroll \
  --agent-url tcp://mac-2.example:45432 \
  --tls-ca /absolute/path/to/private-ca.crt \
  --tls-server-name mac-2.example \
  --pairing-code "$AMCP_CONTROLLER_PAIRING_CODE" \
  --db "$HOME/Library/Application Support/AMCP/controller.sqlite" --json

# Remote Mac, after enrollment succeeds:
./amcp-agent-macos-tools/scripts/configure-macos-remote-agent.sh \
  --agent-bin "$HOME/Library/Application Support/AMCP/bin/amcp-agent" \
  --host-id mac-2 --listen 192.0.2.42:45432 \
  --tls-cert /absolute/path/to/mac-2.crt \
  --tls-key /absolute/path/to/mac-2.key
```

The pairing code is short-lived and must be transferred to the Controller over
an out-of-band channel. The persistent LaunchAgent uses the rotated credential
in the remote Mac's Keychain; it does not store a pairing code or token. The
detailed deployment notes remain in [Remote Agent deployment](#remote-agent-example-tls-is-required-for-tcp-mode).

## Run the first vertical slice

```bash
cargo test
cargo build --bins
cargo run -p amcp-controller -- run-once --json
cargo run -p amcp-controller -- search --db "$HOME/Library/Application Support/AMCP/controller.sqlite" "AGENTS"
```

Use `--codex-home` to point the Agent at a fixture or alternate Codex home. For a deterministic local run:

```bash
cargo run -p amcp-controller -- run-once \
  --codex-home fixtures/codex \
  --db /tmp/amcp-fixture.sqlite \
  --socket /tmp/amcp-fixture.sock \
  --query Project \
  --json
```

Discovery remains read-only and does not read credentials. Session bodies are collected as metadata-only evidence and normalized session items without transcript content by default; a human can explicitly request a bounded, redacted excerpt from a discovered JSONL session source. Such session evidence remains read-only and cannot enter the change workflow. Documented memory files are stored as bounded, redacted excerpts with source hashes. Configuration and instruction files are redacted before persistence. A separate, explicit change workflow supports proposal, human approval, atomic apply, backup, conflict detection, and rollback for `config.toml`, root-level Codex `*.config.toml` profiles, `AGENTS.md`, and `AGENTS.override.md`.

Run the isolated end-to-end safe-change acceptance (it only copies fixtures into `/tmp`). It verifies apply/backup/rollback and refuses an apply after an external source edit:

```bash
./scripts/acceptance-safe-change.sh
```

Run an isolated two-host TLS collection acceptance (two loopback Agents, one
Controller catalog, temporary CA) with:

```bash
./scripts/acceptance-multi-host-tls.sh
```

Measure the actual central FTS search path for an existing catalog without
printing the query, snippets, or artifact identifiers. It records only the
same bounded content-free latency/result-count telemetry as a normal search:

```bash
cargo run -p amcp-controller -- benchmark-search \
  --db "$AMCP_DB_PATH" --iterations 25 --warmup 3 --assert-p95-ms 300 --json "codex"
```

The `--assert-p95-ms` flag makes the command fail if the measured p95 misses
the supplied target. Run it against representative local data before treating
the first-release 300 ms target as verified.

Report the locally observable Codex catalog readiness without exposing catalog
content or claiming completion of host/signing/platform checks:

```bash
cargo run -p amcp-controller -- readiness --db "$AMCP_DB_PATH" --assert-local-codex --json
```

Evaluate a deliberately redacted RAG corpus through the same lexical retrieval
path, without enabling normal RAG, opening provider files, network egress or
persisting retrieval history:

```bash
cargo run -p amcp-controller -- rag-evaluate --assert-targets --json
```

The default fixture establishes 100% citation coverage and expected-record
recall with zero forbidden/stale hits. Replace `--fixture` only with a redacted
evaluation corpus, and tune the three explicit threshold flags for a
representative acceptance gate.

Verify that Controller/UI search and the embedded MCP tool return the same
source-linked, cited evidence from one catalog:

```bash
./scripts/acceptance-shared-search.sh
```

Exercise Controller restart, bounded search-index rebuild and recovery into a
fresh central catalog using only copied fixtures:

```bash
./scripts/acceptance-recovery.sh
```

On macOS, build and structurally verify the desktop bundle with an ad-hoc
development signature:

```bash
./scripts/acceptance-desktop-bundle.sh
```

This builds the target-specific Agent, Controller and MCP sidecars, then
verifies that the generated `AMCP.app` contains those executables, its icon
resources and bundle identifier. It is not a replacement for Developer ID
signing and Apple notarization.

For a distribution release, a macOS release owner with a Developer ID
Application certificate and an already configured `notarytool` Keychain profile
can run:

```bash
AMCP_CODESIGN_IDENTITY='Developer ID Application: Your Organization (TEAMID)' \
AMCP_NOTARY_PROFILE='amcp-notary' \
./scripts/release-macos.sh
```

The release script signs every bundled executable explicitly with hardened
runtime, submits the archive to Apple, staples the accepted ticket and checks
the result with Gatekeeper. It does not use `codesign --deep`.

## Current implementation surface

- `amcp-agent` is a provider-registry based local process. Codex is the first adapter; the Agent can also expose an opt-in TLS TCP listener for a remote host.
- Provider adapters are capability-based and every descriptor persists `provider_version`, adapter version, native roots, schema fingerprint, explicit `full`, `read-only`, `inventory-only` or `unsupported` support level, health and Controller compatibility per host; the JSON API accepts legacy `version` input but emits `provider_version`; adapters can omit runtime reads and mutations, keeping Claude Code, Kiro and Antigravity out of the Codex-specific UI and storage contract.
- Set `AMCP_ENABLE_FUTURE_PROVIDERS=true` on an Agent to enable modular file adapters for Claude Code, Kiro and Antigravity (read-only memory, guidance, configuration and project discovery); runtime/session parsing and mutation remain provider-specific follow-up work.
- The same future-provider adapters support scoped live reads for discovered, bounded, redacted files. They intentionally remain inventory/read-only for mutation: `amcp_artifact_read` can inspect them, while change proposals are rejected until a provider-specific write policy exists.
- `amcp-controller` supports local Unix IPC and `tcp://` Agent endpoints with a user-supplied CA, central host connection records, collection, FTS search, change proposal, approval, atomic apply, and rollback. `run-once` and `watch` collect every registered provider by default; `--provider-id <id>` narrows the operation, and one provider failure is reported without preventing the others from collecting. Approval envelopes carry a signed nonce and are consumed once by the Agent through a durable replay store.
- The Agent keeps a bounded, redacted collection outbox. On reconnect, the Controller replays it idempotently before requesting a fresh snapshot; cursors advance only after central persistence.
- The same authenticated Agent endpoint offers bounded `SearchLocal` results from its already-redacted collection cache for local/offline operation. `amcp-controller local-search --json <query>` exposes that path without a Controller catalog; it validates host/project scope, never opens native provider files during the request, and is not a cross-host search source.
- Collection batches emit persisted runtime events with stable IDs; SQLite deduplicates replayed events, while the MCP diagnostics tool exposes the resulting event history.
- Runtime events also have a separate bounded Agent outbox and authenticated replay/ack endpoint; the Controller acknowledges event IDs only after central persistence, and repeated delivery remains safe because central persistence deduplicates IDs.
- The Agent additionally exposes bounded `SubscribeEvents` long-poll pages (maximum 256 events / 30 seconds) with continuation IDs and explicit timeout semantics; it shares the event/ACK contract with the bidirectional stream.
- The Agent also exposes a dedicated bidirectional `OpenEventStream` with negotiated `max_in_flight` (maximum 64), heartbeat frames, scope filtering and ACK-gated delivery; `amcp-controller stream-events` persists and acknowledges the stream.
- `amcp-controller watch` uses the long-poll wait budget before reconciling each host/provider cursor, while preserving the bounded reconnect behavior.
- The Agent can optionally supervise a local Codex app-server runtime with `AMCP_AGENT_APP_SERVER_ENABLED=true`; it polls bounded thread metadata, emits deterministic `session.updated` events, persists no transcript deltas, and reconnects with exponential backoff.
- The authenticated Agent protocol also exposes bounded `RuntimeListThreads` read pages with host-scope enforcement and provider-neutral metadata; raw app-server response objects and transcript content are not returned.
- The authenticated Agent protocol also exposes `RuntimeReadThread`; it returns only one normalized thread snapshot with bounded item count/kind/role metadata. The Controller `runtime-read` command and MCP `amcp_runtime_thread_read` share the same host/provider scope checks and never return transcript content.
- Codex runtime archive/unarchive uses the normal human approval queue: `runtime-propose` creates a hash-bound `ChangeSet`, and approval calls `thread/archive` or `thread/unarchive` only after a fresh state check and post-operation verification. MCP can create the proposal but cannot apply it.
- The macOS Agent runs a `notify`/FSEvents-backed watcher over the Codex root and emits bounded, path-relative `source.changed` events; sensitive `auth.json` paths are excluded and bursts are coalesced.
- Central FTS5 search is maintained incrementally during collection, records projection runs, and supports bounded chunk rebuilds through `amcp-controller rebuild-index`.
- Every Controller collection attempt persists content-free host/provider metrics: request and correlation IDs when available, latency, discovered/inserted counts, replay count and a stable failure classification. The CLI includes `duration_ms`; `amcp-controller diagnostics --json`, the Desktop and MCP expose the latest bounded collection history.
- Every lexical catalog search also records bounded operational metadata — host/provider scope, correlation ID, latency, result count and limit — while deliberately excluding the query, snippets, previews and result identifiers. The retained history is capped at 1,000 records and appears in Controller CLI, Desktop and MCP diagnostics.
- The Desktop can save a named private search shortcut with the same host/provider/project, trust, artifact, lifecycle, sensitivity and date constraints used by the shared catalog search. Saved query text is retained only because the user explicitly saves it; it is never copied into search telemetry, MCP diagnostics or audit metrics.
- The Desktop also supports private Controller-owned aliases for enrolled hosts. An alias improves multi-host navigation but never replaces the Agent-reported `host_id`, hostname, connection credential, scope checks or policy decisions.
- The artifact inspector supports private Controller tags on normalized catalog records. Tags are database relationships only: they do not write to native provider files, and are removed automatically with a deleted central artifact.
- The artifact inspector can also create explicit symmetric links between indexed artifacts from different hosts (`related`, `duplicate`, `same-policy`, or `follow-up`). These remain Controller catalog metadata and never copy, merge, or mutate either native provider source.
- The Controller creates a consistent, private SQLite snapshot before a schema migration. A user can also request one explicitly through `amcp-controller backup --json` or the Desktop diagnostics panel; backups live in the private `backups/` directory next to the central catalog and never include provider-native files.
- Codex discovery exposes a metadata cursor; unchanged collections are served from the Agent cache, while source changes trigger a fresh scan.
- If a provider collection fails but a cached collection exists, the Agent returns that cache together with a stable, content-free `diagnostic.updated` event so the Controller can show provider degradation without leaking parser errors or native data.
- Existing Codex session `cwd` metadata contributes validated project inventory: AMCP prefers the enclosing Git root when present, assigns the session to that project, and does not read project contents as part of this discovery step.
- The Codex provider descriptor reports safe installation metadata: detected `CODEX_HOME`, an explicitly configured and existing `CODEX_SQLITE_HOME`, CLI availability, and the bounded first line of `codex --version`. AMCP does not open native SQLite files for this check.
- `amcp-mcp` is a stdio MCP gateway for embedded Codex with scoped redacted search, host/project/session/session-item/memory inventory, configuration-layer and guidance-chain tools, bounded content-free diagnostics, change review, and verified change-proposal tools. Every successful tool result has a request ID, host/provider scope, a `result_status`, citations/evidence, warnings, and its tool-specific payload under `data`; an empty catalog search reports `not_indexed`, while a no-match search reports `not_found`. Structured MCP errors classify unsupported, untrusted and permission-denied policy outcomes without returning provider payloads. It never applies a change.
- The shared diagnostics snapshot is content-free and bounded: `amcp-controller diagnostics --json`, the Desktop and MCP report stale sources, untrusted/unknown projects, conflict metadata and the count of provider diagnostic events without returning artifact bodies, diffs or provider payloads.
- The same snapshot reports aggregate applied, conflicted and rolled-back change counts without retaining operation diffs, reasons or target content.
- Diagnostics also report aggregate stale-source ratio, FTS projection coverage and the size of the central SQLite catalog plus active WAL/SHM sidecars; native provider files are never measured or included.
- The Controller exposes a scoped `read-artifact` path used by MCP `amcp_artifact_read` and the desktop inspector for live, bounded, redacted reads from the owning Agent. Successful `Sensitive` or `SecretLike` live reads and catalog-search results record content-free audit metadata in the same central catalog; neither a search query nor a preview is stored. The inspector can turn returned content into a provider-validated change proposal, but never writes directly. The desktop, `amcp-controller audit-list`, and MCP `amcp_audit_events_list` provide the same bounded audit view, scoped by host and provider.
- `scripts/acceptance-sensitive-read-audit.sh` verifies a redacted sensitive live read and its matching content-free Controller audit record in an isolated catalog.
- `scripts/acceptance-multi-provider-collection.sh` enables fixture-backed future adapters and verifies one default Controller collection independently indexes Codex, Claude Code, Kiro and Antigravity without sharing a parser failure path.
- `amcp-app-server` supervises the documented Codex app-server stdio protocol, captures bounded notification summaries, and supports initialization, thread/turn start, streamed notifications, and interruption.
- If the embedded Codex app-server cannot start or connect, the desktop shows an explicit degraded state and keeps the catalog, search, source inspection, and session-evidence features available read-only; a later turn retries the runtime.
- The desktop can request one evidence-grounded recommendation from embedded Codex only after the user selects 2–4 redacted catalog results. The prompt requires AMCP artifact citations, retains no prompt text in diagnostics, and shows the selected source-linked records beside the response. As with every embedded turn, the bounded redacted exchange is retained as a central AMCP session record.
- The app-server client also exposes thread list/read/archive/unarchive primitives; the desktop session explorer displays bounded session items and metadata-only event summaries.
- Embedded desktop Codex turns are persisted as bounded, redacted session items and `session.event` runtime events, while delta/transcript payloads are excluded from event items and native Codex state remains authoritative.
- `amcp-rag` defines the consent, citation, invalidation, and retrieval contract; its default implementation is disabled and lexical search remains the fallback.
- The Desktop persists a private, validated RAG policy shared with MCP: enablement, allowed host/provider/project scopes, lexical/local-hash/OpenAI-compatible provider selection, model, retention, chunk size and retrieval budget. Ingestion remains permanently redacted-excerpt-only and excludes transcript bodies. RAG stays disabled by default; the legacy `AMCP_RAG_*` settings remain deployment overrides.
- RAG retrieval history never stores the user query or context text. It retains only scope, provider/model metadata, result/citation counters, elapsed time and a correlation ID; legacy stored phrases are cleared by migration and history is capped at 1,000 runs. RAG status reports average retrieval latency and citation coverage.
- `AMCP_RAG_EMBEDDING_PROVIDER=local-hash` optionally enables a deterministic local feature-hashing vector baseline with embedding metadata in citations; it performs no network egress, persists derived `rag_chunks`/retrieval runs in SQLite, and does not replace lexical search.
- `AMCP_RAG_EMBEDDING_PROVIDER=openai` enables the OpenAI-compatible provider only when `AMCP_RAG_EGRESS_CONSENT=true` and `OPENAI_API_KEY` are present. This consent and the key are process-local and never persisted with the RAG policy. `AMCP_RAG_EMBEDDING_MODEL` defaults to `text-embedding-3-small`, `AMCP_RAG_EMBEDDING_DIMENSIONS` is optional, and `AMCP_RAG_EMBEDDING_ENDPOINT` defaults to `https://api.openai.com/v1/embeddings`. AMCP sends only bounded redacted chunks; the key is never stored in the catalog, RAG index, logs or citations.
- `fixtures/rag/retrieval-evaluation.json` is a redacted retrieval evaluation set. Its test measures citation coverage, expected-record recall, stale-record exclusion, and host/provider/project scope isolation through the production retrieval path.
- `amcp-controller rag-status --json` reports only derived RAG-index metadata. `amcp-controller rag-clear --yes --json` deletes the complete derived RAG projection and retrieval history while leaving native provider files, the AMCP catalog and FTS search intact; the same operation is available from the desktop RAG panel after explicit confirmation.
- The desktop memory inventory also has an explicitly confirmed **Forget** action for one central record. It deletes that record's AMCP artifact/search projection, related RAG chunks and stored retrieval runs without touching native provider state; a tombstone suppresses only a replay of the same source hash, so a later changed native version can be collected again.
- `amcp-core` exposes the shared functional catalog API used by the desktop UI, MCP gateway, and Controller; all surfaces therefore share scope and storage behavior.
- Collection cursors are persisted only after a successful catalog transaction, allowing the Controller to resume per-host/provider collection safely.
- `apps/amcp-desktop` is the Tauri 2 + React desktop shell. It renders host/index/approval status, search evidence, provenance, safe local sync, and human change review: operation diff, expected/before/after hashes, evidence count, approval and a separately confirmed rollback action for applied changes.
- The desktop shell also provides a multi-host panel for TLS Agent enrollment and resync. Enrollment uses the Agent pairing code, stores the rotated credential in the macOS Keychain, and performs the initial provider collection without mounting or browsing the remote filesystem.
- When a host is disconnected, AMCP keeps its indexed catalog searchable and visibly labels offline previews, while disabling live Agent reads and mutation/runtime controls until that host reconnects.

Remote Agent example (TLS is required for TCP mode):

```bash
AMCP_HOST_ID=mac-2 ./target/debug/amcp-agent \
  --tcp-bind 0.0.0.0:45432 \
  --tls-cert /path/to/agent.crt \
  --tls-key /path/to/agent.key \
  --token "$AMCP_AGENT_TOKEN" serve

./target/debug/amcp-controller run-once \
  --agent-url tcp://mac-2.example:45432 \
  --tls-ca /path/to/agent-ca.crt \
  --tls-server-name mac-2.example \
  --token "$AMCP_AGENT_TOKEN" \
  --db "$HOME/Library/Application Support/AMCP/controller.sqlite" \
  --json
```

For a central Collector loop over several remote Agents, pass `--agent-url` once per host:

```bash
./target/debug/amcp-controller watch \
  --agent-url tcp://mac-1.example:45432 \
  --agent-url tcp://mac-2.example:45432 \
  --tls-ca /path/to/agent-ca.crt \
  --token "$AMCP_AGENT_TOKEN" \
  --interval-seconds 30
```

On macOS, the development/default token can be replaced by a host-scoped Keychain credential:

```bash
./target/debug/amcp-controller keychain-store \
  --host-id mac-2 \
  --token "$AMCP_AGENT_TOKEN"
```

When the default token is used, Controller and Agent first look up `agent:<host_id>` (or `AMCP_AGENT_KEYCHAIN_ACCOUNT`) and fall back to the development token only when no Keychain entry exists.

On Linux and other non-macOS/non-Windows platforms, credential persistence is deliberately opt-in: set `AMCP_CREDENTIAL_STORE_DIR` to a user-owned directory before enrolling a remote host. AMCP stores one host credential per `0600` file and restricts the directory to `0700` on Unix; without this setting it does not persist credentials and retains the development-token fallback. A native Secret Service integration remains a separate platform enhancement.

On Windows, enrolled Agent credentials are persisted in the current user's Windows Credential Manager under the AMCP service namespace; `AMCP_CREDENTIAL_STORE_DIR` is not needed.

For first-time pairing, start a remote Agent with its displayed short-lived code and run:

```bash
./target/debug/amcp-controller enroll \
  --agent-url tcp://mac-2.example:45432 \
  --tls-ca /path/to/agent-ca.crt \
  --tls-server-name mac-2.example \
  --pairing-code 12345678 \
  --json
```

Enrollment rotates the Agent credential, stores it in the macOS Keychain, and records the host/capabilities in the central catalog.

For a developer/test deployment on a second macOS host, the `Publish Agent release` GitHub Action publishes target-specific Agent archives, source-only macOS bootstrap tools, and `SHA256SUMS` on every `v*` tag. The release installer verifies that checksum before installing a binary; it never fetches credentials, TLS keys, pairing codes, or Codex state. Configure the paired remote TLS LaunchAgent separately with `scripts/configure-macos-remote-agent.sh`. Run `./scripts/acceptance-agent-release-package.sh` locally to verify that packaging contract before tagging. These developer artifacts are not a substitute for a Developer ID-signed and notarized production macOS release.

To bootstrap a clean second Mac without cloning this repository, download the
small tooling archive and verify it first (replace the placeholders):

```bash
amcp_repo=gohyperdev/agent-memory-control-plane
amcp_version=v0.1.6
amcp_bootstrap=$(mktemp -d)
cd "$amcp_bootstrap"
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/$amcp_repo/releases/download/$amcp_version/amcp-agent-macos-tools.tar.gz" \
  -o amcp-agent-macos-tools.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/$amcp_repo/releases/download/$amcp_version/SHA256SUMS" \
  -o SHA256SUMS
awk '$2 == "amcp-agent-macos-tools.tar.gz"' SHA256SUMS | shasum -a 256 -c -
tar -xzf amcp-agent-macos-tools.tar.gz
./amcp-agent-macos-tools/scripts/install-agent-macos-release.sh \
  --repo "$amcp_repo" --version "$amcp_version"
```

Provision the remote Agent certificate/key through the chosen private PKI and
restrict its listener with a firewall to the Controller host. Start the
installed Agent once with a short-lived pairing code, enroll from the
Controller, then install its per-user LaunchAgent. The LaunchAgent deliberately
contains no token: after enrollment the rotated credential is resolved from
that remote Mac's Keychain. For later direct Controller CLI calls, select the
remote Controller-side Keychain item with
`AMCP_AGENT_KEYCHAIN_ACCOUNT=agent:<remote-host-id>`; the Desktop does this
through its enrolled-host connection record.

The one-time pairing and durable launch sequence is:

```bash
# On the remote Mac: use absolute paths from its private PKI and do not expose
# this listener beyond the Controller's network address.
read -r -s AMCP_AGENT_PAIRING_CODE
export AMCP_HOST_ID=mac-2
export AMCP_AGENT_PAIRING_CODE
"$HOME/Library/Application Support/AMCP/bin/amcp-agent" \
  --tcp-bind 192.0.2.42:45432 \
  --tls-cert /absolute/path/to/mac-2.crt \
  --tls-key /absolute/path/to/mac-2.key serve

# On the Controller Mac, while the temporary Agent is running:
read -r -s AMCP_CONTROLLER_PAIRING_CODE
./target/release/amcp-controller enroll \
  --agent-url tcp://mac-2.example:45432 \
  --tls-ca /absolute/path/to/private-ca.crt \
  --tls-server-name mac-2.example \
  --pairing-code "$AMCP_CONTROLLER_PAIRING_CODE" \
  --db "$HOME/Library/Application Support/AMCP/controller.sqlite" --json

# Back on the remote Mac, after enrollment stops the temporary Agent:
./amcp-agent-macos-tools/scripts/configure-macos-remote-agent.sh \
  --agent-bin "$HOME/Library/Application Support/AMCP/bin/amcp-agent" \
  --host-id mac-2 --listen 192.0.2.42:45432 \
  --tls-cert /absolute/path/to/mac-2.crt \
  --tls-key /absolute/path/to/mac-2.key
```

Use a shell-local secure prompt and transfer that one-time code to the
Controller through an out-of-band channel; do not paste it into command
history. The temporary Agent is stopped by a successful enrollment. Its
persistent LaunchAgent then starts using only the rotated Keychain credential.

Run the desktop shell from `apps/amcp-desktop` with `npm install` followed by `npm run tauri dev`. The Tauri command builds the current-target AMCP sidecars first; use `AMCP_SIDECAR_TARGET=<rust-target>` to override that target. The bundled UI reads the same central catalog used by the CLI and MCP gateway.

Install the Agent as a per-user macOS LaunchAgent after building the binaries:

```bash
AMCP_AGENT_BIN="$PWD/target/debug/amcp-agent" \
  ./scripts/install-launch-agent.sh
```

Use `./scripts/uninstall-launch-agent.sh` to stop and remove it. The installer keeps the Agent in the user session and does not create a network listener.

On Linux, install the equivalent per-user systemd service after building the binaries:

```bash
AMCP_AGENT_BIN="$PWD/target/debug/amcp-agent" \
  ./scripts/install-systemd-user-service.sh
```

The unit is installed as `~/.config/systemd/user/com.gohyperdev.amcp.agent.service` with mode `0600`, restarts only after failures, and never embeds a token. Use `./scripts/uninstall-systemd-user-service.sh` to disable and remove it. For durable enrolled credentials, set `AMCP_CREDENTIAL_STORE_DIR` in the user service environment through your systemd user-environment configuration before starting the Agent.

On Windows, AMCP uses a local named pipe (`\\.\pipe\com.gohyperdev.amcp.agent`) rather than a Unix socket. Install the current user's lifecycle task after building:

```powershell
.\scripts\install-windows-agent-task.ps1 -AgentBin "$PWD\target\debug\amcp-agent.exe"
```

The Scheduled Task runs with limited interactive-user privileges, restarts after failures, and does not embed an Agent token. Remove it with `./scripts/uninstall-windows-agent-task.ps1`. Enrolled remote-host credentials are stored in the current user's Windows Credential Manager.

Export a bounded macOS diagnostic bundle without copying the central database or native provider files:

```bash
./scripts/diagnose-agent.sh
```

See [PLAN-IMPLEMENTACJI.md](PLAN-IMPLEMENTACJI.md) for the full implementation roadmap.
See [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md) for the evidence-backed implementation status and outstanding acceptance work.
See [PRODUCTION-ACCEPTANCE.md](PRODUCTION-ACCEPTANCE.md) for the safe, evidence-oriented runbook for real hosts, distribution signing, and remaining Definition-of-Done checks.
