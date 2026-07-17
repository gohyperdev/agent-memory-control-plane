# AMCP — Agent Memory Control Plane

AMCP manages configuration, guidance, memory, and session state for coding agents across hosts.

The current implementation slice is macOS-first and Codex-first:

- `amcp-agent` is a separate local process that owns native provider-state access.
- `amcp-controller` is the central collector with SQLite/FTS5 storage and scoped search.
- The Agent and Controller communicate over an authenticated JSONL protocol on a Unix socket.
- The default local socket is `~/Library/Application Support/AMCP/agent.sock` with a `0700` parent directory and `0600` socket permissions; `/tmp` remains available only when explicitly supplied for development.
- Native provider state remains authoritative; AMCP stores normalized, redacted observations and evidence.
- Codex configuration layers and `AGENTS.md`/`AGENTS.override.md` guidance are normalized with explicit precedence and source hashes.
- Existing trusted paths from Codex `projects.toml` are discovered as additional project roots, so project `.codex/config.toml` and guidance are inventoried without manual root configuration.

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

Discovery remains read-only and does not read credentials. Session bodies are collected as metadata-only evidence and normalized session items without transcript content by default; documented memory files are stored as bounded, redacted excerpts with source hashes. Configuration and instruction files are redacted before persistence. A separate, explicit change workflow supports proposal, human approval, atomic apply, backup, conflict detection, and rollback for safe Codex text documents.

## Current implementation surface

- `amcp-agent` is a provider-registry based local process. Codex is the first adapter; the Agent can also expose an opt-in TLS TCP listener for a remote host.
- Provider adapters are capability-based; inventory-only adapters can omit reads and mutations, keeping future Claude Code, Kiro, and Antigravity integrations out of the Codex-specific UI and storage contract.
- `amcp-controller` supports local Unix IPC and `tcp://` Agent endpoints with a user-supplied CA, central host connection records, collection, FTS search, change proposal, approval, atomic apply, and rollback. Approval envelopes carry a signed nonce and are consumed once by the Agent through a durable replay store.
- The Agent keeps a bounded, redacted collection outbox. On reconnect, the Controller replays it idempotently before requesting a fresh snapshot; cursors advance only after central persistence.
- Collection batches emit persisted runtime events with stable IDs; SQLite deduplicates replayed events, while the MCP diagnostics tool exposes the resulting event history.
- Runtime events also have a separate bounded Agent outbox and authenticated replay/ack endpoint; the Controller acknowledges event IDs only after central persistence, and repeated delivery remains safe because central persistence deduplicates IDs.
- The Agent additionally exposes bounded `SubscribeEvents` long-poll pages (maximum 256 events / 30 seconds) with continuation IDs and explicit timeout semantics, allowing a future streaming transport to reuse the same event/ACK contract.
- `amcp-controller watch` uses the long-poll wait budget before reconciling each host/provider cursor, while preserving the bounded reconnect behavior.
- The macOS Agent runs a `notify`/FSEvents-backed watcher over the Codex root and emits bounded, path-relative `source.changed` events; sensitive `auth.json` paths are excluded and bursts are coalesced.
- Codex discovery exposes a metadata cursor; unchanged collections are served from the Agent cache, while source changes trigger a fresh scan.
- `amcp-mcp` is a stdio MCP gateway for embedded Codex with scoped redacted search, host/project/session/session-item/memory inventory, configuration-layer and guidance-chain tools, change review, and verified change-proposal tools. It never applies a change.
- `amcp-app-server` supervises the documented Codex app-server stdio protocol, captures bounded notification summaries, and supports initialization, thread/turn start, streamed notifications, and interruption.
- The app-server client also exposes thread list/read/archive/unarchive primitives; the desktop session explorer displays bounded session items and metadata-only event summaries.
- Embedded desktop Codex turns are persisted as bounded, redacted session items and `session.event` runtime events, while delta/transcript payloads are excluded from event items and native Codex state remains authoritative.
- `amcp-rag` defines the consent, citation, invalidation, and retrieval contract; its default implementation is disabled and lexical search remains the fallback.
- Setting `AMCP_RAG_ENABLED=true` enables the bounded, cited lexical RAG manager over redacted FTS previews; `AMCP_RAG_RETENTION_DAYS` purges expired chunks before retrieval, embeddings remain a separate future provider, and RAG stays disabled by default.
- `amcp-core` exposes the shared functional catalog API used by the desktop UI, MCP gateway, and Controller; all surfaces therefore share scope and storage behavior.
- Collection cursors are persisted only after a successful catalog transaction, allowing the Controller to resume per-host/provider collection safely.
- `apps/amcp-desktop` is the Tauri 2 + React desktop shell. It renders host/index/approval status, search evidence, provenance, safe local sync, and the human approval action for proposed changes.

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

Run the desktop shell from `apps/amcp-desktop` with `npm install` followed by `npm run tauri dev`. The bundled UI reads the same central catalog used by the CLI and MCP gateway.

Install the Agent as a per-user macOS LaunchAgent after building the binaries:

```bash
AMCP_AGENT_BIN="$PWD/target/debug/amcp-agent" \
  ./scripts/install-launch-agent.sh
```

Use `./scripts/uninstall-launch-agent.sh` to stop and remove it. The installer keeps the Agent in the user session and does not create a network listener.

See [PLAN-IMPLEMENTACJI.md](PLAN-IMPLEMENTACJI.md) for the full implementation roadmap.
