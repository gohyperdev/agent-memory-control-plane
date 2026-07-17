# Agent Memory Control Plane

Initial product brief and technical specification

Status: Draft for OpenAI Hackathon — Developer Tools

Detailed component design: [AMCP Collector/Controller and Agent HLD](HLD-AMCP-COLLECTOR-CONTROLLER-AND-AGENT.md)

Implementation roadmap: [AMCP implementation plan](PLAN-IMPLEMENTACJI.md)

## 1. Product brief

### Working name

**Agent Memory Control Plane** (AMCP), with “Codex Atlas” as a possible product-facing name.

### One-sentence pitch

AMCP is a multi-host control plane for discovering, understanding, searching, and safely changing the configuration, guidance, memory, and session state of AI coding agents across projects and machines.

### The problem

AI agents accumulate valuable operational context, but that context is fragmented across hidden directories, project files, databases, transcripts, configuration layers, and different hosts. Developers need to answer questions such as:

- Which projects have agent history, and where is it stored?
- Why did Codex, Claude Code, Antigravity, or Kiro behave differently in this repository?
- Which instructions, model settings, MCP servers, permissions, or memories are active?
- What did an earlier session discover or change?
- Can a recommendation be reviewed, applied, and reverted safely?

Existing tools expose individual files or a terminal session. They do not provide a coherent, searchable, explainable view of an agent’s operational state.

### Target users

1. **Agent-heavy developer** — uses several coding agents across many repositories and wants fast recall and cleanup.
2. **Developer-tools engineer** — diagnoses agent behavior, permissions, MCP configuration, and session history.
3. **Team lead or platform engineer** — standardizes guidance and configuration across projects and hosts.
4. **Hackathon judge** — should understand the value within a short demo: discover → inspect → ask Codex → review diff → apply safely.

### Product thesis

The product should make agent state observable without making it opaque or proprietary. It should preserve native Codex files and protocols, add an indexed control plane beside them, and require explicit human approval for mutations.

### Goals

- Run a lightweight local AMCP Agent on every connected system.
- Aggregate multiple systems through a central AMCP Collector/Controller.
- Discover agent state on connected machines with minimal setup.
- Present projects, active configuration layers, guidance, memories, and sessions from multiple providers as one navigable graph.
- Make configuration precedence and effective values understandable.
- Search across session transcripts, memories, project guidance, and configuration.
- Embed a Codex assistant that can inspect the indexed state and produce recommendations.
- Let the assistant propose changes as reviewable patches; never silently modify user state.
- Preserve compatibility with Codex CLI, IDE extension, and desktop app by using documented files and the Codex app-server protocol.
- Establish a provider adapter architecture so Codex is the first provider, not a special case.

### Non-goals for the first release

- Replacing the Codex CLI, IDE extension, or desktop app.
- Reimplementing Codex’s model runtime, sandbox, authentication, or approval engine.
- Editing or exposing credentials, tokens, cookies, or `auth.json` contents.
- Implementing Claude Code, Antigravity, or Kiro adapters in the Codex-first MVP; the provider contract must exist, while only Codex needs full implementation initially.
- Synchronizing or merging native state between hosts; the controller aggregates metadata and actions but does not silently replicate agent files.
- Treating undocumented SQLite schemas as a stable public API.

## 2. Codex integration facts that shape the design

These facts are based on the current official Codex documentation and should be revalidated when the Codex version changes.

### State root and configuration

- `CODEX_HOME` is the root for Codex state; it defaults to `~/.codex` and includes configuration, authentication, logs, sessions, skills, and other state.
- User configuration is `~/.codex/config.toml`.
- Project configuration is `.codex/config.toml`; Codex loads project layers only for trusted projects.
- Configuration precedence is: CLI overrides, project layers from root to current directory, selected profile, user config, system config, then defaults.
- Profile files are separate files such as `$CODEX_HOME/profile-name.config.toml`.
- Project-local configuration cannot override selected machine-local/provider/auth/telemetry keys. AMCP must surface this distinction rather than implying that every setting can be moved into a repository.

### Guidance and memory

- Codex loads `AGENTS.override.md` or `AGENTS.md` at global and project/directory scopes. More specific files are merged later and therefore have higher practical precedence.
- `AGENTS.md` is durable guidance and should hold rules that must always apply; it is not a replacement for memory.
- Local Codex memories are separate from ChatGPT web memory. The documented local memory area is under `$CODEX_HOME/memories/`; current Codex versions may also use SQLite-backed state.
- Memory generation and memory use are independently configurable. Memory is a recall layer, not the only source of rules that must always apply.

### Sessions and history

- `history.jsonl` stores session transcripts when history persistence is enabled.
- Session rollout files live under `$CODEX_HOME/sessions`; archived sessions live under `$CODEX_HOME/archived_sessions`.
- The app-server exposes thread-oriented operations for listing, reading, resuming, archiving, deleting, unarchiving, compacting, and subscribing to streamed events.
- A thread ID is the stable identifier to use when resuming or operating on a stored session. AMCP must not infer identity only from filenames.

### Best integration seam

Use **Codex app-server** for the embedded Codex experience. Official guidance describes it as the interface used by rich clients, including authentication, conversation history, approvals, and streamed agent events. It communicates over JSON-RPC-style messages via stdio, WebSocket, or Unix socket.

Use a separate **AMCP MCP server** to expose AMCP capabilities to that embedded Codex. `codex mcp-server` is useful when another MCP client wants to consume Codex; it is not the primary integration seam for building AMCP’s rich client.

## 3. MVP scope

### MVP user journey

1. Launch the central AMCP Collector/Controller.
2. Start or connect to the local AMCP Agent on the current system.
3. Detect the local Codex installation and register the host.
4. Index known project roots and relevant Codex state without reading secrets.
5. Show a system map: hosts, agent providers, projects, configuration layers, memories, and sessions.
6. Select a Codex project and inspect its effective guidance/configuration with source and precedence labels.
7. Search for a phrase such as “Azure DevOps”, “sandbox”, or “review PR” across the connected host.
8. Open a session and inspect its transcript, tools, working directory, model, and outcomes.
9. Ask embedded Codex: “Find repeated configuration or guidance problems and recommend fixes.”
10. Codex calls AMCP read/search/diagnostic tools and returns recommendations with evidence links.
11. User reviews a diff, approves one change, and the local Agent applies it atomically with backup and audit record.

### MVP capabilities

#### Discovery

- Register a host and report Agent version, capabilities, operating system, and connectivity.
- Detect `CODEX_HOME`, `CODEX_SQLITE_HOME`, Codex executable, version, and host identity through the Codex provider adapter.
- Discover projects from provider state, session metadata, Git roots, and user-selected scan roots.
- Discover provider-specific configuration, guidance, memory, and session artifacts through an adapter; for Codex this includes `AGENTS.md`, `.codex/config.toml`, profiles, `history.jsonl`, rollouts, memories, rules, hooks, and MCP configuration.
- Classify each item as documented, derived, unsupported/private, or provider-specific.

#### Inspection and search

- Full-text search over safe-to-index text content.
- Filter by host, agent provider, project, file type, session, date, model, branch, archived state, and trust status.
- Show the source path, scope, last modified time, content hash, and parser status for every result.
- Show configuration source and precedence instead of presenting a flattened value with no explanation.

#### Editing

- Read-only by default.
- Edit text files with syntax highlighting and a structured diff.
- Edit TOML through a comment-preserving editor (`toml_edit`) where feasible.
- Apply changes only through an explicit change set.
- Create a timestamped backup, recheck the original hash, write atomically, and record the result.
- Support undo by restoring the pre-change backup or applying the inverse patch.

#### Embedded Codex

- Start/attach to a local Codex app-server.
- Stream turn, tool, approval, and completion events into the UI.
- Allow Codex to read/search AMCP state through a local stdio MCP server.
- Require UI approval for AMCP mutations and destructive session operations.
- Show evidence for recommendations: file path, line/field, session ID, or indexed record.

## 4. Functional architecture

The functional core must be independent of the UI, network transport, filesystem watcher, process manager, provider adapters, and MCP transport. The product has two runtime roles:

- **AMCP Agent** — a small local daemon installed on each system. It owns local discovery, provider adapters, indexing, file access, app-server connections, and policy enforcement.
- **AMCP Collector/Controller** — the central application. It manages host enrollment, aggregates metadata/search results, coordinates actions, hosts the human UI, and runs the embedded Codex assistant. It does not directly mount or browse remote files.

```text
                   Human UI
            Tauri 2 + React/TypeScript
                         |
              AMCP Collector/Controller
       host registry, federation, UI, approvals,
       global search, embedded Codex, audit view
              /              |              \
     secure host link   secure host link   secure host link
          /                    |                    \
   AMCP Agent A          AMCP Agent B          AMCP Agent C
   local core             local core             local core
   provider adapters      provider adapters      provider adapters
   local index            local index            local index
   local policy           local policy           local policy
       |                      |                      |
 Codex / Claude /       Codex / Kiro /       Antigravity / ...
 other local state      other local state    other local state
```

### Recommended technology choice

- **Language:** Rust 2024 edition.
- **Desktop shell:** Tauri 2. It keeps the application shell and privileged operations in Rust while enabling a fast, information-dense UI.
- **Frontend:** React + TypeScript, with a component library and a code editor such as CodeMirror or Monaco.
- **Core storage/index:** SQLite with FTS5. Keep the index rebuildable; native Codex files remain the source of truth.
- **Parsing:** `toml_edit` for comment-preserving TOML, `serde`/`serde_json` for JSON/JSONL, `walkdir`/`notify` for discovery and changes, `sha2` or BLAKE3 for content hashes.
- **Transport:** JSON-RPC client for Codex app-server; MCP stdio server/gateway for AMCP tools; versioned authenticated Agent ↔ Controller protocol for host links.
- **Testing:** Rust unit/property tests for parsers and change planning; fixture-based integration tests; Playwright or Tauri WebDriver smoke tests for the critical UI path.

### Rust workspace layout

```text
crates/
  amcp-domain/       entities, IDs, value objects, capability model
  amcp-core/         commands, queries, policies, change planning
  amcp-providers/    provider trait and provider-neutral artifact model
  amcp-codex/        Codex config, guidance, memory, session adapters
  amcp-index/        SQLite schema, FTS5, indexing and watchers
  amcp-app-server/   Codex app-server JSON-RPC client and event model
  amcp-mcp/          AMCP MCP server and tool schemas
  amcp-agent/        local host daemon, provider lifecycle, local RPC
  amcp-controller/   host registry, federation, global queries, approvals
apps/
  amcp-desktop/      Tauri controller shell, lifecycle, UI bridge
ui/                  React/TypeScript human interface
fixtures/
  codex/             versioned safe sample Codex homes and projects
  providers/          safe fixtures for future Claude Code, Antigravity, Kiro adapters
```

### Core invariants

1. Native provider state is authoritative; the AMCP index is disposable.
2. Every mutation is represented as a `ChangeSet` before it is applied.
3. Every change checks the source content hash immediately before writing.
4. Every mutation is attributable to a human action or an embedded-agent tool call.
5. Read permissions and write permissions are separate capabilities.
6. Authentication and secret-bearing files are never returned through normal read APIs.
7. A parser failure never causes a destructive fallback or an automatic rewrite.

## 5. Provider adapter architecture

AMCP must model “agent provider” separately from “host”. One host may run several providers, and one provider may have several projects or profiles.

### Provider contract

Each provider implements a versioned `AgentProvider` trait with these capabilities:

```rust
trait AgentProvider {
    fn descriptor(&self) -> ProviderDescriptor;
    fn discover(&self, context: DiscoveryContext) -> Result<DiscoveryReport>;
    fn inspect(&self, artifact: ArtifactRef) -> Result<ArtifactView>;
    fn search_projection(&self) -> Result<Vec<SearchDocument>>;
    fn plan_change(&self, request: ChangeRequest) -> Result<ChangeSet>;
    fn apply_change(&self, change: ApprovedChangeSet) -> Result<ChangeReceipt>;
    fn capabilities(&self) -> ProviderCapabilities;
}
```

The exact Rust signatures may evolve, but the boundary must remain provider-neutral. A provider adapter may use files, SQLite, a CLI, an app-server, or a vendor API internally. The rest of AMCP sees normalized artifacts and capability declarations.

### Normalized artifact categories

Every provider maps its native state into some or all of these categories:

- `Instruction` — durable guidance, rules, or system prompts.
- `Configuration` — settings, profiles, models, permissions, tools, and integrations.
- `Memory` — durable learned context, summaries, facts, or recalled preferences.
- `Session` — conversation, task, thread, transcript, rollout, or run history.
- `Tooling` — MCP servers, plugins, skills, hooks, commands, or extensions.
- `ProjectContext` — repository, workspace, branch, working directory, or project membership.
- `RuntimeEvent` — active process, approval, tool call, error, or status event.

Each normalized artifact retains `provider_kind`, `native_type`, `native_id`, `source_path_or_endpoint`, `support_level`, `schema_fingerprint`, and evidence links. Normalization must never discard the native representation needed for a faithful edit or audit.

### Initial and future adapters

| Provider | MVP role | Adapter responsibility |
| --- | --- | --- |
| Codex | Full implementation | `CODEX_HOME`, config layers, AGENTS guidance, memories, sessions, app-server, MCP |
| Claude Code | Contract fixture and planned adapter | Discover vendor config, project guidance, memory, session, and MCP artifacts when implemented |
| Antigravity | Contract fixture and planned adapter | Discover provider-specific project/user state and runtime artifacts when implemented |
| Kiro | Contract fixture and planned adapter | Discover provider-specific project/user state and runtime artifacts when implemented |
| Future agents | Extension point | Add a crate/plugin without changing controller, index, or UI contracts |

The UI must not contain provider-specific path logic. It should render the normalized artifact model and use provider capability flags to decide which actions are available.

### Provider capability levels

- `inventory` — identify the provider and list artifacts.
- `read` — inspect safe native state.
- `search` — project content into the local index.
- `propose` — generate a change set.
- `apply` — apply approved changes safely.
- `runtime` — attach to live sessions/events.
- `archive` / `delete` — lifecycle operations, always separately declared.

## 6. Domain model

```text
Host
  id, display_name, platform, hostname, agent_endpoint, status, last_seen

AgentProvider
  id, host_id, kind, display_name, version, adapter_version, capabilities, status

Project
  id, host_id, provider_id, root_path, git_remote, trust_level, last_seen

ConfigDocument
  id, host_id, project_id?, scope, path, format, hash, parse_status

GuidanceDocument
  id, host_id, project_id?, directory, kind, path, precedence_rank, hash

MemoryRecord
  id, host_id, provider_id, source_path?, storage_kind, title, summary, evidence, timestamps

Session
  id, host_id, provider_id, project_id?, native_id, title, cwd, model, branch,
  created_at, updated_at, archived, native_path, source_kind

ChangeSet
  id, actor, reason, status, created_at, operations[], expected_hashes[]

AuditEvent
  id, actor, operation, target, before_hash, after_hash, result, timestamp
```

The model intentionally separates a session/thread from its rollout file and separates a configuration document from its effective values. This permits app-server-backed sessions and filesystem-backed legacy records to coexist.

## 7. Local Agent and Collector/Controller

### AMCP Agent responsibilities

The Agent is the trusted local execution boundary. It runs on the system that contains the coding-agent state and is the only component allowed to directly inspect or mutate that state.

- Register the host and installed provider adapters.
- Discover local providers, projects, configuration layers, memories, sessions, and runtime processes.
- Maintain a local rebuildable index for fast search and offline operation.
- Connect to native runtime interfaces such as Codex app-server.
- Enforce local path, trust, redaction, approval, and capability policies.
- Plan and apply local changes atomically, with backups and audit records.
- Stream indexing progress, runtime events, approvals, and change receipts to the Controller.
- Continue operating in local/offline mode if the Controller is unavailable.

The Agent should run as a user-level service, not as a root/system daemon, unless a future provider explicitly requires elevated installation. It should expose a loopback IPC endpoint for the local desktop Controller and an authenticated remote endpoint for enrolled Controllers.

### Collector/Controller responsibilities

The Controller is the central coordination and human-facing component. The embedded Codex assistant normally runs here; its AMCP tools route through the Controller to the selected local Agent, so Codex can reason over a remote host without receiving direct filesystem access.

- Maintain the registry of connected hosts and provider instances.
- Enroll, authenticate, suspend, and remove hosts.
- Federate search and metadata queries across Agents.
- Route a requested read/proposal/apply operation to the owning Agent.
- Aggregate normalized artifacts into a central memory/catalog database without requiring remote filesystem mounts.
- Maintain central indexes for human search and embedded-agent retrieval across hosts and providers.
- Optionally build and query a RAG index from approved, redacted collected data.
- Host the Tauri UI, approval queue, change review, and audit explorer.
- Run the embedded Codex app-server integration and expose AMCP MCP tools to it.
- Select the target host/provider context for each Codex task and include that scope in every tool call.
- Maintain controller-owned metadata such as aliases, tags, saved searches, and cross-host relationships.
- Show capability and connectivity gaps explicitly rather than presenting remote data as fully available.

### Host protocol

Define a versioned, typed protocol for Agent ↔ Controller operations. The initial implementation may use local JSON-RPC over Unix domain socket/loopback and a secure WebSocket or QUIC transport for remote hosts. The protocol must support:

- `host/register`, `host/heartbeat`, `host/capabilities`, `host/unregister`;
- paginated `artifact/list`, `artifact/read`, and `search/query`;
- `change/propose`, `change/apply`, `change/rollback`;
- `session/subscribe` and streamed runtime/index events;
- request IDs, deadlines, cancellation, resumable cursors, and idempotency keys;
- per-request authorization context and audit correlation IDs.

The Controller sends intents and scoped requests; the Agent makes the final local policy decision. A disconnected or compromised Controller must not bypass Agent-side protections.

### Data placement

| Data | Local Agent | Central Controller |
| --- | --- | --- |
| Raw provider files and databases | Authoritative | Never authoritative |
| Raw transcripts and memories | Optional, policy-controlled | Never copied by default; references/excerpts only when allowed |
| Normalized memory records and provenance | Source-derived | Central collected catalog |
| Local search index | Yes, for offline/local operation | Central lexical index for federated search |
| Optional embeddings/RAG chunks | No or local temporary copy | Central derived index, disabled by default |
| Host/provider capabilities | Source | Registry copy |
| Change backups and local audit | Yes | Receipt and audit summary |
| Tags, saved searches, host aliases | Optional | Yes |
| Credentials and tokens | Native OS/provider store only | Never stored |

## 8. Provider-specific adapter implementation

The following adapters are Codex’s initial implementation behind the provider-neutral contract. Their names must not leak into controller or UI logic; they are registered under the `codex` provider ID.

### `CodexHomeAdapter`

- Resolve `CODEX_HOME` without expanding or storing credentials.
- Parse user config, profile config, system config when readable, and project `.codex/config.toml`.
- Preserve unknown TOML keys and comments.
- Label keys that are ignored or restricted at project scope.
- Never expose `auth.json`, token values, keychain contents, or environment-secret values.

### `ProjectAdapter`

- Start with known project paths from Codex state and session `cwd` values.
- Validate that paths still exist and detect Git roots.
- Allow explicit user-added scan roots.
- Apply a trust state: unknown, trusted, untrusted, inaccessible.
- Do not activate or execute project hooks while indexing.

### `GuidanceAdapter`

- Discover the AGENTS chain from global Codex home through project root to current directory.
- Show merge order and “closer file wins” relationships.
- Treat `AGENTS.override.md` and fallback names as distinct source kinds.
- Provide a rendered effective guidance view plus the original files.

### `MemoryAdapter`

- Read documented memory files when present.
- Detect supported SQLite-backed memory stores by schema fingerprint and Codex version.
- Prefer public app-server/session APIs where they expose a stable memory-related view.
- If a memory store is unsupported, expose inventory and diagnostics rather than editing it.
- Keep memory records linked to source sessions/evidence when the source provides those links.

### `SessionAdapter`

- Prefer a local Codex app-server connection for thread list/read/resume/archive/delete/unarchive and streaming events.
- Use the app-server thread ID as the canonical identity.
- Use filesystem scanning for inventory, archived/legacy records, and offline search fallback.
- Index `history.jsonl`, rollout JSONL, and metadata without assuming one permanent schema.
- Treat raw transcript content as sensitive and make retention/indexing configurable.

### Provider registry

- Load the built-in Codex adapter first.
- Register future providers through a compiled crate initially; consider signed dynamic plugins only after the security model is mature.
- Store adapter health and compatibility per host/provider pair.
- Do not let one provider’s parser failure stop discovery for other providers on the same host.
- Use fixture suites per provider and contract tests against the normalized artifact model.

### Versioning rule

Every adapter reports `adapter_version`, `provider_version`, `schema_fingerprint`, and `support_level` (`full`, `read-only`, `inventory-only`, `unsupported`). This is essential because provider state formats can change independently of public protocols.

## 9. AMCP API and MCP surface

The internal API should use the same typed command/query model as the UI and MCP server. MCP is an adapter over that model, not a second business-logic implementation.

### Read/query tools

- `hosts_list` — connected hosts, health, capabilities, and last-seen status.
- `providers_list` — providers installed on a host and adapter support status.
- `projects_list` — known projects, provider, trust state, and indexing status.
- `config_effective_get` — effective configuration plus source layers and precedence.
- `document_read` — safe document content with redaction and line ranges.
- `search` — FTS query with filters and evidence references.
- `guidance_chain_get` — ordered AGENTS guidance for a project/directory.
- `memory_search` — search local memory records and evidence.
- `memory_get` — read a normalized memory record, provenance, lifecycle, and source evidence.
- `memory_collection_status` — report Agent sync cursors, freshness, coverage, redaction, and retention state.
- `retrieve_context` — optional hybrid lexical/semantic retrieval for RAG, always returning citations and scope metadata.
- `sessions_list` — page through session metadata across hosts/providers.
- `session_read` — read a session summary or selected transcript range.
- `diagnostics_run` — report stale files, parse failures, trust problems, unsupported formats, and conflicts.

### Proposal and mutation tools

- `change_propose` — create a diff-backed change set; no write.
- `change_review` — return diff, affected scopes, risk classification, and expected hashes.
- `change_apply` — apply an approved change set atomically.
- `change_rollback` — restore the recorded pre-change content.
- `session_archive` / `session_unarchive` — delegate to app-server where possible.
- `session_delete` — destructive, always requires explicit confirmation and a second warning.

### Tool contract requirements

- All tools return structured JSON with `request_id`, `host_id`, `provider_id`, `evidence[]`, and `warnings[]`.
- Mutation tools require `change_set_id` and an approval token issued by the human UI.
- Tools must accept a narrow `scope` (`host_id`, `provider_id`, project, artifact, or session) rather than an unrestricted filesystem path where possible.
- Results must distinguish “not found”, “not indexed”, “unsupported”, “untrusted”, and “permission denied”.
- MCP server instructions should explain the scope, approval requirement, redaction policy, and first-step workflow in a short self-contained preamble.

## 10. UI specification

### Shell

- Left rail: Hosts, Providers, Projects, Sessions, Memories, Configuration, Diagnostics.
- Center: table, graph, search results, editor, or transcript depending on route.
- Right inspector: source path, scope, trust, effective value, provenance, hash, last update, and actions.
- Persistent top bar: global search, active host/provider scope, aggregate index status, Controller/Agent connectivity, pending approvals.

### Primary screens

1. **System map** — Controller connected to host Agents, providers, projects, sessions, config layers, memories, and recent changes.
2. **Host detail** — Agent health, installed providers, capabilities, indexing state, and local policy.
3. **Project detail** — effective provider context with a layer-by-layer explanation.
4. **Provider detail** — provider version, adapter support, native roots, capabilities, and diagnostics.
5. **Configuration explorer** — side-by-side native content, parsed values, provenance, and warnings.
6. **Guidance explorer** — provider-neutral instruction chain with merged preview and file-level navigation.
7. **Memory browser** — searchable memory records with provider, host, evidence, age, usage, and confidence labels.
8. **Session explorer** — searchable list and transcript viewer; filters for host, provider, project, branch, model, date, and archive state.
9. **Collection and RAG settings** — per-host/provider consent, ingestion coverage, retention, embedding provider, index health, rebuild, and delete controls.
7. **Change review** — diff, risk, affected files, backup location, approval controls, and post-apply verification.
8. **Embedded Codex** — conversation view with streamed events, tool calls, approvals, and clickable evidence.
9. **Diagnostics** — parser support, stale index, missing paths, trust state, conflicting edits, and unsupported formats.

### Human approval UX

Every write displays:

- exact files and lines/keys affected;
- before/after diff;
- why the change was recommended;
- evidence used by Codex;
- risk level and whether the file is project- or user-scoped;
- backup and rollback action;
- external-change conflict status.

## 11. Security and safety

### Default policy

Each AMCP Agent launches read-only. Search and inspect are safe capabilities. Propose is allowed without writing. Apply, archive, unarchive, and delete are separate capabilities and require a human approval flow. The Controller can coordinate an operation, but the Agent makes the final local authorization decision.

### Sensitive data handling

- Exclude `auth.json`, access tokens, API keys, cookies, keychain data, and secret-looking environment values from indexing and MCP output.
- Redact common secret patterns before content reaches the embedded model.
- Store the AMCP index in the user’s application-data directory with restrictive permissions.
- Make transcript indexing opt-in or configurable for privacy-sensitive users.
- Do not upload local state to a remote service in the MVP.
- Treat the central database as sensitive: use restrictive filesystem permissions in local mode and authenticated/encrypted transport plus database encryption or encrypted storage in server mode.
- Keep raw content, normalized summaries, lexical indexes, and embeddings under separate retention/deletion controls.

### File safety

- Path allowlist per host and project.
- No symlink traversal outside approved roots.
- Atomic temp-file write + rename.
- Pre-write content hash check.
- Backup before mutation.
- File watcher marks index entries stale after external changes.
- Never execute hooks, MCP servers, project scripts, or shell commands merely to inspect configuration.

### Embedded-agent safety

- Run app-server under an explicit working directory and permission profile.
- Keep AMCP MCP tools narrowly scoped and typed.
- Require approval for any tool marked destructive or side-effecting.
- Add a kill/cancel control for active turns.
- Show the full tool call and result in the conversation timeline.
- Record all agent-originated changes in the audit log.
- Ensure RAG context includes source citations and never becomes an untraceable replacement for the underlying memory record.

## 12. Central memory database, indexes, and optional RAG

The Controller owns a central database that collects normalized memory information, artifact metadata, provenance, and search projections from connected Agents. Native provider state remains authoritative; the central database is the authoritative catalog of what AMCP has collected and is allowed to search.

This database must support both human search and embedded-agent retrieval through the same query service. The UI and MCP tools must not implement separate search logic.

### Collection pipeline

```text
Agent discovery
      |
      v
Provider adapter normalization
      |
      v
classification + secret redaction + consent policy
      |
      v
central memory/catalog database
      |
      +--> lexical index (MVP, always available)
      |
      +--> optional semantic/vector index
      |
      +--> optional RAG retrieval context with citations
```

For each collected item, the Controller stores the provider, host, project, native identifier, source reference, content hash, timestamps, classification, retention policy, and provenance. It should store redacted excerpts or summaries by default; raw transcript/memory content is collected only when the host policy allows it.

### Memory lifecycle

Memory records have an explicit lifecycle:

- `discovered` — observed by an Agent but not yet normalized;
- `candidate` — normalized and eligible for review/indexing;
- `approved` — permitted for central search and/or RAG;
- `active` — currently valid according to the latest source observation;
- `stale` — source changed, unavailable, or outside retention policy;
- `superseded` — replaced by a newer memory record;
- `deleted` — removed from the central database and derived indexes.

This prevents an old session summary from silently becoming permanent truth. Every memory result must show source age, provider, host, confidence/quality metadata, and whether it is current or stale.

### Suggested tables

```text
hosts, providers, projects, documents, document_versions, guidance_edges,
memory_records, memory_sources, memory_observations, sessions, session_items,
search_content, search_chunks, embeddings, retrieval_runs,
change_sets, change_operations, audit_events, index_runs,
agent_connections, provider_capabilities, sync_cursors, controller_tags
```

Use SQLite with FTS5 for the first central deployment. For a multi-user/server deployment, keep the storage interface portable to PostgreSQL or another central database. Store metadata, hashes, provenance, and lifecycle state in ordinary tables; store large transcript bodies either in a retention-controlled content table or as references to native files. Support cancellation, incremental indexing, per-host sync cursors, and resumable collection.

### Search for humans and agents

- Lexical search is always available and is the MVP baseline.
- Search filters include host, provider, project, artifact type, date, lifecycle, trust, and sensitivity class.
- Results return ranked matches plus evidence references, source paths/IDs, line or chunk ranges, and freshness.
- The same `SearchService` powers the UI, REST/internal commands, and AMCP MCP tools.
- Agent retrieval must be scope-aware: the Controller passes the selected host/provider/project scope and the search service enforces it.

### Optional RAG mode

RAG is a derived feature, not the source of truth and not required for basic search.

- Disabled by default until the user enables it for selected hosts/providers/projects.
- Chunks only approved/redacted records; never embed secret-bearing content.
- Uses a pluggable embedding provider: local embedding model, configured OpenAI API, or another explicitly configured provider.
- Stores embedding model, dimensions, source hash, consent/policy version, and creation time with every vector.
- Uses hybrid retrieval when enabled: lexical matches plus semantic similarity, followed by scope, freshness, and sensitivity filtering.
- Produces context packets containing citations, not uncited prose. Codex must be able to open the underlying evidence through AMCP tools.
- Rebuilds or invalidates derived embeddings when the source hash, retention policy, or embedding model changes.
- Supports “delete everywhere”: deleting a central memory record removes its lexical chunks, embeddings, cached retrieval context, and controller references.

### RAG configuration controls

The Controller UI should expose:

- enabled providers/hosts/projects;
- raw-content versus excerpt-only ingestion;
- local versus remote embedding provider;
- retention duration;
- maximum chunk size and retrieval budget;
- whether external-context sessions may contribute to memory;
- reset/rebuild/delete controls;
- current index coverage and last successful collection time.

Initial indexing priority:

1. provider/host/project inventory and configuration metadata;
2. guidance and rules;
3. memory records and provenance;
4. session metadata and recent transcript excerpts;
5. full historical transcripts when explicitly enabled;
6. lexical index refresh;
7. optional embeddings/RAG chunks;
8. diagnostics and reconciliation.

## 13. Multi-host operation

Multi-host support is a core product capability, even if the hackathon demo uses one or two local Agents. The Controller must treat every host as an independent authority and every provider installation as a separate capability set.

### Operating modes

- **Embedded/local mode:** Controller and Agent run in one desktop process or on one system. This is the simplest MVP installation.
- **Controller mode:** the desktop application runs as the central Collector/Controller and connects to one or more Agents.
- **Agent-only mode:** a headless local service runs discovery/indexing and waits for an enrolled Controller.
- **Disconnected mode:** the Agent continues local indexing and queues event/receipt synchronization until the Controller reconnects.

### Remote design requirements

- explicit host enrollment and visible identity;
- per-host path/capability policy;
- mutual authentication or short-lived pairing tokens;
- no default public listener;
- streamed events with reconnect and backpressure;
- local audit log on both sides;
- offline/read-only behavior when a host is unavailable.

The Controller must never make a remote host appear writable merely because a UI user has global permission. The Agent’s local policy, provider capability, project trust, and current file hash all participate in the final decision.

## 14. Delivery plan

### Phase 0 — Spike

- Verify Codex CLI version and app-server launch on the target development machine.
- Define and test the provider-neutral artifact and capability contracts.
- Build a minimal AMCP Agent that registers one local Codex provider.
- Build a minimal Controller ↔ Agent heartbeat and query path.
- Build a Rust app-server client that can list/read a thread and stream one turn.
- Parse `config.toml`, `.codex/config.toml`, profiles, and AGENTS chains with fixtures.
- Confirm Tauri 2 shell and React UI boot.

### Phase 1 — Read-only explorer

- Host/project discovery.
- Host enrollment and provider registry.
- Central memory/catalog database with collection cursors and provenance.
- Config, guidance, session inventory, and basic search.
- SQLite index with incremental refresh.
- System map and project detail screens.
- Sensitive-file redaction and diagnostics.

### Phase 2 — Embedded Codex

- App-server supervision and conversation UI.
- Local AMCP MCP server.
- Evidence links from Codex responses into the explorer.
- Read-only recommendations and diagnostics workflows.
- Shared SearchService and `memory_search`/`retrieve_context` tools over the central database.

### Phase 3 — Safe changes

- Change sets, diff review, approvals, atomic writes, backups, rollback, audit log.
- App-server-backed archive/unarchive.
- Conflict detection and post-apply verification.

### Phase 4 — Additional hosts and providers

- Secure enrollment for a second host and remote Agent lifecycle.
- Contract-tested Claude Code, Antigravity, and Kiro adapters, beginning with inventory/read-only support.
- Cross-provider and cross-host comparison and policy recommendations.
- Optional RAG embeddings and hybrid retrieval with explicit consent and deletion controls.

## 15. Hackathon demo acceptance criteria

The Codex-first MVP is demo-ready when it can:

- run a local Agent and Controller, with the Controller visibly showing the Agent’s health and capabilities;
- collect normalized memory records and provenance into the central database;
- discover the local Codex home and at least five real project roots through the Codex provider adapter;
- display the distinction between user config, project config, profiles, and guidance;
- show a searchable list of stored sessions with provider, project, and date metadata;
- open a session and show transcript evidence without exposing credentials;
- run embedded Codex against AMCP tools;
- produce one useful recommendation grounded in at least two local evidence items;
- show a human-readable diff and require approval before changing a file;
- apply the change, create a backup, refresh the index, and show rollback;
- survive a simulated external file edit by refusing to overwrite a changed file.
- keep the provider-neutral UI/API operational when a second provider is registered as `inventory-only`.
- return the same cited search result through the human UI and embedded Codex MCP tool.

## 16. Risks and open decisions

- **Codex private state formats:** keep adapters versioned and fail closed; do not make SQLite internals the core dependency.
- **Transcript privacy:** decide default retention and whether full transcript indexing is opt-in.
- **Central memory governance:** define which normalized records are automatically collected versus requiring approval, and how deletion propagates to every derived index.
- **RAG quality and cost:** keep RAG optional; measure citation coverage, stale-memory rate, retrieval precision, embedding cost, and latency before enabling it by default.
- **App-server availability:** provide a read-only filesystem fallback and an explicit degraded-mode indicator.
- **UI framework scope:** Tauri 2 + React is recommended for hackathon speed; revisit a native Rust UI only if cross-platform packaging becomes the dominant constraint.
- **Embedded Codex credentials:** reuse the user’s existing Codex login through the local app-server only with explicit consent; never copy credentials into AMCP storage.
- **Change semantics for generated memories:** start with read-only memory management until a documented write API or stable file format is available.
- **Remote hosts:** design the protocol now, but do not add network exposure to the MVP.

## 17. Official references

- [Codex configuration basics](https://learn.chatgpt.com/docs/config-file/config-basic)
- [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Codex advanced configuration and state locations](https://learn.chatgpt.com/docs/config-file/config-advanced)
- [Codex customization overview](https://learn.chatgpt.com/docs/customization/overview)
- [Codex memories](https://learn.chatgpt.com/docs/customization/memories)
- [Codex AGENTS.md guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
- [Codex MCP integration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Codex app-server protocol](https://learn.chatgpt.com/docs/app-server)
- [Codex as an MCP server](https://learn.chatgpt.com/docs/mcp-server)

## 18. Local discovery note

The initial workspace itself was empty, but the current machine’s Codex home contained enough real state to validate the premise: approximately 1.0 GB under `~/.codex`, 81 stored threads in the current state database, 20 distinct working directories, 117 session files, and an archived-session area. These counts are discovery-time observations, not product assumptions; the indexer must handle missing, stale, mixed-version, and unsupported records gracefully.
