import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

type Host = {
  identity: { host_id: string; display_name: string; platform: string; hostname: string };
  status: string;
  capabilities: string[];
  agent_version?: string;
  last_seen?: string;
};

type Provider = {
  host_id: string;
  provider_id: string;
  display_name: string;
  version?: string;
  adapter_version: string;
  capabilities: string[];
};

type SearchHit = {
  artifact_id: string;
  title: string;
  source_reference: string;
  preview: string;
  host_id: string;
  provider_id: string;
  sensitivity: string;
  observed_at: string;
};

type ArtifactRecord = {
  artifact_id: string;
  host_id: string;
  provider_id: string;
  title: string;
  source_reference: string;
  content: string;
  sensitivity: string;
  observed_at: string;
};

type ChangeSet = {
  change_set_id: string;
  reason: string;
  status: string;
  provider_id: string;
  actor: string;
  operations: Array<{ target: { source_reference: string }; diff: string }>;
};

type Project = {
  project_id: string;
  display_name: string;
  root_path: string;
  trust_level?: string;
};

type Session = {
  session_id: string;
  title?: string;
  cwd?: string;
  model?: string;
  archived: boolean;
  observed_at: string;
};

type SessionItem = {
  session_id: string;
  sequence: number;
  role?: string;
  item_kind: string;
  content?: string;
  source_reference: string;
  observed_at: string;
};

type Memory = {
  memory_record_id: string;
  title: string;
  content: string;
  lifecycle: string;
  source_reference: string;
};

type ConfigLayer = {
  config_layer_id: string;
  source_reference: string;
  scope: string;
  profile?: string;
  precedence_rank: number;
};

type Guidance = {
  guidance_id: string;
  source_reference: string;
  kind: string;
  precedence_rank: number;
};

type RuntimeEvent = {
  event_id: string;
  host_id: string;
  provider_id: string;
  event_type: string;
  sequence: number;
  payload_json: string;
  occurred_at: string;
};

function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [changes, setChanges] = useState<ChangeSet[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionItems, setSessionItems] = useState<SessionItem[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [configLayers, setConfigLayers] = useState<ConfigLayer[]>([]);
  const [guidance, setGuidance] = useState<Guidance[]>([]);
  const [runtimeEvents, setRuntimeEvents] = useState<RuntimeEvent[]>([]);
  const [selectedHostId, setSelectedHostId] = useState("");
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [query, setQuery] = useState("sandbox");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [selected, setSelected] = useState<SearchHit | null>(null);
  const [artifactDetail, setArtifactDetail] = useState<ArtifactRecord | null>(null);
  const [readingArtifact, setReadingArtifact] = useState(false);
  const [replacementText, setReplacementText] = useState("");
  const [changeReason, setChangeReason] = useState("Update agent document from AMCP");
  const [proposingArtifact, setProposingArtifact] = useState(false);
  const [activeNav, setActiveNav] = useState("System map");
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [approving, setApproving] = useState<string | null>(null);
  const [codexPrompt, setCodexPrompt] = useState("Summarize the most important configuration and memory signals in AMCP.");
  const [codexReply, setCodexReply] = useState<string | null>(null);
  const [askingCodex, setAskingCodex] = useState(false);
  const [proposingRuntime, setProposingRuntime] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      invoke<Host[]>("list_hosts"),
      invoke<Provider[]>("list_providers"),
      invoke<ChangeSet[]>("list_changes"),
      invoke<Project[]>("list_projects"),
      invoke<Session[]>("list_sessions"),
      invoke<Memory[]>("list_memory"),
      invoke<ConfigLayer[]>("list_config_layers"),
      invoke<Guidance[]>("list_guidance"),
      invoke<RuntimeEvent[]>("list_runtime_events", { hostId: null, providerId: null }),
    ])
      .then(([nextHosts, nextProviders, nextChanges, nextProjects, nextSessions, nextMemories, nextConfigLayers, nextGuidance, nextRuntimeEvents]) => {
        setHosts(nextHosts);
        setProviders(nextProviders);
        setChanges(nextChanges);
        setProjects(nextProjects);
        setSessions(nextSessions);
        setMemories(nextMemories);
        setConfigLayers(nextConfigLayers);
        setGuidance(nextGuidance);
        setRuntimeEvents(nextRuntimeEvents);
      })
      .catch((reason) => setError(String(reason)));
  }, []);

  const search = async (event?: React.FormEvent) => {
    event?.preventDefault();
    if (!query.trim()) return;
    try {
      setError(null);
      const nextHits = await invoke<SearchHit[]>("search_catalog", {
        query,
        hostId: selectedHostId || null,
        providerId: selectedProviderId || null,
      });
      setHits(nextHits);
      setSelected(nextHits[0] ?? null);
    } catch (reason) {
      setError(String(reason));
    }
  };

  const syncLocal = async () => {
    try {
      setSyncing(true);
      setError(null);
      await invoke("collect_local", { providerId: selectedProviderId || "codex" });
      const [nextHosts, nextProviders, nextChanges, nextProjects, nextSessions, nextMemories, nextConfigLayers, nextGuidance, nextRuntimeEvents] = await Promise.all([
        invoke<Host[]>("list_hosts"),
        invoke<Provider[]>("list_providers"),
        invoke<ChangeSet[]>("list_changes"),
        invoke<Project[]>("list_projects"),
        invoke<Session[]>("list_sessions"),
        invoke<Memory[]>("list_memory"),
        invoke<ConfigLayer[]>("list_config_layers"),
        invoke<Guidance[]>("list_guidance"),
        invoke<RuntimeEvent[]>("list_runtime_events", {
          hostId: selectedHostId || null,
          providerId: selectedProviderId || null,
        }),
      ]);
      setHosts(nextHosts);
      setProviders(nextProviders);
      setChanges(nextChanges);
      setProjects(nextProjects);
      setSessions(nextSessions);
      setMemories(nextMemories);
      setConfigLayers(nextConfigLayers);
      setGuidance(nextGuidance);
      setRuntimeEvents(nextRuntimeEvents);
      await search();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSyncing(false);
    }
  };

  const refreshRuntimeEvents = async () => {
    try {
      setRuntimeEvents(await invoke<RuntimeEvent[]>("list_runtime_events", {
        hostId: selectedHostId || null,
        providerId: selectedProviderId || null,
      }));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const approve = async (changeSetId: string) => {
    try {
      setApproving(changeSetId);
      setError(null);
      await invoke("approve_change", { changeSetId, approvedBy: "desktop-human" });
      const nextChanges = await invoke<ChangeSet[]>("list_changes");
      setChanges(nextChanges);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setApproving(null);
    }
  };

  const askCodex = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!codexPrompt.trim()) return;
    try {
      setAskingCodex(true);
      setError(null);
      const result = await invoke<{ text: string }>("ask_codex", { prompt: codexPrompt });
      setCodexReply(result.text || "Codex completed without a text response.");
      setSessions(await invoke<Session[]>("list_sessions"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setAskingCodex(false);
    }
  };

  const inspectArtifact = async (hit: SearchHit) => {
    setSelected(hit);
    setArtifactDetail(null);
    try {
      setReadingArtifact(true);
      setError(null);
      const artifact = await invoke<ArtifactRecord>("read_artifact", {
        hostId: hit.host_id,
        providerId: hit.provider_id,
        sourceReference: hit.source_reference,
      });
      setArtifactDetail(artifact);
      setReplacementText(artifact.content);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setReadingArtifact(false);
    }
  };

  const proposeArtifactChange = async () => {
    if (!selected || !artifactDetail || !replacementText.trim()) return;
    try {
      setProposingArtifact(true);
      setError(null);
      await invoke("propose_artifact_change", {
        hostId: selected.host_id,
        providerId: selected.provider_id,
        sourceReference: selected.source_reference,
        replacement: replacementText,
        reason: changeReason,
      });
      setChanges(await invoke<ChangeSet[]>("list_changes"));
      setReplacementText("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setProposingArtifact(false);
    }
  };

  const inspectSession = async (session: Session) => {
    try {
      setError(null);
      setSelectedSessionId(session.session_id);
      setSessionItems(await invoke<SessionItem[]>("list_session_items", { sessionId: session.session_id }));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const proposeRuntimeChange = async (session: Session) => {
    try {
      setProposingRuntime(session.session_id);
      setError(null);
      await invoke("propose_runtime_change", {
        threadId: session.session_id,
        archived: !session.archived,
      });
      setChanges(await invoke<ChangeSet[]>("list_changes"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setProposingRuntime(null);
    }
  };

  const connectedHosts = useMemo(() => hosts.filter((host) => host.status === "Connected"), [hosts]);

  const navigation = [
    ["System map", "⌘"],
    ["Hosts", String(hosts.length)],
    ["Providers", String(providers.length)],
    ["Projects", String(projects.length)],
    ["Configuration", String(configLayers.length)],
    ["Guidance", String(guidance.length)],
    ["Memories", String(memories.length)],
    ["Sessions", String(sessions.length)],
    ["Changes", String(changes.filter((change) => change.status === "Proposed").length)],
  ];

  return (
    <main className="app-shell">
      <aside className="rail">
        <div className="brand"><span className="brand-mark">A</span><span>AMCP</span><small>control plane</small></div>
        <div className="rail-label">Workspace</div>
        <nav>
          {navigation.map(([label, count]) => (
            <button className={activeNav === label ? "nav-item active" : "nav-item"} key={label} onClick={() => setActiveNav(label)}>
              <span className="nav-icon">{label.slice(0, 1)}</span><span>{label}</span><em>{count}</em>
            </button>
          ))}
        </nav>
        <div className="rail-footer"><div className="avatar">M</div><div><strong>Local workspace</strong><small>macOS · private</small></div><span className="dot green" /></div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><div className="eyebrow">{activeNav} / overview</div><h1>Agent state, made legible.</h1></div>
          <div className="top-actions"><span className="connection"><span className="dot green" /> Controller online</span><select className="scope-select" value={selectedHostId} onChange={(event) => setSelectedHostId(event.target.value)}><option value="">All hosts</option>{hosts.map((host) => <option key={host.identity.host_id} value={host.identity.host_id}>{host.identity.display_name}</option>)}</select><select className="scope-select" value={selectedProviderId} onChange={(event) => setSelectedProviderId(event.target.value)}><option value="">All providers</option>{providers.filter((provider) => !selectedHostId || provider.host_id === selectedHostId).map((provider) => <option key={`${provider.host_id}-${provider.provider_id}`} value={provider.provider_id}>{provider.display_name}</option>)}</select><button className="secondary sync-button" onClick={() => void syncLocal()} disabled={syncing}>{syncing ? "Syncing…" : "Sync now"}</button><button className="icon-button">?</button><button className="avatar">M</button></div>
        </header>

        <section className="content">
          <div className="status-row">
            <div className="status-card"><span className="status-icon violet">⌁</span><div><small>Connected hosts</small><strong>{connectedHosts.length || hosts.length || 0}<span> / {hosts.length || 1}</span></strong></div><span className="trend">↗ healthy</span></div>
            <div className="status-card"><span className="status-icon blue">⌂</span><div><small>Indexed artifacts</small><strong>{projects.length + sessions.length + memories.length + configLayers.length + guidance.length || "—"}</strong></div><span className="muted">normalized catalog</span></div>
            <div className="status-card"><span className="status-icon blue">◉</span><div><small>Active providers</small><strong>{providers.length || "—"}</strong></div><span className="muted">capability registry</span></div>
            <div className="status-card"><span className="status-icon orange">◈</span><div><small>Pending approval</small><strong>{changes.filter((change) => change.status === "Proposed").length}</strong></div><span className="muted">review required</span></div>
          </div>

          <form className="search-box" onSubmit={search}><span className="search-icon">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search configuration, memory, sessions…"/><kbd>⌘ K</kbd><button type="submit">Search</button></form>
          {error && <div className="error-banner">{error}</div>}

          <section className="codex-section">
            <div className="section-heading"><div><span className="eyebrow">Embedded agent</span><h2>Ask Codex about this control plane</h2></div><span className="scope-pill"><span className="dot green" /> AMCP tools enabled</span></div>
            <form className="codex-box" onSubmit={askCodex}><textarea value={codexPrompt} onChange={(event) => setCodexPrompt(event.target.value)} /><button className="primary" type="submit" disabled={askingCodex}>{askingCodex ? "Thinking…" : "Ask Codex"}</button></form>
            {codexReply && <div className="codex-reply"><div className="evidence-heading"><span>Codex response</span><span className="verified">✓ app-server</span></div><pre>{codexReply}</pre></div>}
          </section>

          <div className="section-heading"><div><span className="eyebrow">Unified index</span><h2>Search evidence</h2></div><span className="scope-pill"><span className="dot green" /> {selectedHostId || "All connected hosts"}{selectedProviderId ? ` · ${selectedProviderId}` : ""}</span></div>
          <div className="explorer">
            <div className="results-panel">
              <div className="panel-toolbar"><span>{hits.length ? `${hits.length} results` : "Run a search to inspect indexed evidence"}</span><button>Filters ˅</button></div>
              {hits.map((hit) => <button className={selected?.artifact_id === hit.artifact_id ? "result selected" : "result"} key={hit.artifact_id} onClick={() => void inspectArtifact(hit)}><div className="result-top"><span className="type-chip">{hit.provider_id}</span><time>{new Date(hit.observed_at).toLocaleDateString()}</time></div><strong>{hit.title}</strong><p>{hit.preview}</p><small>{hit.source_reference}</small></button>)}
              {!hits.length && <div className="empty-state"><div className="empty-glyph">⌁</div><strong>Search the AMCP catalog</strong><p>Results are redacted, source-linked, and scoped to the connected hosts.</p><button className="primary" onClick={() => void search()}>Search “{query}”</button></div>}
            </div>
            <aside className="inspector">
              {selected ? <><div className="inspector-header"><span className="type-chip">{selected.provider_id}</span><span className="verified">{readingArtifact ? "Reading live…" : artifactDetail ? "✓ live redacted read" : "indexed preview"}</span></div><h3>{selected.title}</h3><p className="path">{selected.source_reference}</p><div className="meta-grid"><div><small>Host</small><strong>{selected.host_id}</strong></div><div><small>Sensitivity</small><strong>{selected.sensitivity}</strong></div><div><small>Artifact</small><strong>{selected.artifact_id.slice(0, 16)}</strong></div><div><small>Observed</small><strong>{new Date(selected.observed_at).toLocaleString()}</strong></div></div><div className="evidence"><div className="evidence-heading"><span>{artifactDetail ? "Live artifact content" : "Evidence preview"}</span><span className="verified">✓ redacted</span></div><pre>{artifactDetail?.content ?? selected.preview}</pre></div><button className="secondary" onClick={() => void inspectArtifact(selected)} disabled={readingArtifact}>{readingArtifact ? "Reading…" : "Read from Agent"}</button>{artifactDetail && <div className="proposal-editor"><div className="evidence-heading"><span>Propose replacement</span><span className="verified">Approval required</span></div><textarea value={replacementText} onChange={(event) => setReplacementText(event.target.value)} /><input value={changeReason} onChange={(event) => setChangeReason(event.target.value)} aria-label="Change reason" /><button className="primary" onClick={() => void proposeArtifactChange()} disabled={proposingArtifact || !replacementText.trim()}>{proposingArtifact ? "Creating proposal…" : "Create change proposal"}</button></div>}</> : <div className="inspector-empty"><span>◌</span><p>Select an evidence record to inspect provenance, scope, and safe content.</p></div>}
            </aside>
          </div>

          <section className="runtime-section">
            <div className="section-heading"><div><span className="eyebrow">Runtime telemetry</span><h2>Recent agent activity</h2></div><button className="secondary refresh-button" onClick={() => void refreshRuntimeEvents()}>Refresh events</button></div>
            <div className="runtime-list">{runtimeEvents.slice(0, 8).map((event) => <article className="runtime-row" key={event.event_id}><span className="runtime-marker">●</span><div><strong>{event.event_type}</strong><small>{event.host_id} · {event.provider_id} · seq {event.sequence}</small></div><time>{new Date(event.occurred_at).toLocaleString()}</time><code>{event.payload_json}</code></article>)}{!runtimeEvents.length && <div className="change-empty">No runtime events in the selected scope.</div>}</div>
          </section>

          <section className="changes-section">
            <div className="section-heading"><div><span className="eyebrow">Policy gate</span><h2>Change queue</h2></div><span className="scope-pill">Human approval required</span></div>
            <div className="change-list">
              {changes.length ? changes.map((change) => <article className="change-row" key={change.change_set_id}>
                <div className="change-main"><span className={change.status === "Proposed" ? "status-badge pending" : "status-badge"}>{change.status}</span><strong>{change.reason}</strong><small>{change.change_set_id} · {change.operations.length} operation{change.operations.length === 1 ? "" : "s"}</small></div>
                <div className="change-target">{change.operations[0]?.target.source_reference ?? "No target"}</div>
                {change.status === "Proposed" && <button className="primary approve-button" onClick={() => void approve(change.change_set_id)} disabled={approving === change.change_set_id}>{approving === change.change_set_id ? "Applying…" : "Approve & apply"}</button>}
              </article>) : <div className="change-empty">No proposed changes. Controller proposals will appear here with their diff and provenance.</div>}
            </div>
          </section>

          <section className="inventory-section">
            <div className="section-heading"><div><span className="eyebrow">Normalized catalog</span><h2>Projects, memories, sessions</h2></div><span className="scope-pill">Source-linked records</span></div>
            <div className="inventory-grid">
              <div className="inventory-card"><div className="inventory-card-head"><strong>Providers</strong><span>{providers.length}</span></div>{providers.slice(0, 4).map((provider) => <div className="inventory-item" key={`${provider.host_id}-${provider.provider_id}`}><span className="inventory-symbol">◉</span><div><strong>{provider.display_name}</strong><small>{provider.host_id} · {provider.capabilities.slice(0, 3).join(", ") || "inventory-only"}</small></div></div>)}{!providers.length && <div className="change-empty">No provider capabilities reported yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Configuration</strong><span>{configLayers.length}</span></div>{configLayers.slice(0, 4).map((layer) => <div className="inventory-item" key={layer.config_layer_id}><span className="inventory-symbol">⚙</span><div><strong>{layer.profile ?? layer.scope}</strong><small>precedence {layer.precedence_rank} · {layer.source_reference}</small></div></div>)}{!configLayers.length && <div className="change-empty">No normalized config layers yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Guidance chain</strong><span>{guidance.length}</span></div>{guidance.slice(0, 4).map((item) => <div className="inventory-item" key={item.guidance_id}><span className="inventory-symbol">☷</span><div><strong>{item.kind}</strong><small>precedence {item.precedence_rank} · {item.source_reference}</small></div></div>)}{!guidance.length && <div className="change-empty">No AGENTS guidance discovered yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Projects</strong><span>{projects.length}</span></div>{projects.slice(0, 4).map((project) => <div className="inventory-item" key={project.project_id}><span className="inventory-symbol">◈</span><div><strong>{project.display_name}</strong><small>{project.trust_level ?? "trust unknown"} · {project.root_path}</small></div></div>)}{!projects.length && <div className="change-empty">No normalized projects yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Memories</strong><span>{memories.length}</span></div>{memories.slice(0, 4).map((memory) => <div className="inventory-item" key={memory.memory_record_id}><span className="inventory-symbol">✦</span><div><strong>{memory.title}</strong><small>{memory.lifecycle} · {memory.source_reference}</small></div></div>)}{!memories.length && <div className="change-empty">No normalized memories yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Sessions</strong><span>{sessions.length}</span></div>{sessions.slice(0, 4).map((session) => <div className="session-entry" key={session.session_id}><button className={selectedSessionId === session.session_id ? "inventory-item session-item selected" : "inventory-item session-item"} onClick={() => void inspectSession(session)}><span className="inventory-symbol">◌</span><div><strong>{session.title ?? session.session_id}</strong><small>{session.model ?? "model unknown"} · {session.archived ? "archived" : "active"}</small></div></button><button className="session-action" onClick={() => void proposeRuntimeChange(session)} disabled={proposingRuntime === session.session_id}>{proposingRuntime === session.session_id ? "…" : session.archived ? "Unarchive" : "Archive"}</button></div>)}{!sessions.length && <div className="change-empty">No normalized sessions yet.</div>}</div>
            </div>
            {selectedSessionId && <div className="session-inspector"><div className="section-heading"><div><span className="eyebrow">Session evidence</span><h2>{selectedSessionId}</h2></div><span className="scope-pill">{sessionItems.length} bounded items</span></div><div className="session-item-list">{sessionItems.map((item) => <article className="session-event" key={`${item.session_id}-${item.sequence}`}><div><span className="type-chip">{item.role ?? "event"}</span><strong>{item.item_kind}</strong><time>{new Date(item.observed_at).toLocaleString()}</time></div>{item.content ? <pre>{item.content}</pre> : <small>Metadata-only event; transcript payload is not stored.</small>}</article>)}{!sessionItems.length && <div className="change-empty">No session items available.</div>}</div></div>}
          </section>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
