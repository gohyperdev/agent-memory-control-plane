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

type ChangeSet = {
  change_set_id: string;
  reason: string;
  status: string;
  provider_id: string;
  actor: string;
  operations: Array<{ target: { source_reference: string }; diff: string }>;
};

const navigation = [
  ["System map", "⌘"],
  ["Hosts", "2"],
  ["Projects", "12"],
  ["Configuration", "9"],
  ["Guidance", "24"],
  ["Memories", "41"],
  ["Sessions", "128"],
  ["Changes", "1"]
];

function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [changes, setChanges] = useState<ChangeSet[]>([]);
  const [query, setQuery] = useState("sandbox");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [selected, setSelected] = useState<SearchHit | null>(null);
  const [activeNav, setActiveNav] = useState("System map");
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [approving, setApproving] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([invoke<Host[]>("list_hosts"), invoke<ChangeSet[]>("list_changes")])
      .then(([nextHosts, nextChanges]) => {
        setHosts(nextHosts);
        setChanges(nextChanges);
      })
      .catch((reason) => setError(String(reason)));
  }, []);

  const search = async (event?: React.FormEvent) => {
    event?.preventDefault();
    if (!query.trim()) return;
    try {
      setError(null);
      const nextHits = await invoke<SearchHit[]>("search_catalog", { query });
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
      await invoke("collect_local");
      const [nextHosts, nextChanges] = await Promise.all([invoke<Host[]>("list_hosts"), invoke<ChangeSet[]>("list_changes")]);
      setHosts(nextHosts);
      setChanges(nextChanges);
      await search();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSyncing(false);
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

  const connectedHosts = useMemo(() => hosts.filter((host) => host.status === "Connected"), [hosts]);

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
          <div className="top-actions"><span className="connection"><span className="dot green" /> Controller online</span><button className="secondary sync-button" onClick={() => void syncLocal()} disabled={syncing}>{syncing ? "Syncing…" : "Sync now"}</button><button className="icon-button">?</button><button className="avatar">M</button></div>
        </header>

        <section className="content">
          <div className="status-row">
            <div className="status-card"><span className="status-icon violet">⌁</span><div><small>Connected hosts</small><strong>{connectedHosts.length || hosts.length || 0}<span> / {hosts.length || 1}</span></strong></div><span className="trend">↗ healthy</span></div>
            <div className="status-card"><span className="status-icon blue">⌂</span><div><small>Indexed artifacts</small><strong>{hits.length ? "1,284" : "—"}</strong></div><span className="muted">last sync 2m ago</span></div>
            <div className="status-card"><span className="status-icon orange">◈</span><div><small>Pending approval</small><strong>{changes.filter((change) => change.status === "Proposed").length}</strong></div><span className="muted">review required</span></div>
          </div>

          <form className="search-box" onSubmit={search}><span className="search-icon">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search configuration, memory, sessions…"/><kbd>⌘ K</kbd><button type="submit">Search</button></form>
          {error && <div className="error-banner">{error}</div>}

          <div className="section-heading"><div><span className="eyebrow">Unified index</span><h2>Search evidence</h2></div><span className="scope-pill"><span className="dot green" /> All connected hosts</span></div>
          <div className="explorer">
            <div className="results-panel">
              <div className="panel-toolbar"><span>{hits.length ? `${hits.length} results` : "Run a search to inspect indexed evidence"}</span><button>Filters ˅</button></div>
              {hits.map((hit) => <button className={selected?.artifact_id === hit.artifact_id ? "result selected" : "result"} key={hit.artifact_id} onClick={() => setSelected(hit)}><div className="result-top"><span className="type-chip">{hit.provider_id}</span><time>{new Date(hit.observed_at).toLocaleDateString()}</time></div><strong>{hit.title}</strong><p>{hit.preview}</p><small>{hit.source_reference}</small></button>)}
              {!hits.length && <div className="empty-state"><div className="empty-glyph">⌁</div><strong>Search the AMCP catalog</strong><p>Results are redacted, source-linked, and scoped to the connected hosts.</p><button className="primary" onClick={() => void search()}>Search “{query}”</button></div>}
            </div>
            <aside className="inspector">
              {selected ? <><div className="inspector-header"><span className="type-chip">{selected.provider_id}</span><button>•••</button></div><h3>{selected.title}</h3><p className="path">{selected.source_reference}</p><div className="meta-grid"><div><small>Host</small><strong>{selected.host_id}</strong></div><div><small>Sensitivity</small><strong>{selected.sensitivity}</strong></div><div><small>Artifact</small><strong>{selected.artifact_id.slice(0, 16)}</strong></div><div><small>Observed</small><strong>{new Date(selected.observed_at).toLocaleString()}</strong></div></div><div className="evidence"><div className="evidence-heading"><span>Evidence preview</span><span className="verified">✓ redacted</span></div><pre>{selected.preview}</pre></div><button className="secondary">Open in explorer</button></> : <div className="inspector-empty"><span>◌</span><p>Select an evidence record to inspect provenance, scope, and safe content.</p></div>}
            </aside>
          </div>

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
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
