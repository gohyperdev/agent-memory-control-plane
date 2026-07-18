import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./styles.css";

type Host = {
  identity: { host_id: string; display_name: string; platform: string; hostname: string };
  status: string;
  capabilities: string[];
  agent_version?: string;
  last_seen?: string;
};

type HostAlias = {
  host_id: string;
  alias: string;
  updated_at: string;
};

type ControllerTag = {
  tag_id: string;
  name: string;
  created_at: string;
};

type CrossHostRelationship = {
  relationship_id: string;
  relationship_kind: string;
  left_artifact_id: string;
  left_host_id: string;
  left_title: string;
  right_artifact_id: string;
  right_host_id: string;
  right_title: string;
  created_at: string;
};

type CatalogBackup = {
  backup_path: string;
  reason: string;
  created_at: string;
  size_bytes: number;
};

type Provider = {
  host_id: string;
  provider_id: string;
  display_name: string;
  provider_version?: string;
  /** Backwards-compatible data from catalogs created before provider_version. */
  version?: string;
  adapter_version: string;
  schema_fingerprint: string;
  support_level: string;
  health: string;
  compatibility: string;
  native_roots: string[];
  capabilities: string[];
};

type SearchHit = {
  artifact_id: string;
  project_id?: string;
  project_trust_level?: string;
  kind: string;
  lifecycle: string;
  title: string;
  source_reference: string;
  preview: string;
  host_id: string;
  provider_id: string;
  sensitivity: string;
  observed_at: string;
};

type SavedSearchFilters = {
  host_id?: string;
  provider_id?: string;
  project_id?: string;
  project_trust_levels: string[];
  artifact_kinds: string[];
  lifecycle_states: string[];
  sensitivity_max?: string;
  observed_after?: string;
  observed_before?: string;
};

type SavedSearch = {
  saved_search_id: string;
  name: string;
  query: string;
  filters: SavedSearchFilters;
  created_at: string;
  updated_at: string;
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
  scope?: { host_id?: string };
  evidence_ids: string[];
  operations: Array<{
    target: { source_reference: string };
    operation: string;
    diff: string;
    expected_source_hash?: string;
    before_hash?: string;
    after_hash?: string;
  }>;
};

type Project = {
  project_id: string;
  host_id: string;
  provider_id: string;
  display_name: string;
  root_path: string;
  trust_level?: string;
};

type Session = {
  session_id: string;
  host_id: string;
  provider_id: string;
  project_id?: string;
  title?: string;
  cwd?: string;
  model?: string;
  branch?: string;
  started_at?: string;
  archived: boolean;
  source_reference: string;
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

type CodexStreamEvent = {
  request_id: string;
  method: string;
  turn_id?: string;
  item_id?: string;
  status?: string;
  text?: string;
};

type Memory = {
  memory_record_id: string;
  host_id: string;
  provider_id: string;
  title: string;
  content: string;
  lifecycle: string;
  source_reference: string;
};

type ConfigLayer = {
  config_layer_id: string;
  host_id: string;
  provider_id: string;
  project_id?: string;
  source_reference: string;
  scope: string;
  profile?: string;
  precedence_rank: number;
};

type Guidance = {
  guidance_id: string;
  host_id: string;
  provider_id: string;
  project_id?: string;
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

type AuditEvent = {
  audit_event_id: string;
  actor: string;
  operation: string;
  target: string;
  host_id?: string;
  provider_id?: string;
  result: string;
  timestamp: string;
};

type RagStats = {
  chunk_count: number;
  source_count: number;
  retrieval_run_count: number;
  average_retrieval_latency_ms?: number;
  retrieval_context_item_count: number;
  retrieval_citation_count: number;
  retrieval_citation_coverage_basis_points: number;
  oldest_indexed_at?: string;
  newest_indexed_at?: string;
};

type RagScope = {
  host_id?: string;
  provider_id?: string;
  project_id?: string;
};

type RagConfig = {
  enabled: boolean;
  allowed_scopes: RagScope[];
  embedding_provider?: string;
  embedding_model?: string;
  retention_days?: number;
  chunk_size: number;
  retrieval_limit: number;
};

const defaultRagConfig: RagConfig = {
  enabled: false,
  allowed_scopes: [],
  chunk_size: 800,
  retrieval_limit: 5,
};

type Diagnostics = {
  generated_at: string;
  latest_index_run?: { status: string; mode: string; indexed_count: number; completed_at?: string };
  pending_change_count: number;
  recent_event_count: number;
  recent_collection_runs: Array<{ provider_id: string; status: string; duration_ms: number; discovered_count: number; inserted_count: number; failure_kind?: string; completed_at: string }>;
  recent_search_runs: Array<{ duration_ms: number; result_count: number; limit: number; completed_at: string }>;
  catalog_diagnostics: {
    total_artifact_count: number;
    stale_artifact_count: number;
    stale_source_ratio: number;
    search_indexed_artifact_count: number;
    search_index_coverage_ratio: number;
    database_size_bytes: number;
    applied_change_count: number;
    conflicted_change_count: number;
    rolled_back_change_count: number;
    stale_artifacts: unknown[];
    projects_requiring_attention: unknown[];
    conflicted_changes: unknown[];
    recent_provider_diagnostic_event_count: number;
  };
  rag: RagStats;
  content_included: boolean;
};

function dateTimeLocalFromIso(value?: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "";
  return new Date(date.valueOf() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostAliases, setHostAliases] = useState<HostAlias[]>([]);
  const [hostAliasDrafts, setHostAliasDrafts] = useState<Record<string, string>>({});
  const [savingHostAlias, setSavingHostAlias] = useState<string | null>(null);
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
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [selectedHostId, setSelectedHostId] = useState("");
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedProjectTrust, setSelectedProjectTrust] = useState("");
  const [selectedArtifactKind, setSelectedArtifactKind] = useState("");
  const [selectedLifecycle, setSelectedLifecycle] = useState("");
  const [sensitivityMax, setSensitivityMax] = useState("");
  const [observedAfter, setObservedAfter] = useState("");
  const [observedBefore, setObservedBefore] = useState("");
  const [sessionBranch, setSessionBranch] = useState("");
  const [sessionModel, setSessionModel] = useState("");
  const [sessionArchiveState, setSessionArchiveState] = useState("");
  const [sessionStartedAfter, setSessionStartedAfter] = useState("");
  const [sessionStartedBefore, setSessionStartedBefore] = useState("");
  const [query, setQuery] = useState("sandbox");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [recommendationEvidenceIds, setRecommendationEvidenceIds] = useState<string[]>([]);
  const [lastRecommendationEvidence, setLastRecommendationEvidence] = useState<SearchHit[]>([]);
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [savedSearchName, setSavedSearchName] = useState("");
  const [savingSearch, setSavingSearch] = useState(false);
  const [selected, setSelected] = useState<SearchHit | null>(null);
  const [artifactTags, setArtifactTags] = useState<ControllerTag[]>([]);
  const [newArtifactTag, setNewArtifactTag] = useState("");
  const [taggingArtifact, setTaggingArtifact] = useState(false);
  const [crossHostRelationships, setCrossHostRelationships] = useState<CrossHostRelationship[]>([]);
  const [crossHostTargetId, setCrossHostTargetId] = useState("");
  const [crossHostRelationshipKind, setCrossHostRelationshipKind] = useState("related");
  const [linkingCrossHost, setLinkingCrossHost] = useState(false);
  const [artifactDetail, setArtifactDetail] = useState<ArtifactRecord | null>(null);
  const [readingArtifact, setReadingArtifact] = useState(false);
  const [replacementText, setReplacementText] = useState("");
  const [changeReason, setChangeReason] = useState("Update agent document from AMCP");
  const [proposingArtifact, setProposingArtifact] = useState(false);
  const [activeNav, setActiveNav] = useState("System map");
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [additionalScanRoots, setAdditionalScanRoots] = useState(() => localStorage.getItem("amcp.additionalScanRoots") ?? "");
  const [approving, setApproving] = useState<string | null>(null);
  const [rollingBack, setRollingBack] = useState<string | null>(null);
  const [codexPrompt, setCodexPrompt] = useState("Summarize the most important configuration and memory signals in AMCP.");
  const [codexReply, setCodexReply] = useState<string | null>(null);
  const [codexRuntimeState, setCodexRuntimeState] = useState<"on-demand" | "available" | "degraded">("on-demand");
  const [askingCodex, setAskingCodex] = useState(false);
  const [activeCodexRequestId, setActiveCodexRequestId] = useState<string | null>(null);
  const [codexEvents, setCodexEvents] = useState<CodexStreamEvent[]>([]);
  const [proposingRuntime, setProposingRuntime] = useState<string | null>(null);
  const [remoteUrl, setRemoteUrl] = useState("tcp://");
  const [remoteCaPath, setRemoteCaPath] = useState("");
  const [remoteServerName, setRemoteServerName] = useState("");
  const [remotePairingCode, setRemotePairingCode] = useState("");
  const [remoteBootstrapToken, setRemoteBootstrapToken] = useState("");
  const [remoteHostId, setRemoteHostId] = useState("");
  const [remoteToken, setRemoteToken] = useState("");
  const [remoteProviderId, setRemoteProviderId] = useState("codex");
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [forgettingMemory, setForgettingMemory] = useState<string | null>(null);
  const [ragStats, setRagStats] = useState<RagStats | null>(null);
  const [ragConfig, setRagConfig] = useState<RagConfig>(defaultRagConfig);
  const [savingRagConfig, setSavingRagConfig] = useState(false);
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const [backingUpCatalog, setBackingUpCatalog] = useState(false);
  const [lastCatalogBackup, setLastCatalogBackup] = useState<CatalogBackup | null>(null);
  const catalogedCodexProjectRoots = projects.filter((project) => project.provider_id === "codex").length;
  const remainingMvpProjectRoots = Math.max(0, 5 - catalogedCodexProjectRoots);
  const selectedAdditionalRootCount = additionalScanRoots.split(/\r?\n/).map((root) => root.trim()).filter(Boolean).length;

  const sessionFilters = () => ({
    hostId: selectedHostId || null,
    providerId: selectedProviderId || null,
    projectId: selectedProjectId || null,
    branch: sessionBranch || null,
    model: sessionModel || null,
    archived: sessionArchiveState === "archived" ? true : sessionArchiveState === "active" ? false : null,
    startedAfter: sessionStartedAfter ? new Date(sessionStartedAfter).toISOString() : null,
    startedBefore: sessionStartedBefore ? new Date(sessionStartedBefore).toISOString() : null,
  });

  const searchFilters = () => ({
    hostId: selectedHostId || null,
    providerId: selectedProviderId || null,
    projectId: selectedProjectId || null,
    projectTrustLevels: selectedProjectTrust ? [selectedProjectTrust] : [],
    artifactKinds: selectedArtifactKind ? [selectedArtifactKind] : [],
    lifecycleStates: selectedLifecycle ? [selectedLifecycle] : [],
    sensitivityMax: sensitivityMax || null,
    observedAfter: observedAfter ? new Date(observedAfter).toISOString() : null,
    observedBefore: observedBefore ? new Date(observedBefore).toISOString() : null,
  });

  const refreshCatalog = async (hostId = selectedHostId, providerId = selectedProviderId) => {
    const [nextHosts, nextHostAliases, nextProviders, nextChanges, nextProjects, nextSessions, nextMemories, nextConfigLayers, nextGuidance, nextRuntimeEvents, nextAuditEvents, nextRagStats, nextDiagnostics, nextSavedSearches] = await Promise.all([
      invoke<Host[]>("list_hosts"),
      invoke<HostAlias[]>("list_host_aliases"),
      invoke<Provider[]>("list_providers"),
      invoke<ChangeSet[]>("list_changes"),
      invoke<Project[]>("list_projects", { hostId: hostId || null }),
      invoke<Session[]>("list_sessions", { filters: sessionFilters() }),
      invoke<Memory[]>("list_memory", { hostId: hostId || null, providerId: providerId || null, projectId: selectedProjectId || null }),
      invoke<ConfigLayer[]>("list_config_layers", { hostId: hostId || null, providerId: providerId || null, projectId: selectedProjectId || null }),
      invoke<Guidance[]>("list_guidance", { hostId: hostId || null, providerId: providerId || null, projectId: selectedProjectId || null }),
      invoke<RuntimeEvent[]>("list_runtime_events", {
        hostId: hostId || null,
        providerId: providerId || null,
      }),
      invoke<AuditEvent[]>("list_audit_events", {
        hostId: hostId || null,
        providerId: providerId || null,
        limit: 20,
      }),
      invoke<RagStats>("rag_status"),
      invoke<Diagnostics>("diagnostics_snapshot"),
      invoke<SavedSearch[]>("list_saved_searches"),
    ]);
    setHosts(nextHosts);
    setHostAliases(nextHostAliases);
    setHostAliasDrafts((drafts) => Object.fromEntries(nextHosts.map((host) => [host.identity.host_id, drafts[host.identity.host_id] ?? nextHostAliases.find((alias) => alias.host_id === host.identity.host_id)?.alias ?? ""])));
    setProviders(nextProviders);
    setChanges(nextChanges);
    setProjects(nextProjects);
    setSessions(nextSessions);
    setMemories(nextMemories);
    setConfigLayers(nextConfigLayers);
    setGuidance(nextGuidance);
    setRuntimeEvents(nextRuntimeEvents);
    setAuditEvents(nextAuditEvents);
    setRagStats(nextRagStats);
    setDiagnostics(nextDiagnostics);
    setSavedSearches(nextSavedSearches);
  };

  useEffect(() => {
    refreshCatalog().catch((reason) => setError(String(reason)));
  }, []);

  useEffect(() => {
    invoke<RagConfig>("rag_config")
      .then(setRagConfig)
      .catch((reason) => setError(String(reason)));
  }, []);

  useEffect(() => {
    if (!selected || selected.artifact_id.startsWith("source:")) {
      setArtifactTags([]);
      setCrossHostRelationships([]);
      return;
    }
    invoke<ControllerTag[]>("list_artifact_tags", { artifactId: selected.artifact_id })
      .then(setArtifactTags)
      .catch((reason) => setError(String(reason)));
    invoke<CrossHostRelationship[]>("list_cross_host_relationships", { artifactId: selected.artifact_id })
      .then(setCrossHostRelationships)
      .catch((reason) => setError(String(reason)));
  }, [selected?.artifact_id]);

  useEffect(() => {
    refreshCatalog().catch((reason) => setError(String(reason)));
  }, [selectedHostId, selectedProviderId, selectedProjectId]);

  useEffect(() => {
    invoke<Session[]>("list_sessions", { filters: sessionFilters() })
      .then((nextSessions) => {
        setSessions(nextSessions);
        if (selectedSessionId && !nextSessions.some((session) => session.session_id === selectedSessionId)) {
          setSelectedSessionId(null);
          setSessionItems([]);
        }
      })
      .catch((reason) => setError(String(reason)));
  }, [selectedHostId, selectedProviderId, selectedProjectId, sessionBranch, sessionModel, sessionArchiveState, sessionStartedAfter, sessionStartedBefore]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    listen<CodexStreamEvent>("amcp://codex-turn-event", (event) => {
      if (!disposed) setCodexEvents((events) => [...events.slice(-31), event.payload]);
    }).then((handler) => {
      if (disposed) handler();
      else unlisten = handler;
    }).catch((reason) => setError(String(reason)));
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const runSearch = async (nextQuery: string, filters = searchFilters()) => {
    if (!nextQuery.trim()) return;
    try {
      setError(null);
      const nextHits = await invoke<SearchHit[]>("search_catalog", {
        query: nextQuery,
        filters,
      });
      setHits(nextHits);
      setRecommendationEvidenceIds([]);
      setSelected(nextHits[0] ?? null);
    } catch (reason) {
      setError(String(reason));
    }
  };

  const search = async (event?: React.FormEvent) => {
    event?.preventDefault();
    await runSearch(query);
  };

  const saveCurrentSearch = async () => {
    if (!query.trim()) return;
    try {
      setSavingSearch(true);
      setError(null);
      const saved = await invoke<SavedSearch>("save_saved_search", {
        name: savedSearchName || query.trim(),
        query,
        filters: searchFilters(),
      });
      setSavedSearches((searches) => [...searches.filter((search) => search.saved_search_id !== saved.saved_search_id), saved].sort((left, right) => left.name.localeCompare(right.name)));
      setSavedSearchName("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSavingSearch(false);
    }
  };

  const applySavedSearch = async (saved: SavedSearch) => {
    const filters = {
      hostId: saved.filters.host_id || null,
      providerId: saved.filters.provider_id || null,
      projectId: saved.filters.project_id || null,
      projectTrustLevels: saved.filters.project_trust_levels || [],
      artifactKinds: saved.filters.artifact_kinds || [],
      lifecycleStates: saved.filters.lifecycle_states || [],
      sensitivityMax: saved.filters.sensitivity_max || null,
      observedAfter: saved.filters.observed_after || null,
      observedBefore: saved.filters.observed_before || null,
    };
    setQuery(saved.query);
    setSelectedHostId(saved.filters.host_id || "");
    setSelectedProviderId(saved.filters.provider_id || "");
    setSelectedProjectId(saved.filters.project_id || "");
    setSelectedProjectTrust(saved.filters.project_trust_levels?.[0] || "");
    setSelectedArtifactKind(saved.filters.artifact_kinds?.[0] || "");
    setSelectedLifecycle(saved.filters.lifecycle_states?.[0] || "");
    setSensitivityMax(saved.filters.sensitivity_max || "");
    setObservedAfter(dateTimeLocalFromIso(saved.filters.observed_after));
    setObservedBefore(dateTimeLocalFromIso(saved.filters.observed_before));
    await runSearch(saved.query, filters);
  };

  const deleteSearch = async (savedSearchId: string) => {
    try {
      await invoke<boolean>("delete_saved_search", { savedSearchId });
      setSavedSearches((searches) => searches.filter((search) => search.saved_search_id !== savedSearchId));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const addArtifactTag = async () => {
    if (!selected || selected.artifact_id.startsWith("source:") || !newArtifactTag.trim()) return;
    try {
      setTaggingArtifact(true);
      setError(null);
      const tag = await invoke<ControllerTag>("tag_artifact", { artifactId: selected.artifact_id, name: newArtifactTag });
      setArtifactTags((tags) => [...tags.filter((item) => item.tag_id !== tag.tag_id), tag].sort((left, right) => left.name.localeCompare(right.name)));
      setNewArtifactTag("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setTaggingArtifact(false);
    }
  };

  const removeArtifactTag = async (tagId: string) => {
    if (!selected || selected.artifact_id.startsWith("source:")) return;
    try {
      await invoke<boolean>("untag_artifact", { artifactId: selected.artifact_id, tagId });
      setArtifactTags((tags) => tags.filter((tag) => tag.tag_id !== tagId));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const linkCrossHostArtifact = async () => {
    if (!selected || selected.artifact_id.startsWith("source:") || !crossHostTargetId) return;
    try {
      setLinkingCrossHost(true);
      setError(null);
      const relationship = await invoke<CrossHostRelationship>("link_cross_host_artifacts", {
        firstArtifactId: selected.artifact_id,
        secondArtifactId: crossHostTargetId,
        relationshipKind: crossHostRelationshipKind,
      });
      setCrossHostRelationships((relationships) => [relationship, ...relationships.filter((item) => item.relationship_id !== relationship.relationship_id)]);
      setCrossHostTargetId("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLinkingCrossHost(false);
    }
  };

  const unlinkCrossHostArtifact = async (relationshipId: string) => {
    try {
      await invoke<boolean>("unlink_cross_host_relationship", { relationshipId });
      setCrossHostRelationships((relationships) => relationships.filter((relationship) => relationship.relationship_id !== relationshipId));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const backupCatalog = async () => {
    try {
      setBackingUpCatalog(true);
      setError(null);
      const backup = await invoke<CatalogBackup>("backup_catalog", { reason: "desktop-user-request" });
      setLastCatalogBackup(backup);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBackingUpCatalog(false);
    }
  };

  const saveHostAlias = async (hostId: string) => {
    const alias = hostAliasDrafts[hostId]?.trim() ?? "";
    try {
      setSavingHostAlias(hostId);
      setError(null);
      if (!alias) {
        await invoke<boolean>("delete_host_alias", { hostId });
        setHostAliases((aliases) => aliases.filter((item) => item.host_id !== hostId));
      } else {
        const saved = await invoke<HostAlias>("set_host_alias", { hostId, alias });
        setHostAliases((aliases) => [...aliases.filter((item) => item.host_id !== hostId), saved].sort((left, right) => left.alias.localeCompare(right.alias)));
      }
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSavingHostAlias(null);
    }
  };

  const syncLocal = async () => {
    try {
      setSyncing(true);
      setError(null);
      const scanRoots = additionalScanRoots.split(/\r?\n/).map((root) => root.trim()).filter(Boolean);
      localStorage.setItem("amcp.additionalScanRoots", additionalScanRoots);
      await invoke("collect_local", { providerId: selectedProviderId || undefined, scanRoots });
      await refreshCatalog();
      await search();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSyncing(false);
    }
  };

  const enrollAndSyncRemote = async () => {
    try {
      setRemoteBusy(true);
      setError(null);
      const result = await invoke<{ enrollment: { host_id: string } }>("enroll_remote", {
        agentUrl: remoteUrl,
        tlsCa: remoteCaPath,
        tlsServerName: remoteServerName || null,
        pairingCode: remotePairingCode,
        bootstrapToken: remoteBootstrapToken,
        providerId: remoteProviderId,
      });
      const hostId = result.enrollment.host_id;
      setRemoteHostId(hostId);
      setSelectedHostId(hostId);
      await refreshCatalog(hostId, remoteProviderId);
      setRemotePairingCode("");
      setRemoteBootstrapToken("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRemoteBusy(false);
    }
  };

  const syncRemote = async () => {
    try {
      setRemoteBusy(true);
      setError(null);
      await invoke("sync_remote", {
        agentUrl: remoteUrl,
        tlsCa: remoteCaPath,
        tlsServerName: remoteServerName || null,
        hostId: remoteHostId,
        token: remoteToken || null,
        providerId: remoteProviderId,
      });
      setSelectedHostId(remoteHostId);
      await refreshCatalog(remoteHostId, remoteProviderId);
      setRemoteToken("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRemoteBusy(false);
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

  const clearRagIndex = async () => {
    if (!window.confirm("Delete the derived RAG chunks and retrieval history? Native provider files and the AMCP catalog will remain untouched.")) return;
    try {
      setError(null);
      await invoke("clear_rag_index");
      setRagStats(await invoke<RagStats>("rag_status"));
    } catch (reason) {
      setError(String(reason));
    }
  };

  const saveRagConfig = async () => {
    try {
      setSavingRagConfig(true);
      setError(null);
      setRagConfig(await invoke<RagConfig>("save_rag_config", { config: ragConfig }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSavingRagConfig(false);
    }
  };

  const addSelectedRagScope = () => {
    const scope: RagScope = {
      host_id: selectedHostId || undefined,
      provider_id: selectedProviderId || undefined,
      project_id: selectedProjectId || undefined,
    };
    if (!scope.host_id && !scope.provider_id && !scope.project_id) {
      setError("Choose a host, provider, or project before adding a RAG scope.");
      return;
    }
    const key = JSON.stringify(scope);
    setRagConfig((current) => current.allowed_scopes.some((item) => JSON.stringify(item) === key)
      ? current
      : { ...current, allowed_scopes: [...current.allowed_scopes, scope] });
  };

  const removeRagScope = (scope: RagScope) => {
    const key = JSON.stringify(scope);
    setRagConfig((current) => ({
      ...current,
      allowed_scopes: current.allowed_scopes.filter((item) => JSON.stringify(item) !== key),
    }));
  };

  const forgetMemory = async (memory: Memory) => {
    if (!window.confirm(`Remove “${memory.title}” from the AMCP catalog, lexical search, and derived RAG data? The native provider file will not be changed. The same source version will stay excluded; a changed version may be collected again.`)) return;
    try {
      setForgettingMemory(memory.memory_record_id);
      setError(null);
      await invoke("forget_memory", {
        memoryRecordId: memory.memory_record_id,
        hostId: memory.host_id,
        providerId: memory.provider_id,
        reason: "Desktop human requested central memory deletion",
      });
      await refreshCatalog();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setForgettingMemory(null);
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

  const rollback = async (change: ChangeSet) => {
    const target = change.operations[0]?.target.source_reference ?? "the recorded target";
    if (!window.confirm(`Restore the recorded pre-change content for ${target}? This creates a new, approved rollback operation and will overwrite the current version only if its safety checks pass.`)) return;
    try {
      setRollingBack(change.change_set_id);
      setError(null);
      await invoke("rollback_change", { changeSetId: change.change_set_id, approvedBy: "desktop-human" });
      setChanges(await invoke<ChangeSet[]>("list_changes"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRollingBack(null);
    }
  };

  const executeCodexPrompt = async (prompt: string, grounding: SearchHit[] = []) => {
    if (!prompt.trim()) return;
    const requestId = crypto.randomUUID();
    try {
      setAskingCodex(true);
      setActiveCodexRequestId(requestId);
      setCodexEvents([]);
      setLastRecommendationEvidence([]);
      setError(null);
      const result = await invoke<{ text: string }>("ask_codex", { prompt, requestId });
      setCodexReply(result.text || "Codex completed without a text response.");
      setLastRecommendationEvidence(grounding);
      setCodexRuntimeState("available");
      setSessions(await invoke<Session[]>("list_sessions", { filters: sessionFilters() }));
    } catch (reason) {
      const message = String(reason);
      if (message.includes("Embedded Codex is unavailable")) setCodexRuntimeState("degraded");
      setError(message);
    } finally {
      setAskingCodex(false);
      setActiveCodexRequestId(null);
    }
  };

  const askCodex = async (event: React.FormEvent) => {
    event.preventDefault();
    await executeCodexPrompt(codexPrompt);
  };

  const selectedRecommendationEvidence = useMemo(
    () => recommendationEvidenceIds
      .map((artifactId) => hits.find((hit) => hit.artifact_id === artifactId))
      .filter((hit): hit is SearchHit => Boolean(hit)),
    [hits, recommendationEvidenceIds],
  );

  const toggleRecommendationEvidence = (artifactId: string) => {
    setRecommendationEvidenceIds((current) => current.includes(artifactId)
      ? current.filter((currentId) => currentId !== artifactId)
      : current.length >= 4 ? current : [...current, artifactId]);
  };

  const askEvidenceGroundedRecommendation = async () => {
    if (selectedRecommendationEvidence.length < 2) {
      setError("Choose at least two redacted catalog records before requesting a recommendation.");
      return;
    }
    const evidence = selectedRecommendationEvidence.map((hit) => [
      `[AMCP:${hit.artifact_id}]`,
      `title: ${hit.title}`,
      `kind: ${hit.kind}; host: ${hit.host_id}; provider: ${hit.provider_id}; observed: ${hit.observed_at}`,
      `source: ${hit.source_reference}`,
      `redacted excerpt: ${hit.preview.slice(0, 900)}`,
    ].join("\n")).join("\n\n");
    const prompt = [
      "Give one practical AMCP recommendation based only on the redacted catalog evidence below.",
      "State uncertainty instead of inventing facts. Cite every factual claim with its [AMCP:artifact-id] marker, and cite at least two distinct markers overall.",
      "Do not propose an automatic write; if a change could help, describe it as a human-reviewed proposal.",
      "\nCatalog evidence:\n",
      evidence,
    ].join("\n");
    await executeCodexPrompt(prompt, selectedRecommendationEvidence);
  };

  const cancelCodex = async () => {
    if (!activeCodexRequestId) return;
    try {
      await invoke("cancel_codex_turn", { requestId: activeCodexRequestId });
    } catch (reason) {
      setError(String(reason));
    }
  };

  const streamedCodexText = useMemo(() => codexEvents.map((event) => event.text ?? "").join(""), [codexEvents]);
  const hostIsConnected = (hostId: string) => hosts.some((host) => host.identity.host_id === hostId && host.status === "Connected");

  const inspectArtifact = async (hit: SearchHit) => {
    setSelected(hit);
    setArtifactDetail(null);
    if (!hostIsConnected(hit.host_id)) {
      setError("The selected host Agent is unavailable. Showing the indexed catalog preview; live reads and changes remain disabled until it reconnects.");
      return;
    }
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

  const inspectCatalogSource = (source: { source_reference: string; host_id: string; provider_id: string; project_id?: string }, kind: string, title: string) => {
    void inspectArtifact({
      artifact_id: `source:${source.host_id}:${source.provider_id}:${source.source_reference}`,
      host_id: source.host_id,
      provider_id: source.provider_id,
      project_id: source.project_id,
      project_trust_level: undefined,
      kind,
      lifecycle: "Active",
      title,
      source_reference: source.source_reference,
      preview: "Open the source-linked, redacted artifact from the Agent.",
      sensitivity: "Internal",
      observed_at: new Date().toISOString(),
    });
  };

  const selectedArtifactCanBeChanged = selected !== null
    && ["Configuration", "Instruction"].includes(selected.kind)
    && /(?:^|\/)(?:config\.toml|[^/]+\.config\.toml|AGENTS(?:\.override)?\.md)$/.test(selected.source_reference)
    && hostIsConnected(selected.host_id);

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
    if (!hostIsConnected(session.host_id)) {
      setError("The selected host Agent is unavailable. Runtime session changes remain disabled until it reconnects.");
      return;
    }
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
  const hostAliasById = useMemo(() => new Map(hostAliases.map((alias) => [alias.host_id, alias.alias])), [hostAliases]);
  const hostLabel = (hostId: string, nativeName = hostId) => hostAliasById.get(hostId) ? `${hostAliasById.get(hostId)} · ${nativeName}` : nativeName;
  const knownSessionBranches = useMemo(() => [...new Set(sessions.flatMap((session) => session.branch ? [session.branch] : []))].sort(), [sessions]);
  const knownSessionModels = useMemo(() => [...new Set(sessions.flatMap((session) => session.model ? [session.model] : []))].sort(), [sessions]);
  const selectedSession = sessions.find((session) => session.session_id === selectedSessionId);
  const selectedHostIsConnected = selected !== null && hostIsConnected(selected.host_id);
  const selectedArtifactCanBeTagged = selected !== null && !selected.artifact_id.startsWith("source:");
  const crossHostLinkCandidates = selected ? hits.filter((hit) => !hit.artifact_id.startsWith("source:") && hit.artifact_id !== selected.artifact_id && hit.host_id !== selected.host_id) : [];

  const navigation = [
    ["System map", "⌘"],
    ["Hosts", String(hosts.length)],
    ["Providers", String(providers.length)],
    ["Projects", String(projects.length)],
    ["Configuration", String(configLayers.length)],
    ["Guidance", String(guidance.length)],
    ["Memories", String(memories.length)],
    ["Sessions", String(sessions.length)],
    ["Diagnostics", diagnostics?.latest_index_run?.status ?? "—"],
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
          <div className="top-actions"><span className="connection"><span className="dot green" /> Controller online</span><select className="scope-select" value={selectedHostId} onChange={(event) => { setSelectedHostId(event.target.value); setSelectedProjectId(""); }}><option value="">All hosts</option>{hosts.map((host) => <option key={host.identity.host_id} value={host.identity.host_id}>{hostLabel(host.identity.host_id, host.identity.display_name)}</option>)}</select><select className="scope-select" value={selectedProviderId} onChange={(event) => { setSelectedProviderId(event.target.value); setSelectedProjectId(""); }}><option value="">All providers</option>{providers.filter((provider) => !selectedHostId || provider.host_id === selectedHostId).map((provider) => <option key={`${provider.host_id}-${provider.provider_id}`} value={provider.provider_id}>{provider.display_name}</option>)}</select><select className="scope-select" value={selectedProjectId} onChange={(event) => setSelectedProjectId(event.target.value)}><option value="">All projects</option>{projects.filter((project) => (!selectedHostId || project.host_id === selectedHostId) && (!selectedProviderId || project.provider_id === selectedProviderId)).map((project) => <option key={`${project.host_id}-${project.provider_id}-${project.project_id}`} value={project.project_id}>{project.display_name}</option>)}</select><button className="secondary sync-button" onClick={() => void syncLocal()} disabled={syncing}>{syncing ? "Syncing…" : "Sync now"}</button><button className="icon-button">?</button><button className="avatar">M</button></div>
        </header>

        <section className="content">
          <div className="status-row">
            <div className="status-card"><span className="status-icon violet">⌁</span><div><small>Connected hosts</small><strong>{connectedHosts.length || hosts.length || 0}<span> / {hosts.length || 1}</span></strong></div><span className="trend">↗ healthy</span></div>
            <div className="status-card"><span className="status-icon blue">⌂</span><div><small>Indexed artifacts</small><strong>{projects.length + sessions.length + memories.length + configLayers.length + guidance.length || "—"}</strong></div><span className="muted">normalized catalog</span></div>
            <div className="status-card"><span className="status-icon blue">◉</span><div><small>Active providers</small><strong>{providers.length || "—"}</strong></div><span className="muted">capability registry</span></div>
            <div className="status-card"><span className="status-icon orange">◈</span><div><small>Pending approval</small><strong>{changes.filter((change) => change.status === "Proposed").length}</strong></div><span className="muted">review required</span></div>
          </div>

          <section className="local-roots-section">
            <div className="section-heading"><div><span className="eyebrow">Local collection scope</span><h2>Additional Codex project roots</h2></div><span className="scope-pill">{catalogedCodexProjectRoots}/5 cataloged · local read-only discovery</span></div>
            <textarea value={additionalScanRoots} onChange={(event) => setAdditionalScanRoots(event.target.value)} placeholder="One absolute project directory per line" aria-label="Additional Codex project roots" />
            <small>These folders are sent only to the local Agent during the next sync, must already exist, and are never trusted for mutation merely by being indexed. {remainingMvpProjectRoots > 0 ? `Select ${remainingMvpProjectRoots} more real Codex project root${remainingMvpProjectRoots === 1 ? "" : "s"} to reach the five-root MVP smoke target${selectedAdditionalRootCount ? `; ${selectedAdditionalRootCount} selected for the next sync` : ""}.` : "The five-root MVP smoke target is met in the current catalog scope."}</small>
          </section>

          <section className="remote-section">
            <div className="section-heading"><div><span className="eyebrow">Multi-host</span><h2>Connect another AMCP Agent</h2></div><span className="scope-pill"><span className="dot green" /> TLS · no remote filesystem mount</span></div>
            <div className="remote-grid">
              <input value={remoteUrl} onChange={(event) => setRemoteUrl(event.target.value)} placeholder="tcp://host.example:45432" aria-label="Remote Agent URL" />
              <input value={remoteCaPath} onChange={(event) => setRemoteCaPath(event.target.value)} placeholder="/path/to/agent-ca.crt" aria-label="TLS CA path" />
              <input value={remoteServerName} onChange={(event) => setRemoteServerName(event.target.value)} placeholder="TLS server name (optional)" aria-label="TLS server name" />
              <select value={remoteProviderId} onChange={(event) => setRemoteProviderId(event.target.value)} aria-label="Remote provider"><option value="codex">Codex</option><option value="claude-code">Claude Code</option><option value="kiro">Kiro</option><option value="antigravity">Antigravity</option></select>
              <input value={remotePairingCode} onChange={(event) => setRemotePairingCode(event.target.value)} placeholder="Pairing code" aria-label="Pairing code" />
              <input type="password" value={remoteBootstrapToken} onChange={(event) => setRemoteBootstrapToken(event.target.value)} placeholder="Bootstrap token" aria-label="Bootstrap token" />
              <input value={remoteHostId} onChange={(event) => setRemoteHostId(event.target.value)} placeholder="Enrolled host id for resync" aria-label="Enrolled host id" />
              <input type="password" value={remoteToken} onChange={(event) => setRemoteToken(event.target.value)} placeholder="Credential (optional; Keychain fallback)" aria-label="Remote credential" />
            </div>
            <div className="remote-actions"><button className="primary" onClick={() => void enrollAndSyncRemote()} disabled={remoteBusy}>{remoteBusy ? "Connecting…" : "Enroll & sync"}</button><button className="secondary" onClick={() => void syncRemote()} disabled={remoteBusy || !remoteHostId}>{remoteBusy ? "Syncing…" : "Sync enrolled host"}</button><small>Enrollment stores the rotated host credential in the macOS Keychain. Later sync can use the stored credential by leaving the credential field empty.</small></div>
          </section>

          <section className="host-aliases" aria-label="Host aliases">
            <div className="section-heading"><div><span className="eyebrow">Controller metadata</span><h2>Host aliases</h2></div><span className="scope-pill">Native host identity unchanged</span></div>
            <p>Give enrolled hosts a private label for this Controller. Aliases never change the Agent’s `host_id`, hostname, or remote access policy.</p>
            <div className="host-alias-list">
              {hosts.map((host) => <div key={host.identity.host_id}><span className={host.status === "Connected" ? "dot green" : "dot orange"} /><strong>{host.identity.display_name}</strong><small>{host.identity.host_id} · {host.identity.platform}</small><input value={hostAliasDrafts[host.identity.host_id] ?? ""} maxLength={80} onChange={(event) => setHostAliasDrafts((drafts) => ({ ...drafts, [host.identity.host_id]: event.target.value }))} placeholder="Private alias" aria-label={`Alias for ${host.identity.display_name}`} /><button type="button" className="secondary" onClick={() => void saveHostAlias(host.identity.host_id)} disabled={savingHostAlias === host.identity.host_id}>{savingHostAlias === host.identity.host_id ? "Saving…" : hostAliasDrafts[host.identity.host_id]?.trim() ? "Save alias" : "Clear alias"}</button></div>)}
              {!hosts.length && <small>No hosts have been registered yet.</small>}
            </div>
          </section>

          <form className="search-box" onSubmit={search}><span className="search-icon">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search configuration, memory, sessions…"/><kbd>⌘ K</kbd><button type="submit">Search</button></form>
          <div className="search-filters" aria-label="Search filters">
            <select value={selectedArtifactKind} onChange={(event) => setSelectedArtifactKind(event.target.value)} aria-label="Artifact type"><option value="">All artifact types</option><option value="Configuration">Configuration</option><option value="Instruction">Instruction</option><option value="Memory">Memory</option><option value="Session">Session</option><option value="Tooling">Tooling</option><option value="ProjectContext">Project context</option><option value="RuntimeEvent">Runtime event</option></select>
            <select value={selectedProjectTrust} onChange={(event) => setSelectedProjectTrust(event.target.value)} aria-label="Project trust"><option value="">All trust states</option><option value="trusted">Trusted</option><option value="untrusted">Untrusted</option><option value="unknown">Unknown</option><option value="inaccessible">Inaccessible</option></select>
            <select value={selectedLifecycle} onChange={(event) => setSelectedLifecycle(event.target.value)} aria-label="Lifecycle"><option value="">All lifecycle states</option><option value="Discovered">Discovered</option><option value="Candidate">Candidate</option><option value="Approved">Approved</option><option value="Active">Active</option><option value="Stale">Stale</option><option value="Superseded">Superseded</option><option value="Deleted">Deleted</option></select>
            <select value={sensitivityMax} onChange={(event) => setSensitivityMax(event.target.value)} aria-label="Maximum sensitivity"><option value="">Any sensitivity</option><option value="Public">Public</option><option value="Internal">Internal or lower</option><option value="Sensitive">Sensitive or lower</option><option value="SecretLike">Secret-like or lower</option></select>
            <label>Observed after<input type="datetime-local" value={observedAfter} onChange={(event) => setObservedAfter(event.target.value)} /></label>
            <label>Observed before<input type="datetime-local" value={observedBefore} onChange={(event) => setObservedBefore(event.target.value)} /></label>
            <button type="button" className="secondary" onClick={() => { setSelectedArtifactKind(""); setSelectedProjectTrust(""); setSelectedLifecycle(""); setSensitivityMax(""); setObservedAfter(""); setObservedBefore(""); }}>Clear filters</button>
          </div>
          <section className="saved-searches" aria-label="Saved searches">
            <div><span className="eyebrow">Private Controller shortcuts</span><strong>Saved searches</strong><small>Only explicit shortcuts retain their query; telemetry never stores search text.</small></div>
            <input value={savedSearchName} maxLength={120} onChange={(event) => setSavedSearchName(event.target.value)} placeholder="Name this search (optional)" aria-label="Saved search name" />
            <button type="button" className="secondary" onClick={() => void saveCurrentSearch()} disabled={savingSearch || !query.trim()}>{savingSearch ? "Saving…" : "Save current search"}</button>
            <div className="saved-search-list">
              {savedSearches.map((saved) => <span key={saved.saved_search_id}><button type="button" onClick={() => void applySavedSearch(saved)} title={`Run ${saved.name}`}>{saved.name}</button><button type="button" onClick={() => void deleteSearch(saved.saved_search_id)} aria-label={`Delete saved search ${saved.name}`}>×</button></span>)}
              {!savedSearches.length && <small>No saved searches yet.</small>}
            </div>
          </section>
          {error && <div className="error-banner">{error}</div>}

          <section className="codex-section">
            <div className="section-heading"><div><span className="eyebrow">Embedded agent</span><h2>Ask Codex about this control plane</h2></div><span className="scope-pill"><span className={codexRuntimeState === "degraded" ? "dot orange" : "dot green"} /> {codexRuntimeState === "degraded" ? "Degraded · catalog read-only" : codexRuntimeState === "available" ? "App-server connected" : "App-server on demand"}</span></div>
            <form className="codex-box" onSubmit={askCodex}><textarea value={codexPrompt} onChange={(event) => setCodexPrompt(event.target.value)} /><button className="primary" type="submit" disabled={askingCodex}>{askingCodex ? "Thinking…" : "Ask Codex"}</button>{askingCodex && <button className="secondary" type="button" onClick={() => void cancelCodex()}>Stop turn</button>}</form>
            {hits.length > 0 && <div className="recommendation-evidence"><div><strong>Evidence-grounded recommendation</strong><small>Select 2–4 already-redacted search results. Their excerpts are sent to the local, no-network Codex app-server; the bounded, redacted turn is retained as an AMCP session record.</small></div><div className="recommendation-evidence-options">{hits.slice(0, 8).map((hit) => <label key={hit.artifact_id}><input type="checkbox" checked={recommendationEvidenceIds.includes(hit.artifact_id)} onChange={() => toggleRecommendationEvidence(hit.artifact_id)} disabled={!recommendationEvidenceIds.includes(hit.artifact_id) && recommendationEvidenceIds.length >= 4} /><span><strong>{hit.title}</strong><small>{hit.kind} · {hit.host_id} · {hit.source_reference}</small></span></label>)}</div><div className="recommendation-evidence-actions"><small>{selectedRecommendationEvidence.length}/4 selected · at least two required</small><button className="secondary" type="button" onClick={() => void askEvidenceGroundedRecommendation()} disabled={askingCodex || selectedRecommendationEvidence.length < 2}>{askingCodex ? "Thinking…" : "Ask for grounded recommendation"}</button></div></div>}
            {codexRuntimeState === "degraded" && <p className="muted">Codex app-server is unavailable. You can continue using catalog search, source inspection, and the read-only session evidence fallback; submit again to retry the runtime.</p>}
            {(codexReply || codexEvents.length > 0) && <div className="codex-reply"><div className="evidence-heading"><span>{askingCodex ? "Codex is streaming" : "Codex response"}</span><span className="verified">✓ app-server</span></div><pre>{askingCodex ? streamedCodexText || "Working…" : codexReply}</pre>{lastRecommendationEvidence.length >= 2 && <div className="recommendation-citations"><strong>Grounded in selected AMCP evidence</strong>{lastRecommendationEvidence.map((hit) => <span key={hit.artifact_id}>[AMCP:{hit.artifact_id}] · {hit.title} · {hit.source_reference}</span>)}</div>}<div className="codex-event-list">{codexEvents.filter((event) => !event.text).slice(-8).map((event, index) => <small key={`${event.method}-${event.item_id ?? index}`}>{event.method}{event.status ? ` · ${event.status}` : ""}</small>)}</div></div>}
          </section>

          <div className="section-heading"><div><span className="eyebrow">Unified index</span><h2>Search evidence</h2></div><span className="scope-pill"><span className="dot green" /> {selectedHostId ? hostLabel(selectedHostId) : "All connected hosts"}{selectedProviderId ? ` · ${selectedProviderId}` : ""}{selectedProjectId ? " · selected project" : ""}</span></div>
          <div className="explorer">
            <div className="results-panel">
              <div className="panel-toolbar"><span>{hits.length ? `${hits.length} results` : "Run a search to inspect indexed evidence"}</span><span>{selectedArtifactKind || "all types"} · {selectedLifecycle || "all states"}</span></div>
              {hits.map((hit) => <button className={selected?.artifact_id === hit.artifact_id ? "result selected" : "result"} key={hit.artifact_id} onClick={() => void inspectArtifact(hit)}><div className="result-top"><span className="type-chip">{hit.kind} · {hit.provider_id}</span><time>{new Date(hit.observed_at).toLocaleDateString()}</time></div><strong>{hit.title}</strong><p>{hit.preview}</p><small>{hit.lifecycle} · {hit.source_reference}</small></button>)}
              {!hits.length && <div className="empty-state"><div className="empty-glyph">⌁</div><strong>Search the AMCP catalog</strong><p>Results are redacted, source-linked, and scoped to the connected hosts.</p><button className="primary" onClick={() => void search()}>Search “{query}”</button></div>}
            </div>
            <aside className="inspector">
              {selected ? <><div className="inspector-header"><span className="type-chip">{selected.kind} · {selected.provider_id}</span><span className="verified">{readingArtifact ? "Reading live…" : artifactDetail ? "✓ live redacted read" : selectedHostIsConnected ? "indexed preview" : "offline catalog preview"}</span></div><h3>{selected.title}</h3><p className="path">{selected.source_reference}</p><div className="meta-grid"><div><small>Host</small><strong>{hostLabel(selected.host_id)}</strong></div><div><small>Project</small><strong>{selected.project_id ?? "host scope"}</strong></div><div><small>Trust</small><strong>{selected.project_trust_level ?? "not project-scoped"}</strong></div><div><small>Lifecycle</small><strong>{selected.lifecycle}</strong></div><div><small>Sensitivity</small><strong>{selected.sensitivity}</strong></div><div><small>Artifact</small><strong>{selected.artifact_id.slice(0, 16)}</strong></div><div><small>Observed</small><strong>{new Date(selected.observed_at).toLocaleString()}</strong></div></div><div className="evidence"><div className="evidence-heading"><span>{artifactDetail ? "Live artifact content" : "Evidence preview"}</span><span className="verified">✓ redacted</span></div><pre>{artifactDetail?.content ?? selected.preview}</pre></div>{selectedArtifactCanBeTagged && <><div className="artifact-tags"><div className="evidence-heading"><span>Controller tags</span><span>Catalog metadata only</span></div><div><input value={newArtifactTag} maxLength={48} onChange={(event) => setNewArtifactTag(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void addArtifactTag(); } }} placeholder="Add private tag" aria-label="New artifact tag" /><button type="button" onClick={() => void addArtifactTag()} disabled={taggingArtifact || !newArtifactTag.trim()}>{taggingArtifact ? "Adding…" : "Add"}</button></div><div className="artifact-tag-list">{artifactTags.map((tag) => <span key={tag.tag_id}>{tag.name}<button type="button" onClick={() => void removeArtifactTag(tag.tag_id)} aria-label={`Remove tag ${tag.name}`}>×</button></span>)}{!artifactTags.length && <small>No Controller tags on this artifact.</small>}</div></div><div className="cross-host-links"><div className="evidence-heading"><span>Cross-host relationships</span><span>Catalog metadata only</span></div><div className="cross-host-link-form"><select value={crossHostRelationshipKind} onChange={(event) => setCrossHostRelationshipKind(event.target.value)} aria-label="Cross-host relationship kind"><option value="related">Related</option><option value="duplicate">Duplicate</option><option value="same-policy">Same policy</option><option value="follow-up">Follow-up</option></select><select value={crossHostTargetId} onChange={(event) => setCrossHostTargetId(event.target.value)} aria-label="Cross-host relationship target"><option value="">Choose a result from another host</option>{crossHostLinkCandidates.map((hit) => <option key={hit.artifact_id} value={hit.artifact_id}>{hostLabel(hit.host_id)} · {hit.title}</option>)}</select><button type="button" onClick={() => void linkCrossHostArtifact()} disabled={linkingCrossHost || !crossHostTargetId}>{linkingCrossHost ? "Linking…" : "Link"}</button></div><div className="cross-host-link-list">{crossHostRelationships.map((relationship) => { const otherIsLeft = relationship.right_artifact_id === selected.artifact_id; const otherTitle = otherIsLeft ? relationship.left_title : relationship.right_title; const otherHost = otherIsLeft ? relationship.left_host_id : relationship.right_host_id; return <span key={relationship.relationship_id}><strong>{relationship.relationship_kind.replace("-", " ")}</strong> · {hostLabel(otherHost)} · {otherTitle}<button type="button" onClick={() => void unlinkCrossHostArtifact(relationship.relationship_id)} aria-label={`Remove ${relationship.relationship_kind} relationship`}>×</button></span>; })}{!crossHostRelationships.length && <small>Link an indexed result from another host to compare or track follow-up work.</small>}</div></div></>}<button className="secondary" onClick={() => void inspectArtifact(selected)} disabled={readingArtifact || !selectedHostIsConnected}>{readingArtifact ? "Reading…" : selectedHostIsConnected ? "Read from Agent" : "Host Agent unavailable"}</button>{artifactDetail && selectedArtifactCanBeChanged && <div className="proposal-editor"><div className="evidence-heading"><span>Propose replacement</span><span className="verified">Approval required</span></div><textarea value={replacementText} onChange={(event) => setReplacementText(event.target.value)} /><input value={changeReason} onChange={(event) => setChangeReason(event.target.value)} aria-label="Change reason" /><button className="primary" onClick={() => void proposeArtifactChange()} disabled={proposingArtifact || !replacementText.trim()}>{proposingArtifact ? "Creating proposal…" : "Create change proposal"}</button></div>}</> : <div className="inspector-empty"><span>◌</span><p>Select an evidence record to inspect provenance, scope, and safe content.</p></div>}
            </aside>
          </div>

          <section className="runtime-section">
            <div className="section-heading"><div><span className="eyebrow">Runtime telemetry</span><h2>Recent agent activity</h2></div><button className="secondary refresh-button" onClick={() => void refreshRuntimeEvents()}>Refresh events</button></div>
            <div className="runtime-list">{runtimeEvents.slice(0, 8).map((event) => <article className="runtime-row" key={event.event_id}><span className="runtime-marker">●</span><div><strong>{event.event_type}</strong><small>{event.host_id} · {event.provider_id} · seq {event.sequence}</small></div><time>{new Date(event.occurred_at).toLocaleString()}</time><code>{event.payload_json}</code></article>)}{!runtimeEvents.length && <div className="change-empty">No runtime events in the selected scope.</div>}</div>
          </section>

          <section className="diagnostics-section">
            <div className="section-heading"><div><span className="eyebrow">Bounded health metadata</span><h2>Diagnostics</h2></div><div className="diagnostics-actions"><span className="scope-pill">No artifact or transcript content</span><button className="secondary" type="button" onClick={() => void backupCatalog()} disabled={backingUpCatalog}>{backingUpCatalog ? "Creating backup…" : "Backup catalog"}</button></div></div>
            <div className="diagnostics-grid">
              <article><small>Search projection</small><strong>{diagnostics?.latest_index_run?.status ?? "not indexed"}</strong><span>{diagnostics ? `${diagnostics.catalog_diagnostics.search_indexed_artifact_count}/${diagnostics.catalog_diagnostics.total_artifact_count} records · ${(diagnostics.catalog_diagnostics.search_index_coverage_ratio * 100).toFixed(0)}% coverage` : "Collect a provider to create an index run."}</span></article>
              <article><small>Recent runtime events</small><strong>{diagnostics?.recent_event_count ?? 0}</strong><span>Up to 40 metadata-only events are counted.</span></article>
              <article><small>Latest collection</small><strong>{diagnostics?.recent_collection_runs?.[0] ? `${diagnostics.recent_collection_runs[0].duration_ms} ms` : "not collected"}</strong><span>{diagnostics?.recent_collection_runs?.[0] ? `${diagnostics.recent_collection_runs[0].provider_id} · ${diagnostics.recent_collection_runs[0].discovered_count} found · ${diagnostics.recent_collection_runs[0].inserted_count} new · ${diagnostics.recent_collection_runs[0].status}${diagnostics.recent_collection_runs[0].failure_kind ? ` · ${diagnostics.recent_collection_runs[0].failure_kind}` : ""}` : "Latency and record counters appear after the first sync."}</span></article>
              <article><small>Latest search</small><strong>{diagnostics?.recent_search_runs?.[0] ? `${diagnostics.recent_search_runs[0].duration_ms} ms` : "not searched"}</strong><span>{diagnostics?.recent_search_runs?.[0] ? `${diagnostics.recent_search_runs[0].result_count} results · limit ${diagnostics.recent_search_runs[0].limit}` : "Query text and previews are never persisted as metrics."}</span></article>
              <article><small>Pending approvals</small><strong>{diagnostics?.pending_change_count ?? 0}</strong><span>Every write remains behind the human policy gate.</span></article>
              <article><small>Applied changes</small><strong>{diagnostics?.catalog_diagnostics.applied_change_count ?? 0}</strong><span>Completed Controller-authorized changes.</span></article>
              <article><small>Stale sources</small><strong>{diagnostics ? `${diagnostics.catalog_diagnostics.stale_artifact_count} · ${(diagnostics.catalog_diagnostics.stale_source_ratio * 100).toFixed(1)}%` : "0"}</strong><span>Changed sources need collection before they are current again.</span></article>
              <article><small>Catalog size</small><strong>{diagnostics ? `${(diagnostics.catalog_diagnostics.database_size_bytes / 1024 / 1024).toFixed(1)} MB` : "loading"}</strong><span>Database plus active WAL/SHM sidecars; no native provider files.</span></article>
              <article><small>Trust attention</small><strong>{diagnostics?.catalog_diagnostics.projects_requiring_attention.length ?? 0}</strong><span>Untrusted or unknown projects remain read-only.</span></article>
              <article><small>Edit conflicts</small><strong>{diagnostics?.catalog_diagnostics.conflicted_change_count ?? 0}</strong><span>{diagnostics?.catalog_diagnostics.rolled_back_change_count ?? 0} rollbacks · conflicts require a fresh proposal and review.</span></article>
              <article><small>Provider diagnostics</small><strong>{diagnostics?.catalog_diagnostics.recent_provider_diagnostic_event_count ?? 0}</strong><span>Metadata-only provider warnings retained in the event stream.</span></article>
              <article><small>Diagnostics snapshot</small><strong>{diagnostics?.content_included === false ? "content-free" : "loading"}</strong><span>{diagnostics ? `Generated ${new Date(diagnostics.generated_at).toLocaleString()}` : "Refreshing catalog metadata…"}</span></article>
            </div>
            {lastCatalogBackup && <small className="catalog-backup-receipt">Catalog backup created {new Date(lastCatalogBackup.created_at).toLocaleString()} · {(lastCatalogBackup.size_bytes / 1024 / 1024).toFixed(1)} MB · {lastCatalogBackup.backup_path}</small>}
          </section>

          <section className="rag-section">
            <div className="section-heading"><div><span className="eyebrow">Optional derived index</span><h2>RAG projection</h2></div><span className="scope-pill">Native provider state untouched</span></div>
            <div className="rag-card"><div><strong>{ragStats?.chunk_count ?? 0} chunks</strong><small>{ragStats?.source_count ?? 0} source records · {ragStats?.retrieval_run_count ?? 0} retrieval runs</small><small>{ragStats?.average_retrieval_latency_ms === undefined ? "No retrieval metrics yet" : `${ragStats.average_retrieval_latency_ms} ms avg · ${(ragStats.retrieval_citation_coverage_basis_points / 100).toFixed(0)}% cited`}</small></div><p>RAG stores only redacted, rebuildable derived data. Retrieval metrics exclude the user query and context text. Clearing it does not remove Codex files, the AMCP catalog, or lexical search.</p><button className="secondary" onClick={() => void clearRagIndex()} disabled={!ragStats?.chunk_count && !ragStats?.retrieval_run_count}>Delete derived index</button></div>
            <div className="rag-policy-grid">
              <label className="rag-toggle"><input type="checkbox" checked={ragConfig.enabled} onChange={(event) => setRagConfig({ ...ragConfig, enabled: event.target.checked })} /> Enable cited RAG for selected scope</label>
              <label>Embedding provider<select value={ragConfig.embedding_provider ?? ""} onChange={(event) => setRagConfig({ ...ragConfig, embedding_provider: event.target.value || undefined })}><option value="">Lexical only</option><option value="local-hash">Local hash (offline)</option><option value="openai">OpenAI-compatible (explicit process consent required)</option></select></label>
              <label>Embedding model<input value={ragConfig.embedding_model ?? ""} maxLength={160} placeholder="Provider default" onChange={(event) => setRagConfig({ ...ragConfig, embedding_model: event.target.value || undefined })} /></label>
              <label>Retention days<input type="number" min="0" max="3650" value={ragConfig.retention_days ?? ""} placeholder="No expiry" onChange={(event) => setRagConfig({ ...ragConfig, retention_days: event.target.value === "" ? undefined : Number(event.target.value) })} /></label>
              <label>Chunk size (bytes)<input type="number" min="64" max="16384" value={ragConfig.chunk_size} onChange={(event) => setRagConfig({ ...ragConfig, chunk_size: Number(event.target.value) })} /></label>
              <label>Retrieval budget<input type="number" min="1" max="20" value={ragConfig.retrieval_limit} onChange={(event) => setRagConfig({ ...ragConfig, retrieval_limit: Number(event.target.value) })} /></label>
              <div className="rag-scope-control"><strong>Allowed scopes</strong><small>{ragConfig.allowed_scopes.length ? "Only these host/provider/project combinations can enter the derived index." : "Add at least one scope before enabling the persisted RAG policy."}</small><button type="button" className="secondary" onClick={addSelectedRagScope}>Add active scope</button><div className="rag-scope-list">{ragConfig.allowed_scopes.map((scope) => <button type="button" key={JSON.stringify(scope)} onClick={() => removeRagScope(scope)}>{scope.host_id ?? "all hosts"} · {scope.provider_id ?? "all providers"} · {scope.project_id ?? "all projects"} ×</button>)}</div></div>
              <p className="rag-policy-note">Ingestion is permanently excerpt-only and secret-redacted. External session transcript bodies are excluded. Remote embeddings require `AMCP_RAG_EGRESS_CONSENT=true` and a process-local API key; neither is stored here.</p>
              <button className="primary" type="button" onClick={() => void saveRagConfig()} disabled={savingRagConfig}>{savingRagConfig ? "Saving policy…" : "Save RAG policy"}</button>
            </div>
          </section>

          <section className="audit-section">
            <div className="section-heading"><div><span className="eyebrow">Controller accountability</span><h2>Audit trail</h2></div><span className="scope-pill">Metadata only · {selectedHostId || "all hosts"}</span></div>
            <div className="audit-list">
              {auditEvents.map((event) => <article className="audit-row" key={event.audit_event_id}>
                <div><strong>{event.operation}</strong><small>{event.actor} · {event.host_id ?? "controller"} · {event.provider_id ?? "—"}</small></div>
                <code title={event.target}>{event.target}</code>
                <span>{event.result}</span>
                <time>{new Date(event.timestamp).toLocaleString()}</time>
              </article>)}
              {!auditEvents.length && <div className="change-empty">No audit events in the selected host/provider scope.</div>}
            </div>
          </section>

          <section className="changes-section">
            <div className="section-heading"><div><span className="eyebrow">Policy gate</span><h2>Change queue</h2></div><span className="scope-pill">Human approval required</span></div>
            <div className="change-list">
              {changes.length ? changes.map((change) => <article className="change-row" key={change.change_set_id}>
                <div className="change-main"><span className={change.status === "Proposed" ? "status-badge pending" : "status-badge"}>{change.status}</span><strong>{change.reason}</strong><small>{change.change_set_id} · {change.operations.length} operation{change.operations.length === 1 ? "" : "s"}</small></div>
                <div className="change-target">{change.operations[0]?.target.source_reference ?? "No target"}</div>
                <div className="change-actions">{change.status === "Proposed" && <button className="primary approve-button" onClick={() => void approve(change.change_set_id)} disabled={approving === change.change_set_id || (change.scope?.host_id !== undefined && !hostIsConnected(change.scope.host_id))}>{approving === change.change_set_id ? "Applying…" : "Approve & apply"}</button>}
                {change.status === "Applied" && <button className="secondary approve-button" onClick={() => void rollback(change)} disabled={rollingBack === change.change_set_id || (change.scope?.host_id !== undefined && !hostIsConnected(change.scope.host_id))}>{rollingBack === change.change_set_id ? "Rolling back…" : "Rollback"}</button>}</div>
                <details className="change-review">
                  <summary>Review diff, hashes and evidence</summary>
                  <div className="change-review-meta"><span>Provider: {change.provider_id}</span><span>Evidence: {change.evidence_ids.length}</span><span>Actor: {change.actor}</span></div>
                  {change.operations.map((operation, index) => <div className="change-operation" key={`${change.change_set_id}-${index}`}>
                    <div><strong>{operation.operation}</strong><code>{operation.target.source_reference}</code></div>
                    <div className="hash-grid"><span>Expected <code>{operation.expected_source_hash ?? "not recorded"}</code></span><span>Before <code>{operation.before_hash ?? "not recorded"}</code></span><span>After <code>{operation.after_hash ?? "not recorded"}</code></span></div>
                    <pre>{operation.diff || "Provider-native operation; no text diff is available."}</pre>
                  </div>)}
                </details>
              </article>) : <div className="change-empty">No proposed changes. Controller proposals will appear here with their diff and provenance.</div>}
            </div>
          </section>

          <section className="inventory-section">
            <div className="section-heading"><div><span className="eyebrow">Normalized catalog</span><h2>Projects, memories, sessions</h2></div><span className="scope-pill">Source-linked records</span></div>
            <div className="session-filters" aria-label="Session filters">
              <select value={sessionBranch} onChange={(event) => setSessionBranch(event.target.value)} aria-label="Session branch"><option value="">All branches</option>{knownSessionBranches.map((branch) => <option key={branch} value={branch}>{branch}</option>)}</select>
              <select value={sessionModel} onChange={(event) => setSessionModel(event.target.value)} aria-label="Session model"><option value="">All models</option>{knownSessionModels.map((model) => <option key={model} value={model}>{model}</option>)}</select>
              <select value={sessionArchiveState} onChange={(event) => setSessionArchiveState(event.target.value)} aria-label="Session archive state"><option value="">Active and archived</option><option value="active">Active only</option><option value="archived">Archived only</option></select>
              <label>Started after<input type="datetime-local" value={sessionStartedAfter} onChange={(event) => setSessionStartedAfter(event.target.value)} /></label>
              <label>Started before<input type="datetime-local" value={sessionStartedBefore} onChange={(event) => setSessionStartedBefore(event.target.value)} /></label>
              <button type="button" className="secondary" onClick={() => { setSessionBranch(""); setSessionModel(""); setSessionArchiveState(""); setSessionStartedAfter(""); setSessionStartedBefore(""); }}>Clear session filters</button>
            </div>
            <div className="inventory-grid">
              <div className="inventory-card"><div className="inventory-card-head"><strong>Providers</strong><span>{providers.length}</span></div>{providers.slice(0, 4).map((provider) => <div className="inventory-item" key={`${provider.host_id}-${provider.provider_id}`}><span className="inventory-symbol">◉</span><div><strong>{provider.display_name}</strong><small>{(provider.provider_version ?? provider.version) ? `${provider.provider_version ?? provider.version} · ` : ""}{provider.host_id} · {provider.health || "unknown"} · {provider.compatibility || "unknown"}</small><small>{provider.support_level || "inventory-only"} · schema {provider.schema_fingerprint || "unavailable"}</small><small>{provider.native_roots?.length ? `${provider.native_roots.length} native roots · ${provider.native_roots[0]}` : "no native roots reported"}</small></div></div>)}{!providers.length && <div className="change-empty">No provider capabilities reported yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Configuration</strong><span>{configLayers.length}</span></div>{configLayers.slice(0, 4).map((layer) => <button type="button" className="inventory-item" key={layer.config_layer_id} onClick={() => inspectCatalogSource(layer, "Configuration", layer.profile ?? layer.scope)} disabled={!hostIsConnected(layer.host_id)}><span className="inventory-symbol">⚙</span><div><strong>{layer.profile ?? layer.scope}</strong><small>precedence {layer.precedence_rank} · {layer.source_reference}</small></div></button>)}{!configLayers.length && <div className="change-empty">No normalized config layers yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Guidance chain</strong><span>{guidance.length}</span></div>{guidance.slice(0, 4).map((item) => <button type="button" className="inventory-item" key={item.guidance_id} onClick={() => inspectCatalogSource(item, "Instruction", item.kind)} disabled={!hostIsConnected(item.host_id)}><span className="inventory-symbol">☷</span><div><strong>{item.kind}</strong><small>precedence {item.precedence_rank} · {item.source_reference}</small></div></button>)}{!guidance.length && <div className="change-empty">No guidance, rules, or user skills discovered yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Projects</strong><span>{projects.length}</span></div>{projects.slice(0, 4).map((project) => <div className="inventory-item" key={project.project_id}><span className="inventory-symbol">◈</span><div><strong>{project.display_name}</strong><small>{project.trust_level ?? "trust unknown"} · {project.root_path}</small></div></div>)}{!projects.length && <div className="change-empty">No normalized projects yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Memories</strong><span>{memories.length}</span></div>{memories.slice(0, 4).map((memory) => <div className="inventory-item" key={memory.memory_record_id}><span className="inventory-symbol">✦</span><div><strong>{memory.title}</strong><small>{memory.lifecycle} · {memory.source_reference}</small></div><button className="session-action" onClick={() => void forgetMemory(memory)} disabled={forgettingMemory === memory.memory_record_id}>{forgettingMemory === memory.memory_record_id ? "…" : "Forget"}</button></div>)}{!memories.length && <div className="change-empty">No normalized memories yet.</div>}</div>
              <div className="inventory-card"><div className="inventory-card-head"><strong>Sessions</strong><span>{sessions.length}</span></div>{sessions.slice(0, 4).map((session) => <div className="session-entry" key={session.session_id}><button className={selectedSessionId === session.session_id ? "inventory-item session-item selected" : "inventory-item session-item"} onClick={() => void inspectSession(session)}><span className="inventory-symbol">◌</span><div><strong>{session.title ?? session.session_id}</strong><small>{session.model ?? "model unknown"} · {session.archived ? "archived" : "active"}</small></div></button><button className="session-action" onClick={() => void proposeRuntimeChange(session)} disabled={proposingRuntime === session.session_id || !hostIsConnected(session.host_id)}>{proposingRuntime === session.session_id ? "…" : session.archived ? "Unarchive" : "Archive"}</button></div>)}{!sessions.length && <div className="change-empty">No normalized sessions yet.</div>}</div>
            </div>
            {selectedSessionId && <div className="session-inspector"><div className="section-heading"><div><span className="eyebrow">Session evidence</span><h2>{selectedSessionId}</h2></div><span className="scope-pill">{sessionItems.length} bounded items</span>{selectedSession && !selectedSession.source_reference.startsWith("codex://") && <button className="secondary" onClick={() => inspectCatalogSource(selectedSession, "Session", selectedSession.title ?? selectedSession.session_id)} disabled={!hostIsConnected(selectedSession.host_id)}>Read redacted source excerpt</button>}</div><div className="session-item-list">{sessionItems.map((item) => <article className="session-event" key={`${item.session_id}-${item.sequence}`}><div><span className="type-chip">{item.role ?? "event"}</span><strong>{item.item_kind}</strong><time>{new Date(item.observed_at).toLocaleString()}</time></div>{item.content ? <pre>{item.content}</pre> : <small>Metadata-only event; transcript payload is not stored.</small>}</article>)}{!sessionItems.length && <div className="change-empty">No session items available.</div>}</div></div>}
          </section>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
