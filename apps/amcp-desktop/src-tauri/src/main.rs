#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use amcp_app_server::AppServerClient;
use amcp_codex::{hash_bytes, redact_text};
use amcp_core::CatalogService;
use amcp_domain::{
    new_id, ArtifactKind, ArtifactRecord, AuditEvent, ChangeSet, ChangeStatus, CollectionBatch,
    ConfigLayerRecord, GuidanceRecord, HostIdentity, HostRecord, LifecycleState, MemoryRecord,
    ProjectRecord, ProviderCompatibility, ProviderDescriptor, ProviderHealth, ProviderRecord,
    ProviderSupportLevel, RuntimeEvent, SensitivityClass, SessionItem,
    SessionRecord,
};
use amcp_platform::default_controller_db_path;
use amcp_rag::{PersistentRagIndex, RagClearReceipt, RagConfig, RagIndexStats};
use amcp_storage::{
    CatalogBackupReceipt, CatalogDiagnostics, CollectionRunRecord, ControllerTag,
    CrossHostRelationship, HostAlias, IndexRunRecord, MemoryForgetReceipt, SavedSearch,
    SearchFilters, SearchHit, SearchRunRecord, SessionFilters,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use tauri::Emitter;
use tokio::sync::watch;

#[derive(Clone, Default)]
struct CodexTurnRegistry {
    cancellations: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
}

#[derive(Clone, Serialize)]
struct EmbeddedCodexStreamEvent {
    request_id: String,
    method: String,
    turn_id: Option<String>,
    item_id: Option<String>,
    status: Option<String>,
    text: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchCatalogFilters {
    host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
    project_trust_levels: Option<Vec<String>>,
    artifact_kinds: Option<Vec<ArtifactKind>>,
    lifecycle_states: Option<Vec<LifecycleState>>,
    sensitivity_max: Option<SensitivityClass>,
    observed_after: Option<String>,
    observed_before: Option<String>,
}

impl SearchCatalogFilters {
    fn into_search_filters(self) -> Result<SearchFilters, String> {
        Ok(SearchFilters {
            host_id: self.host_id,
            provider_id: self.provider_id,
            project_id: self.project_id,
            project_trust_levels: self.project_trust_levels.unwrap_or_default(),
            artifact_kinds: self.artifact_kinds.unwrap_or_default(),
            lifecycle_states: self.lifecycle_states.unwrap_or_default(),
            sensitivity_max: self.sensitivity_max,
            observed_after: parse_optional_utc(self.observed_after, "observed_after")?,
            observed_before: parse_optional_utc(self.observed_before, "observed_before")?,
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionCatalogFilters {
    host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
    branch: Option<String>,
    model: Option<String>,
    archived: Option<bool>,
    started_after: Option<String>,
    started_before: Option<String>,
}

fn parse_optional_utc(
    value: Option<String>,
    name: &str,
) -> Result<Option<chrono::DateTime<Utc>>, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| format!("{name} must be an ISO 8601 timestamp"))
        })
        .transpose()
}

fn embedded_codex_stream_event(
    request_id: &str,
    message: &serde_json::Value,
) -> EmbeddedCodexStreamEvent {
    let method = message
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .chars()
        .take(120)
        .collect::<String>();
    let params = message.get("params").unwrap_or(&serde_json::Value::Null);
    let turn = params.get("turn").unwrap_or(&serde_json::Value::Null);
    let scalar = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_str)
            .map(|value| value.chars().take(160).collect::<String>())
    };
    EmbeddedCodexStreamEvent {
        request_id: request_id.to_owned(),
        turn_id: scalar(params.get("turnId")).or_else(|| scalar(turn.get("id"))),
        item_id: scalar(params.get("itemId")),
        status: scalar(params.get("status")).or_else(|| scalar(turn.get("status"))),
        text: (method == "item/agentMessage/delta")
            .then(|| params.get("delta").and_then(serde_json::Value::as_str))
            .flatten()
            .map(bounded_redacted),
        method,
    }
}

fn cancel_registered_codex_turn(
    registry: &CodexTurnRegistry,
    request_id: &str,
) -> Result<(), String> {
    let sender = registry
        .cancellations
        .lock()
        .map_err(|_| "Codex turn registry lock is poisoned".to_owned())?
        .get(request_id)
        .cloned()
        .ok_or_else(|| "no active Codex turn matches this request".to_owned())?;
    sender
        .send(true)
        .map_err(|_| "Codex turn already completed".to_owned())
}

fn executable_file_name(binary: &str) -> String {
    if cfg!(windows) {
        format!("{binary}.exe")
    } else {
        binary.to_owned()
    }
}

fn sidecar_path_from_executable(executable: &Path, binary: &str) -> Option<PathBuf> {
    let candidate = executable.parent()?.join(executable_file_name(binary));
    candidate.is_file().then_some(candidate)
}

fn bundled_sidecar_path(binary: &str) -> Option<PathBuf> {
    sidecar_path_from_executable(&env::current_exe().ok()?, binary)
}

fn command_binary(binary: &str, override_variable: &str) -> PathBuf {
    env::var_os(override_variable)
        .map(PathBuf::from)
        .or_else(|| bundled_sidecar_path(binary))
        .unwrap_or_else(|| PathBuf::from(executable_file_name(binary)))
}

fn controller_command() -> Command {
    Command::new(command_binary("amcp-controller", "AMCP_CONTROLLER_BIN"))
}

fn configure_bundled_sidecars() {
    for (binary, override_variable) in [
        ("amcp-agent", "AMCP_AGENT_BIN"),
        ("amcp-controller", "AMCP_CONTROLLER_BIN"),
        ("amcp-mcp", "AMCP_MCP_BIN"),
    ] {
        if env::var_os(override_variable).is_none() {
            if let Some(path) = bundled_sidecar_path(binary) {
                env::set_var(override_variable, path);
            }
        }
    }
}

fn database_path() -> PathBuf {
    env::var_os("AMCP_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(default_controller_db_path)
}

#[tauri::command]
fn list_hosts() -> Result<Vec<HostRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_hosts()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_host_aliases() -> Result<Vec<HostAlias>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_host_aliases()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn set_host_alias(host_id: String, alias: String) -> Result<HostAlias, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .set_host_alias(&host_id, &alias)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_host_alias(host_id: String) -> Result<bool, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .delete_host_alias(&host_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_artifact_tags(artifact_id: String) -> Result<Vec<ControllerTag>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_artifact_tags(&artifact_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn tag_artifact(artifact_id: String, name: String) -> Result<ControllerTag, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .tag_artifact(&artifact_id, &name)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn untag_artifact(artifact_id: String, tag_id: String) -> Result<bool, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .untag_artifact(&artifact_id, &tag_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_cross_host_relationships(
    artifact_id: String,
) -> Result<Vec<CrossHostRelationship>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_cross_host_relationships(&artifact_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn link_cross_host_artifacts(
    first_artifact_id: String,
    second_artifact_id: String,
    relationship_kind: String,
) -> Result<CrossHostRelationship, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .link_cross_host_artifacts(
            &first_artifact_id,
            &second_artifact_id,
            &relationship_kind,
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn unlink_cross_host_relationship(relationship_id: String) -> Result<bool, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .unlink_cross_host_relationship(&relationship_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn backup_catalog(reason: String) -> Result<CatalogBackupReceipt, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .create_backup(&reason)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_providers() -> Result<Vec<ProviderRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_providers(None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_changes() -> Result<Vec<ChangeSet>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_change_sets(None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_audit_events(
    host_id: Option<String>,
    provider_id: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<AuditEvent>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_audit_events(
            host_id.as_deref(),
            provider_id.as_deref(),
            limit.unwrap_or(20),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_projects(host_id: Option<String>) -> Result<Vec<ProjectRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_projects(host_id.as_deref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_sessions(filters: Option<SessionCatalogFilters>) -> Result<Vec<SessionRecord>, String> {
    let filters = filters.unwrap_or_default();
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_sessions_filtered(&SessionFilters {
            host_id: filters.host_id,
            provider_id: filters.provider_id,
            project_id: filters.project_id,
            branch: filters.branch,
            model: filters.model,
            archived: filters.archived,
            started_after: parse_optional_utc(filters.started_after, "started_after")?,
            started_before: parse_optional_utc(filters.started_before, "started_before")?,
        })
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_session_items(
    session_id: String,
    host_id: Option<String>,
) -> Result<Vec<SessionItem>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_session_items(&session_id, host_id.as_deref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_memory(
    host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
) -> Result<Vec<MemoryRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_memory_records_scoped(
            host_id.as_deref(),
            provider_id.as_deref(),
            project_id.as_deref(),
        )
        .map_err(|error| error.to_string())
}

fn forget_memory_for(
    database: &std::path::Path,
    memory_record_id: &str,
    host_id: &str,
    provider_id: &str,
    reason: &str,
) -> anyhow::Result<MemoryForgetReceipt> {
    CatalogService::open(database)?.forget_memory_record(
        memory_record_id,
        host_id,
        provider_id,
        reason,
    )
}

/// This command removes only AMCP's central projection. The desktop confirmation
/// is deliberate: native provider state is never deleted by this workflow.
#[tauri::command]
fn forget_memory(
    memory_record_id: String,
    host_id: String,
    provider_id: String,
    reason: String,
) -> Result<MemoryForgetReceipt, String> {
    forget_memory_for(
        &database_path(),
        &memory_record_id,
        &host_id,
        &provider_id,
        &reason,
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_config_layers(
    host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
) -> Result<Vec<ConfigLayerRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_config_layers_scoped(
            host_id.as_deref(),
            provider_id.as_deref(),
            project_id.as_deref(),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_guidance(
    host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
) -> Result<Vec<GuidanceRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_guidance_scoped(
            host_id.as_deref(),
            provider_id.as_deref(),
            project_id.as_deref(),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn search_catalog(query: String, filters: SearchCatalogFilters) -> Result<Vec<SearchHit>, String> {
    let mut catalog = CatalogService::open(database_path()).map_err(|error| error.to_string())?;
    let hits = catalog
        .search_filtered(&query, 50, &filters.into_search_filters()?)
        .map_err(|error| error.to_string())?;
    catalog
        .audit_sensitive_search_results("desktop.search", &hits)
        .map_err(|error| error.to_string())?;
    Ok(hits)
}

#[tauri::command]
fn list_saved_searches() -> Result<Vec<SavedSearch>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_saved_searches()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn save_saved_search(
    name: String,
    query: String,
    filters: SearchCatalogFilters,
) -> Result<SavedSearch, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .save_search(&name, &query, &filters.into_search_filters()?)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_saved_search(saved_search_id: String) -> Result<bool, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .delete_saved_search(&saved_search_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn read_artifact(
    host_id: String,
    provider_id: String,
    source_reference: String,
) -> Result<ArtifactRecord, String> {
    let database = database_path();
    let output = controller_command()
        .args([
            "read-artifact",
            "--host-id",
            &host_id,
            "--provider-id",
            &provider_id,
            "--source",
            &source_reference,
            "--json",
        ])
        .arg("--db")
        .arg(&database)
        .output()
        .map_err(|error| format!("start Controller artifact read: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode artifact read result: {error}"))
}

#[tauri::command]
fn propose_artifact_change(
    host_id: String,
    provider_id: String,
    source_reference: String,
    replacement: String,
    reason: String,
) -> Result<serde_json::Value, String> {
    let replacement_file =
        env::temp_dir().join(format!("amcp-ui-replacement-{}.txt", new_id("file")));
    std::fs::write(&replacement_file, replacement)
        .map_err(|error| format!("write ephemeral proposal input: {error}"))?;
    let output = controller_command()
        .args([
            "propose-change",
            "--provider-id",
            &provider_id,
            "--source",
            &source_reference,
            "--replacement-file",
            replacement_file.to_string_lossy().as_ref(),
            "--reason",
            &reason,
            "--host-id",
            &host_id,
            "--json",
        ])
        .output()
        .map_err(|error| format!("start Controller proposal: {error}"));
    let _ = std::fs::remove_file(&replacement_file);
    let output = output?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode proposal result: {error}"))
}

#[tauri::command]
fn list_runtime_events(
    host_id: Option<String>,
    provider_id: Option<String>,
) -> Result<Vec<RuntimeEvent>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_runtime_events(host_id.as_deref(), provider_id.as_deref(), 40)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn rag_status() -> Result<RagIndexStats, String> {
    PersistentRagIndex::open(database_path())
        .map_err(|error| error.to_string())?
        .stats()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn rag_config() -> Result<RagConfig, String> {
    PersistentRagIndex::open(database_path())
        .map_err(|error| error.to_string())?
        .load_config()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn save_rag_config(config: RagConfig) -> Result<RagConfig, String> {
    let index = PersistentRagIndex::open(database_path()).map_err(|error| error.to_string())?;
    index
        .save_config(&config)
        .map_err(|error| error.to_string())?;
    Ok(config)
}

#[tauri::command]
fn clear_rag_index() -> Result<RagClearReceipt, String> {
    let mut index = PersistentRagIndex::open(database_path()).map_err(|error| error.to_string())?;
    index
        .clear_derived_data()
        .map_err(|error| error.to_string())
}

#[derive(Serialize)]
struct DesktopDiagnostics {
    generated_at: String,
    latest_index_run: Option<IndexRunRecord>,
    pending_change_count: usize,
    recent_event_count: usize,
    recent_collection_runs: Vec<CollectionRunRecord>,
    recent_search_runs: Vec<SearchRunRecord>,
    catalog_diagnostics: CatalogDiagnostics,
    rag: RagIndexStats,
    content_included: bool,
}

fn diagnostics_snapshot_for(database: &std::path::Path) -> anyhow::Result<DesktopDiagnostics> {
    let catalog = CatalogService::open(database)?;
    Ok(DesktopDiagnostics {
        generated_at: Utc::now().to_rfc3339(),
        latest_index_run: catalog.latest_index_run()?,
        pending_change_count: catalog
            .list_change_sets(Some(ChangeStatus::Proposed))?
            .len(),
        recent_event_count: catalog.list_runtime_events(None, None, 40)?.len(),
        recent_collection_runs: catalog.list_collection_runs(None, None, 20)?,
        recent_search_runs: catalog.list_search_runs(None, None, 20)?,
        catalog_diagnostics: catalog.diagnostics()?,
        rag: PersistentRagIndex::open(database)?.stats()?,
        content_included: false,
    })
}

#[tauri::command]
fn diagnostics_snapshot() -> Result<DesktopDiagnostics, String> {
    diagnostics_snapshot_for(&database_path()).map_err(|error| error.to_string())
}

const MAX_ADDITIONAL_SCAN_ROOTS: usize = 32;

fn validated_additional_scan_roots(scan_roots: Option<Vec<String>>) -> Result<Vec<PathBuf>, String> {
    let mut roots = BTreeSet::new();
    for candidate in scan_roots.unwrap_or_default() {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        if !Path::new(candidate).is_absolute() {
            return Err("Additional scan roots must be absolute paths.".to_owned());
        }
        let root = PathBuf::from(candidate)
            .canonicalize()
            .map_err(|_| "An additional scan root does not exist or is inaccessible.".to_owned())?;
        if !root.is_dir() {
            return Err("Additional scan roots must be directories.".to_owned());
        }
        roots.insert(root);
        if roots.len() > MAX_ADDITIONAL_SCAN_ROOTS {
            return Err(format!(
                "At most {MAX_ADDITIONAL_SCAN_ROOTS} additional scan roots can be collected at once."
            ));
        }
    }
    Ok(roots.into_iter().collect())
}

#[tauri::command]
fn collect_local(
    provider_id: Option<String>,
    scan_roots: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let scan_roots = validated_additional_scan_roots(scan_roots)?;
    let mut command = controller_command();
    command.args(["run-once", "--json"]);
    if !scan_roots.is_empty() {
        let scan_roots = env::join_paths(scan_roots)
            .map_err(|_| "Additional scan roots contain an unsupported path-list separator.".to_owned())?;
        command.env("AMCP_SCAN_ROOTS", scan_roots);
    }
    if let Some(provider_id) = provider_id.filter(|provider_id| !provider_id.trim().is_empty()) {
        command.args(["--provider-id", &provider_id]);
    }
    let output = command
        .output()
        .map_err(|error| format!("start Controller collection: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode collection result: {error}"))
}

#[tauri::command]
fn enroll_remote(
    agent_url: String,
    tls_ca: String,
    tls_server_name: Option<String>,
    pairing_code: String,
    bootstrap_token: String,
    provider_id: String,
) -> Result<serde_json::Value, String> {
    if !agent_url.starts_with("tcp://") {
        return Err("Remote Agent URL must use tcp://".into());
    }
    if tls_ca.trim().is_empty() || pairing_code.trim().is_empty() {
        return Err("TLS CA path and pairing code are required".into());
    }
    let mut enroll = controller_command();
    enroll
        .args(["enroll", "--agent-url", &agent_url, "--tls-ca", &tls_ca])
        .args([
            "--pairing-code",
            &pairing_code,
            "--bootstrap-token",
            &bootstrap_token,
        ])
        .args(["--no-start-agent", "--json"]);
    if let Some(server_name) = &tls_server_name {
        enroll.args(["--tls-server-name", server_name]);
    }
    let enrollment_output = enroll
        .output()
        .map_err(|error| format!("start remote enrollment: {error}"))?;
    if !enrollment_output.status.success() {
        return Err(String::from_utf8_lossy(&enrollment_output.stderr)
            .trim()
            .to_owned());
    }
    let enrollment: serde_json::Value = serde_json::from_slice(&enrollment_output.stdout)
        .map_err(|error| format!("decode enrollment result: {error}"))?;
    let host_id = enrollment
        .get("host_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "enrollment did not return host_id".to_owned())?;

    let mut collect = controller_command();
    collect
        .args(["run-once", "--agent-url", &agent_url, "--tls-ca", &tls_ca])
        .args([
            "--provider-id",
            &provider_id,
            "--token",
            "amcp-development-token",
        ])
        .args(["--no-start-agent", "--json"])
        .env("AMCP_AGENT_KEYCHAIN_ACCOUNT", format!("agent:{host_id}"));
    if let Some(server_name) = &tls_server_name {
        collect.args(["--tls-server-name", server_name]);
    }
    let collection_output = collect
        .output()
        .map_err(|error| format!("start remote collection: {error}"))?;
    if !collection_output.status.success() {
        return Err(String::from_utf8_lossy(&collection_output.stderr)
            .trim()
            .to_owned());
    }
    let collection: serde_json::Value = serde_json::from_slice(&collection_output.stdout)
        .map_err(|error| format!("decode remote collection result: {error}"))?;
    Ok(serde_json::json!({ "enrollment": enrollment, "collection": collection }))
}

#[tauri::command]
fn sync_remote(
    agent_url: String,
    tls_ca: String,
    tls_server_name: Option<String>,
    host_id: String,
    token: Option<String>,
    provider_id: String,
) -> Result<serde_json::Value, String> {
    if !agent_url.starts_with("tcp://") {
        return Err("Remote Agent URL must use tcp://".into());
    }
    if tls_ca.trim().is_empty() || host_id.trim().is_empty() {
        return Err("TLS CA path and host id are required".into());
    }
    let supplied_token = token.filter(|value| !value.trim().is_empty());
    let auth_token = supplied_token
        .as_deref()
        .unwrap_or("amcp-development-token");
    let mut collect = controller_command();
    collect
        .args(["run-once", "--agent-url", &agent_url, "--tls-ca", &tls_ca])
        .args(["--provider-id", &provider_id, "--token", auth_token])
        .args(["--no-start-agent", "--json"]);
    if supplied_token.is_none() {
        collect.env("AMCP_AGENT_KEYCHAIN_ACCOUNT", format!("agent:{host_id}"));
    }
    if let Some(server_name) = &tls_server_name {
        collect.args(["--tls-server-name", server_name]);
    }
    let output = collect
        .output()
        .map_err(|error| format!("start remote collection: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode remote collection result: {error}"))
}

#[tauri::command]
fn approve_change(
    change_set_id: String,
    approved_by: Option<String>,
) -> Result<serde_json::Value, String> {
    let approver = approved_by.unwrap_or_else(|| "desktop-human".into());
    let output = controller_command()
        .args(["approve-change", "--change-set-id"])
        .arg(&change_set_id)
        .args(["--approved-by"])
        .arg(&approver)
        .arg("--json")
        .output()
        .map_err(|error| format!("start Controller approval: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode approval result: {error}"))
}

#[tauri::command]
fn rollback_change(
    change_set_id: String,
    approved_by: Option<String>,
) -> Result<serde_json::Value, String> {
    let approver = approved_by.unwrap_or_else(|| "desktop-human".into());
    let output = controller_command()
        .args(["rollback-change", "--change-set-id"])
        .arg(&change_set_id)
        .args(["--approved-by"])
        .arg(&approver)
        .arg("--json")
        .output()
        .map_err(|error| format!("start Controller rollback: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode rollback result: {error}"))
}

#[tauri::command]
fn propose_runtime_change(thread_id: String, archived: bool) -> Result<serde_json::Value, String> {
    let mut command = controller_command();
    command
        .args(["runtime-propose", "--provider-id", "codex", "--reason"])
        .arg(if archived {
            "Archive runtime session from AMCP desktop"
        } else {
            "Unarchive runtime session from AMCP desktop"
        })
        .arg(if archived { "--archive" } else { "--unarchive" })
        .arg(&thread_id)
        .arg("--json");
    let output = command
        .output()
        .map_err(|error| format!("start Controller runtime proposal: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode runtime proposal result: {error}"))
}

#[tauri::command]
async fn ask_codex(
    prompt: String,
    request_id: String,
    registry: tauri::State<'_, CodexTurnRegistry>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    if request_id.trim().is_empty() {
        return Err("Codex request id is required".to_owned());
    }
    let (cancel_sender, mut cancellation) = watch::channel(false);
    let cancellations = registry.cancellations.clone();
    {
        let mut active = cancellations
            .lock()
            .map_err(|_| "Codex turn registry lock is poisoned".to_owned())?;
        if active.insert(request_id.clone(), cancel_sender).is_some() {
            return Err("a Codex request with this id is already active".to_owned());
        }
    }
    let result: anyhow::Result<serde_json::Value> = async {
        let executable = env::var_os("AMCP_CODEX_BIN").unwrap_or_else(|| "codex".into());
        let mcp_command = command_binary("amcp-mcp", "AMCP_MCP_BIN");
        let codex_home = env::var_os("CODEX_HOME").map(PathBuf::from);
        let working_directory = env::var_os("AMCP_CODEX_CWD").map(PathBuf::from);
        let mut client = AppServerClient::spawn_with_mcp(
            PathBuf::from(executable),
            codex_home.as_deref(),
            working_directory.as_deref(),
            &mcp_command,
            &database_path(),
        )
        .await?;
        let run_result: anyhow::Result<serde_json::Value> = async {
            client
                .initialize("amcp-desktop", env!("CARGO_PKG_VERSION"))
                .await?;
            let thread = client
                .start_thread(None, working_directory.as_deref())
                .await?;
            let thread_id = thread
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("Codex app-server did not return a thread id"))?
                .to_owned();
            let event_app = app.clone();
            let event_request_id = request_id.clone();
            let response = client
                .run_turn_cancellable_with_events(
                    &thread_id,
                    &prompt,
                    &mut cancellation,
                    move |message| {
                        let _ = event_app.emit(
                            "amcp://codex-turn-event",
                            embedded_codex_stream_event(&event_request_id, message),
                        );
                    },
                )
                .await?;
            persist_embedded_session(
                &database_path(),
                &thread_id,
                &prompt,
                &response,
                working_directory.as_deref(),
            )?;
            Ok(response)
        }
        .await;
        let _ = client.shutdown().await;
        run_result
    }
    .await;
    let _ = cancellations
        .lock()
        .map(|mut active| active.remove(&request_id));
    result.map_err(|error| embedded_codex_error_message(&error))
}

fn embedded_codex_error_message(error: &anyhow::Error) -> String {
    let detail = error.to_string();
    if detail.contains("interrupted") {
        "Embedded Codex turn was cancelled.".to_owned()
    } else {
        format!(
            "Embedded Codex is unavailable; the AMCP catalog remains available for read-only search and inspection. {detail}"
        )
    }
}

#[tauri::command]
fn cancel_codex_turn(
    request_id: String,
    registry: tauri::State<'_, CodexTurnRegistry>,
) -> Result<(), String> {
    cancel_registered_codex_turn(&registry, &request_id)
}

fn persist_embedded_session(
    database: &std::path::Path,
    thread_id: &str,
    prompt: &str,
    response: &serde_json::Value,
    working_directory: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let host = HostIdentity {
        host_id: "controller-local".to_owned(),
        display_name: "AMCP Controller".to_owned(),
        platform: std::env::consts::OS.to_owned(),
        hostname: hostname(),
    };
    let provider = ProviderDescriptor {
        id: "codex".to_owned(),
        display_name: "OpenAI Codex".to_owned(),
        version: None,
        adapter_version: "app-server".to_owned(),
        schema_fingerprint: "codex-app-server-v1".to_owned(),
        support_level: ProviderSupportLevel::ReadOnly,
        health: ProviderHealth::Healthy,
        compatibility: ProviderCompatibility::Compatible,
        native_roots: Vec::new(),
        capabilities: vec!["app-server".to_owned(), "sessions".to_owned()],
    };
    let now = Utc::now();
    let reply_text = response
        .get("text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mut catalog = CatalogService::open(database)?;
    let existing_items = catalog.list_session_items(thread_id, Some(&host.host_id))?;
    let next_sequence = existing_items
        .iter()
        .map(|item| item.sequence)
        .max()
        .map_or(0, |sequence| sequence + 1);
    let prompt = bounded_redacted(prompt);
    let reply = bounded_redacted(reply_text);
    let events = response
        .get("events")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(512)
        .collect::<Vec<_>>();
    let session = SessionRecord {
        session_id: thread_id.to_owned(),
        host_id: host.host_id.clone(),
        provider_id: provider.id.clone(),
        project_id: None,
        title: Some("Embedded Codex".to_owned()),
        cwd: working_directory.map(|path| path.to_string_lossy().into_owned()),
        model: None,
        branch: None,
        started_at: Some(now),
        ended_at: Some(now),
        archived: false,
        source_reference: format!("codex-app-server://thread/{thread_id}"),
        source_hash: hash_bytes(response.to_string().as_bytes()),
        metadata_json: serde_json::json!({
            "surface": "amcp-desktop",
            "thread_id": thread_id,
            "app_server_event_count": events.len()
        })
        .to_string(),
        observed_at: now,
    };
    let mut items = vec![
        SessionItem {
            session_id: thread_id.to_owned(),
            host_id: host.host_id.clone(),
            provider_id: provider.id.clone(),
            sequence: next_sequence,
            role: Some("user".to_owned()),
            item_kind: "message".to_owned(),
            content: Some(prompt),
            source_reference: session.source_reference.clone(),
            observed_at: now,
        },
        SessionItem {
            session_id: thread_id.to_owned(),
            host_id: host.host_id.clone(),
            provider_id: provider.id.clone(),
            sequence: next_sequence + 1,
            role: Some("assistant".to_owned()),
            item_kind: "message".to_owned(),
            content: Some(reply),
            source_reference: session.source_reference.clone(),
            observed_at: now,
        },
    ];
    for (offset, event) in events.iter().enumerate() {
        let method = event
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .chars()
            .take(96)
            .collect::<String>();
        items.push(SessionItem {
            session_id: thread_id.to_owned(),
            host_id: host.host_id.clone(),
            provider_id: provider.id.clone(),
            sequence: next_sequence + 2 + offset as i64,
            role: Some("system".to_owned()),
            item_kind: format!("app-server:{method}"),
            content: None,
            source_reference: session.source_reference.clone(),
            observed_at: now,
        });
    }
    let event_methods = events
        .iter()
        .filter_map(|event| event.get("method").and_then(serde_json::Value::as_str))
        .take(64)
        .collect::<Vec<_>>();
    let event = RuntimeEvent {
        event_id: amcp_domain::new_id("event"),
        host_id: host.host_id.clone(),
        provider_id: provider.id.clone(),
        event_type: "session.event".to_owned(),
        sequence: next_sequence,
        payload_json: serde_json::json!({
            "thread_id": thread_id,
            "items": items.len(),
            "app_server_events": event_methods
        })
        .to_string(),
        occurred_at: now,
    };
    let batch = CollectionBatch {
        collection_run_id: amcp_domain::new_id("run"),
        host,
        providers: vec![provider],
        projects: Vec::new(),
        sessions: vec![session],
        session_items: items,
        memory_records: Vec::new(),
        config_layers: Vec::new(),
        guidance_records: Vec::new(),
        guidance_edges: Vec::new(),
        runtime_events: vec![event],
        artifacts: Vec::<ArtifactRecord>::new(),
        next_cursor: None,
    };
    catalog.ingest(&batch)?;
    Ok(())
}

fn bounded_redacted(value: &str) -> String {
    redact_text(&value.chars().take(4_000).collect::<String>())
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned())
}

fn main() {
    configure_bundled_sidecars();
    tauri::Builder::default()
        .manage(CodexTurnRegistry::default())
        .invoke_handler(tauri::generate_handler![
            list_hosts,
            list_host_aliases,
            set_host_alias,
            delete_host_alias,
            list_artifact_tags,
            tag_artifact,
            untag_artifact,
            list_cross_host_relationships,
            link_cross_host_artifacts,
            unlink_cross_host_relationship,
            backup_catalog,
            list_providers,
            list_changes,
            list_audit_events,
            list_projects,
            list_sessions,
            list_session_items,
            list_memory,
            forget_memory,
            list_config_layers,
            list_guidance,
            search_catalog,
            list_saved_searches,
            save_saved_search,
            delete_saved_search,
            read_artifact,
            propose_artifact_change,
            list_runtime_events,
            rag_status,
            rag_config,
            save_rag_config,
            clear_rag_index,
            diagnostics_snapshot,
            collect_local,
            enroll_remote,
            sync_remote,
            approve_change,
            rollback_change,
            propose_runtime_change,
            ask_codex,
            cancel_codex_turn
        ])
        .run(tauri::generate_context!())
        .expect("error while running AMCP desktop");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn embedded_codex_turn_is_persisted_as_redacted_session_items() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("controller.sqlite");
        persist_embedded_session(
            &database,
            "thread-test",
            "api_key=secret-prompt",
            &serde_json::json!({
                "text": "token=secret-reply",
                "events": [{ "method": "turn/completed", "status": "completed" }]
            }),
            Some(Path::new("/tmp/project")),
        )
        .expect("persist embedded session");
        let catalog = CatalogService::open(&database).expect("catalog");
        let sessions = catalog
            .list_sessions(Some("controller-local"), None)
            .expect("sessions");
        assert_eq!(sessions.len(), 1);
        let items = catalog
            .list_session_items("thread-test", Some("controller-local"))
            .expect("items");
        assert_eq!(items.len(), 3);
        assert_eq!(items[2].item_kind, "app-server:turn/completed");
        assert!(items[2].content.is_none());
        assert!(items
            .iter()
            .filter_map(|item| item.content.as_deref())
            .all(|content| !content.contains("secret")));
        assert_eq!(
            catalog
                .list_runtime_events(None, None, 10)
                .expect("events")
                .len(),
            1
        );
    }

    #[test]
    fn embedded_codex_runtime_failure_explains_the_read_only_catalog_fallback() {
        let message =
            embedded_codex_error_message(&anyhow::anyhow!("start Codex app-server: not found"));
        assert!(message.contains("Embedded Codex is unavailable"));
        assert!(message.contains("read-only search and inspection"));
    }

    #[test]
    fn desktop_diagnostics_are_content_free_and_bounded() {
        let directory = tempfile::tempdir().expect("database directory");
        let diagnostics = diagnostics_snapshot_for(&directory.path().join("controller.sqlite"))
            .expect("diagnostics snapshot");
        assert!(diagnostics.latest_index_run.is_none());
        assert_eq!(diagnostics.pending_change_count, 0);
        assert_eq!(diagnostics.recent_event_count, 0);
        assert!(diagnostics.recent_collection_runs.is_empty());
        assert!(diagnostics.recent_search_runs.is_empty());
        assert_eq!(diagnostics.catalog_diagnostics.total_artifact_count, 0);
        assert_eq!(diagnostics.catalog_diagnostics.stale_source_ratio, 0.0);
        assert_eq!(diagnostics.catalog_diagnostics.applied_change_count, 0);
        assert_eq!(diagnostics.catalog_diagnostics.rolled_back_change_count, 0);
        assert_eq!(
            diagnostics.catalog_diagnostics.search_index_coverage_ratio,
            0.0
        );
        assert_eq!(diagnostics.rag.chunk_count, 0);
        assert!(diagnostics.rag.average_retrieval_latency_ms.is_none());
        assert_eq!(diagnostics.rag.retrieval_citation_coverage_basis_points, 10_000);
        assert!(!diagnostics.content_included);
    }

    #[test]
    fn bundled_sidecar_is_resolved_next_to_desktop_executable() {
        let directory = tempfile::tempdir().expect("sidecar directory");
        let executable = directory.path().join("amcp-desktop");
        let sidecar = directory
            .path()
            .join(executable_file_name("amcp-controller"));
        std::fs::write(&executable, "desktop").expect("desktop executable fixture");
        std::fs::write(&sidecar, "controller").expect("controller sidecar fixture");

        assert_eq!(
            sidecar_path_from_executable(&executable, "amcp-controller"),
            Some(sidecar)
        );
    }

    #[test]
    fn active_codex_turn_can_be_cancelled_once() {
        let registry = CodexTurnRegistry::default();
        let (sender, receiver) = watch::channel(false);
        registry
            .cancellations
            .lock()
            .expect("registry lock")
            .insert("request-1".to_owned(), sender);

        cancel_registered_codex_turn(&registry, "request-1").expect("cancel active turn");
        assert!(*receiver.borrow());
    }

    #[test]
    fn desktop_search_filters_accept_tauri_camel_case_arguments() {
        let filters: SearchCatalogFilters = serde_json::from_value(serde_json::json!({
            "hostId": "host-test",
            "providerId": "codex",
            "projectId": "/tmp/project",
            "projectTrustLevels": ["trusted"],
            "artifactKinds": ["Configuration"],
            "lifecycleStates": ["Active"],
            "sensitivityMax": "Internal",
            "observedAfter": "2026-07-18T10:00:00Z",
            "observedBefore": "2026-07-18T11:00:00Z"
        }))
        .expect("deserialize Tauri filters");
        assert_eq!(filters.host_id.as_deref(), Some("host-test"));
        assert_eq!(filters.project_trust_levels, Some(vec!["trusted".into()]));
        assert_eq!(
            filters.artifact_kinds,
            Some(vec![ArtifactKind::Configuration])
        );
        assert_eq!(filters.lifecycle_states, Some(vec![LifecycleState::Active]));
        assert_eq!(filters.sensitivity_max, Some(SensitivityClass::Internal));
        assert_eq!(
            filters.observed_before.as_deref(),
            Some("2026-07-18T11:00:00Z")
        );
    }

    #[test]
    fn desktop_session_filters_accept_tauri_camel_case_arguments() {
        let filters: SessionCatalogFilters = serde_json::from_value(serde_json::json!({
            "hostId": "host-test",
            "providerId": "codex",
            "projectId": "/tmp/project",
            "branch": "main",
            "model": "gpt-test",
            "archived": false,
            "startedAfter": "2026-07-18T10:00:00Z",
            "startedBefore": "2026-07-18T11:00:00Z"
        }))
        .expect("deserialize Tauri session filters");
        assert_eq!(filters.branch.as_deref(), Some("main"));
        assert_eq!(filters.model.as_deref(), Some("gpt-test"));
        assert_eq!(filters.archived, Some(false));
        assert_eq!(
            filters.started_after.as_deref(),
            Some("2026-07-18T10:00:00Z")
        );
    }

    #[test]
    fn additional_scan_roots_are_absolute_existing_directories_and_deduplicated() {
        let directory = tempfile::tempdir().expect("scan root fixture");
        let root = directory.path().to_string_lossy().into_owned();
        let roots = validated_additional_scan_roots(Some(vec![root.clone(), root]))
            .expect("valid scan roots");
        assert_eq!(roots, vec![directory.path().canonicalize().expect("canonical root")]);
        assert!(validated_additional_scan_roots(Some(vec!["relative/path".into()])).is_err());
        assert!(validated_additional_scan_roots(Some(vec!["/does/not/exist".into()])).is_err());
    }

    #[test]
    fn streamed_codex_delta_is_redacted_and_tool_events_are_metadata_only() {
        let delta = embedded_codex_stream_event(
            "request-1",
            &serde_json::json!({
                "method": "item/agentMessage/delta",
                "params": { "delta": "token=secret-response", "itemId": "item-1" }
            }),
        );
        assert_eq!(delta.request_id, "request-1");
        assert_eq!(delta.item_id.as_deref(), Some("item-1"));
        assert!(!delta
            .text
            .as_deref()
            .unwrap_or_default()
            .contains("secret-response"));

        let tool = embedded_codex_stream_event(
            "request-1",
            &serde_json::json!({
                "method": "item/commandExecution/outputDelta",
                "params": { "delta": "untrusted tool output" }
            }),
        );
        assert!(tool.text.is_none());
    }
}
