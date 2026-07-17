#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use amcp_app_server::AppServerClient;
use amcp_codex::{hash_bytes, redact_text};
use amcp_core::CatalogService;
use amcp_domain::{
    ArtifactRecord, ChangeSet, CollectionBatch, ConfigLayerRecord, GuidanceRecord, HostIdentity,
    HostRecord, MemoryRecord, ProjectRecord, ProviderDescriptor, ProviderRecord, RuntimeEvent,
    SessionItem, SessionRecord, new_id,
};
use amcp_storage::SearchHit;
use chrono::Utc;
use std::{env, path::PathBuf, process::Command};

fn database_path() -> PathBuf {
    env::var_os("AMCP_DB_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home).join("Library/Application Support/AMCP/controller.sqlite")
            })
        })
        .unwrap_or_else(|| PathBuf::from(".amcp/controller.sqlite"))
}

#[tauri::command]
fn list_hosts() -> Result<Vec<HostRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_hosts()
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
fn list_projects() -> Result<Vec<ProjectRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_projects(None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_sessions() -> Result<Vec<SessionRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_sessions(None, None)
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
fn list_memory() -> Result<Vec<MemoryRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_memory_records(None, None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_config_layers() -> Result<Vec<ConfigLayerRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_config_layers(None, None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_guidance() -> Result<Vec<GuidanceRecord>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .list_guidance(None, None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn search_catalog(
    query: String,
    host_id: Option<String>,
    provider_id: Option<String>,
) -> Result<Vec<SearchHit>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .search_scoped(&query, 50, host_id.as_deref(), provider_id.as_deref(), None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn read_artifact(
    host_id: String,
    provider_id: String,
    source_reference: String,
) -> Result<ArtifactRecord, String> {
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let output = Command::new(controller)
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
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let replacement_file = env::temp_dir().join(format!("amcp-ui-replacement-{}.txt", new_id("file")));
    std::fs::write(&replacement_file, replacement)
        .map_err(|error| format!("write ephemeral proposal input: {error}"))?;
    let output = Command::new(controller)
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
fn collect_local(provider_id: Option<String>) -> Result<serde_json::Value, String> {
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let mut command = Command::new(controller);
    command.args(["run-once", "--json"]);
    if let Some(provider_id) = provider_id {
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
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let mut enroll = Command::new(&controller);
    enroll
        .args(["enroll", "--agent-url", &agent_url, "--tls-ca", &tls_ca])
        .args(["--pairing-code", &pairing_code, "--bootstrap-token", &bootstrap_token])
        .args(["--no-start-agent", "--json"]);
    if let Some(server_name) = &tls_server_name {
        enroll.args(["--tls-server-name", server_name]);
    }
    let enrollment_output = enroll
        .output()
        .map_err(|error| format!("start remote enrollment: {error}"))?;
    if !enrollment_output.status.success() {
        return Err(String::from_utf8_lossy(&enrollment_output.stderr).trim().to_owned());
    }
    let enrollment: serde_json::Value = serde_json::from_slice(&enrollment_output.stdout)
        .map_err(|error| format!("decode enrollment result: {error}"))?;
    let host_id = enrollment
        .get("host_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "enrollment did not return host_id".to_owned())?;

    let mut collect = Command::new(&controller);
    collect
        .args(["run-once", "--agent-url", &agent_url, "--tls-ca", &tls_ca])
        .args(["--provider-id", &provider_id, "--token", "amcp-development-token"])
        .args(["--no-start-agent", "--json"])
        .env("AMCP_AGENT_KEYCHAIN_ACCOUNT", format!("agent:{host_id}"));
    if let Some(server_name) = &tls_server_name {
        collect.args(["--tls-server-name", server_name]);
    }
    let collection_output = collect
        .output()
        .map_err(|error| format!("start remote collection: {error}"))?;
    if !collection_output.status.success() {
        return Err(String::from_utf8_lossy(&collection_output.stderr).trim().to_owned());
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
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let supplied_token = token.filter(|value| !value.trim().is_empty());
    let auth_token = supplied_token
        .as_deref()
        .unwrap_or("amcp-development-token");
    let mut collect = Command::new(controller);
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
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let approver = approved_by.unwrap_or_else(|| "desktop-human".into());
    let output = Command::new(controller)
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
fn propose_runtime_change(thread_id: String, archived: bool) -> Result<serde_json::Value, String> {
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let mut command = Command::new(controller);
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
async fn ask_codex(prompt: String) -> Result<serde_json::Value, String> {
    let executable = env::var_os("AMCP_CODEX_BIN").unwrap_or_else(|| "codex".into());
    let mcp_command =
        PathBuf::from(env::var_os("AMCP_MCP_BIN").unwrap_or_else(|| "amcp-mcp".into()));
    let codex_home = env::var_os("CODEX_HOME").map(PathBuf::from);
    let working_directory = env::var_os("AMCP_CODEX_CWD").map(PathBuf::from);
    let mut client = AppServerClient::spawn_with_mcp(
        PathBuf::from(executable),
        codex_home.as_deref(),
        working_directory.as_deref(),
        &mcp_command,
        &database_path(),
    )
    .await
    .map_err(|error| error.to_string())?;
    let result: anyhow::Result<serde_json::Value> = async {
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
        let response = client.run_turn(&thread_id, &prompt).await?;
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
    result.map_err(|error| error.to_string())
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
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_hosts,
            list_providers,
            list_changes,
            list_projects,
            list_sessions,
            list_session_items,
            list_memory,
            list_config_layers,
            list_guidance,
            search_catalog,
            read_artifact,
            propose_artifact_change,
            list_runtime_events,
            collect_local,
            enroll_remote,
            sync_remote,
            approve_change,
            propose_runtime_change,
            ask_codex
        ])
        .run(tauri::generate_context!())
        .expect("error while running AMCP desktop");
}
