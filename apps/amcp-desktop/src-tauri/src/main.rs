#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use amcp_app_server::AppServerClient;
use amcp_codex::{hash_bytes, redact_text};
use amcp_core::CatalogService;
use amcp_domain::{
    ArtifactRecord, ChangeSet, CollectionBatch, ConfigLayerRecord, GuidanceRecord, HostIdentity,
    HostRecord, MemoryRecord, ProjectRecord, ProviderDescriptor, RuntimeEvent, SessionItem,
    SessionRecord,
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
fn search_catalog(query: String) -> Result<Vec<SearchHit>, String> {
    CatalogService::open(database_path())
        .map_err(|error| error.to_string())?
        .search(&query, 50)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn collect_local() -> Result<serde_json::Value, String> {
    let controller = env::var_os("AMCP_CONTROLLER_BIN").unwrap_or_else(|| "amcp-controller".into());
    let output = Command::new(controller)
        .args(["run-once", "--json"])
        .output()
        .map_err(|error| format!("start Controller collection: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode collection result: {error}"))
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
        metadata_json: serde_json::json!({ "surface": "amcp-desktop", "thread_id": thread_id })
            .to_string(),
        observed_at: now,
    };
    let items = vec![
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
    let event = RuntimeEvent {
        event_id: amcp_domain::new_id("event"),
        host_id: host.host_id.clone(),
        provider_id: provider.id.clone(),
        event_type: "session.event".to_owned(),
        sequence: next_sequence,
        payload_json: serde_json::json!({ "thread_id": thread_id, "items": 2 }).to_string(),
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
            &serde_json::json!({ "text": "token=secret-reply" }),
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
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| {
            item.content
                .as_deref()
                .is_some_and(|content| !content.contains("secret"))
        }));
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
            list_changes,
            list_projects,
            list_sessions,
            list_memory,
            list_config_layers,
            list_guidance,
            search_catalog,
            collect_local,
            approve_change,
            ask_codex
        ])
        .run(tauri::generate_context!())
        .expect("error while running AMCP desktop");
}
