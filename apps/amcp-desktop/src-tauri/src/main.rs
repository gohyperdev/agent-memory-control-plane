#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use amcp_domain::{ChangeSet, ConfigLayerRecord, GuidanceRecord, HostRecord, MemoryRecord, ProjectRecord, SessionRecord};
use amcp_app_server::AppServerClient;
use amcp_core::CatalogService;
use amcp_storage::SearchHit;
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
    serde_json::from_slice(&output.stdout).map_err(|error| format!("decode collection result: {error}"))
}

#[tauri::command]
fn approve_change(change_set_id: String, approved_by: Option<String>) -> Result<serde_json::Value, String> {
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
    serde_json::from_slice(&output.stdout).map_err(|error| format!("decode approval result: {error}"))
}

#[tauri::command]
async fn ask_codex(prompt: String) -> Result<serde_json::Value, String> {
    let executable = env::var_os("AMCP_CODEX_BIN").unwrap_or_else(|| "codex".into());
    let mcp_command = PathBuf::from(env::var_os("AMCP_MCP_BIN").unwrap_or_else(|| "amcp-mcp".into()));
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
    let result = async {
        client
            .initialize("amcp-desktop", env!("CARGO_PKG_VERSION"))
            .await?;
        let thread = client.start_thread(None, working_directory.as_deref()).await?;
        let thread_id = thread
            .get("thread")
            .and_then(|thread| thread.get("id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Codex app-server did not return a thread id"))?
            .to_owned();
        client.run_turn(&thread_id, &prompt).await
    }
    .await;
    let _ = client.shutdown().await;
    result.map_err(|error| error.to_string())
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
