#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use amcp_domain::{ChangeSet, HostRecord};
use amcp_storage::{Catalog, SearchHit};
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
    Catalog::open(database_path())
        .map_err(|error| error.to_string())?
        .list_hosts()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_changes() -> Result<Vec<ChangeSet>, String> {
    Catalog::open(database_path())
        .map_err(|error| error.to_string())?
        .list_change_sets(None)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn search_catalog(query: String) -> Result<Vec<SearchHit>, String> {
    Catalog::open(database_path())
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_hosts,
            list_changes,
            search_catalog,
            collect_local,
            approve_change
        ])
        .run(tauri::generate_context!())
        .expect("error while running AMCP desktop");
}
