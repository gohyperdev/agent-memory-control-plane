use amcp_core::CatalogService;
use amcp_domain::Scope;
use amcp_rag::{DisabledRagManager, RagManager};
use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Debug, Parser)]
#[command(name = "amcp-mcp", about = "AMCP MCP gateway for embedded Codex")]
struct Args {
    #[arg(long, env = "AMCP_DB_PATH")]
    db: PathBuf,
    #[arg(long, env = "AMCP_CONTROLLER_BIN", default_value = "amcp-controller")]
    controller_bin: PathBuf,
    #[arg(
        long,
        env = "AMCP_AGENT_SOCKET",
        default_value = "/tmp/amcp-agent.sock"
    )]
    agent_socket: PathBuf,
    #[arg(long, env = "AMCP_AGENT_URL")]
    agent_url: Option<String>,
    #[arg(long, env = "AMCP_AGENT_TLS_CA")]
    tls_ca: Option<PathBuf>,
    #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
    tls_server_name: Option<String>,
    #[arg(
        long,
        env = "AMCP_AGENT_TOKEN",
        default_value = "amcp-development-token"
    )]
    agent_token: String,
    #[arg(long, env = "CODEX_HOME")]
    codex_home: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut stdout,
                    error_response(Value::Null, -32700, error.to_string()),
                )
                .await?;
                continue;
            }
        };
        if request.id.is_none() {
            continue;
        }
        let id = request.id.clone().unwrap_or(Value::Null);
        let response = match handle_request(&args, &request) {
            Ok(result) => success_response(id, result),
            Err(error) => error_response(id, -32000, error.to_string()),
        };
        write_response(&mut stdout, response).await?;
    }
    Ok(())
}

fn handle_request(args: &Args, request: &JsonRpcRequest) -> Result<Value> {
    match request.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "amcp", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "AMCP exposes scoped, redacted agent-state search. Native provider state remains authoritative. Read tools return citations. Any change must be reviewed and approved by a human in the AMCP Controller."
        })),
        "tools/list" => Ok(tool_list()),
        "tools/call" => {
            let params: ToolCallParams = serde_json::from_value(request.params.clone())
                .context("invalid tools/call params")?;
            let output = call_tool(args, &params.name, params.arguments)?;
            Ok(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&output)? }],
                "structuredContent": output,
                "isError": false
            }))
        }
        "ping" => Ok(json!({})),
        _ => anyhow::bail!("unsupported JSON-RPC method: {}", request.method),
    }
}

fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "amcp_search",
                "description": "Search redacted, indexed AMCP evidence across hosts and providers. Results include source citations and freshness.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                        "scope": {
                            "type": "object",
                            "properties": {
                                "host_id": { "type": "string" },
                                "provider_id": { "type": "string" },
                                "project_id": { "type": "string" }
                            }
                        }
                    },
                    "required": ["query"]
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_hosts_list",
                "description": "List connected AMCP hosts and provider capabilities.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_projects_list",
                "description": "List normalized projects discovered from provider state, including trust and provenance.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "host_id": { "type": "string" } }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_sessions_list",
                "description": "List normalized session metadata without exposing transcript bodies by default.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "project_id": { "type": "string" }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_memory_list",
                "description": "List normalized, redacted memory records with lifecycle and source provenance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "project_id": { "type": "string" }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_config_layers_list",
                "description": "List normalized Codex configuration layers with scope, profile and precedence. Content is read through cited artifacts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "project_id": { "type": "string" }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_guidance_chain_get",
                "description": "List applicable AGENTS.md and AGENTS.override.md guidance in effective precedence order for a host or project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "project_id": { "type": "string" }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_retrieve_context",
                "description": "Retrieve optional RAG context. It is disabled by default and returns an explicit fallback warning with no uncited context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "scope": {
                            "type": "object",
                            "properties": {
                                "host_id": { "type": "string" },
                                "provider_id": { "type": "string" },
                                "project_id": { "type": "string" }
                            }
                        },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 20 }
                    },
                    "required": ["query"]
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_change_review",
                "description": "Review an existing human-visible AMCP change set. This never applies a change.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "change_set_id": { "type": "string" } },
                    "required": ["change_set_id"]
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_change_propose",
                "description": "Create a verified AMCP change proposal from replacement text. The Agent checks the target and current hash; no file is written and a human must approve the proposal.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "source": { "type": "string", "description": "Absolute path to an allowed provider document." },
                        "replacement": { "type": "string" },
                        "reason": { "type": "string" }
                    },
                    "required": ["host_id", "source", "replacement", "reason"]
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": false }
            }
        ]
    })
}

fn call_tool(args: &Args, name: &str, arguments: Value) -> Result<Value> {
    let catalog = CatalogService::open(&args.db)?;
    match name {
        "amcp_search" => {
            let query = arguments
                .get("query")
                .and_then(Value::as_str)
                .context("amcp_search requires query")?;
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(1, 50) as usize;
            let scope = arguments.get("scope");
            let host_id = scope
                .and_then(|scope| scope.get("host_id"))
                .and_then(Value::as_str);
            let provider_id = scope
                .and_then(|scope| scope.get("provider_id"))
                .and_then(Value::as_str);
            let project_id = scope
                .and_then(|scope| scope.get("project_id"))
                .and_then(Value::as_str);
            let hits = catalog.search_scoped(query, limit, host_id, provider_id, project_id)?;
            Ok(json!({
                "query": query,
                "scope": { "host_id": host_id, "provider_id": provider_id, "project_id": project_id },
                "results": hits.into_iter().map(|hit| json!({
                    "artifact_id": hit.artifact_id,
                    "title": hit.title,
                    "preview": hit.preview,
                    "host_id": hit.host_id,
                    "provider_id": hit.provider_id,
                    "source_reference": hit.source_reference,
                    "sensitivity": hit.sensitivity,
                    "observed_at": hit.observed_at,
                    "citation": format!("{}#{}", hit.source_reference, hit.artifact_id)
                })).collect::<Vec<_>>()
            }))
        }
        "amcp_hosts_list" => Ok(json!({ "hosts": catalog.list_hosts()? })),
        "amcp_projects_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            Ok(json!({ "projects": catalog.list_projects(host_id)? }))
        }
        "amcp_sessions_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(json!({ "sessions": catalog.list_sessions(host_id, project_id)? }))
        }
        "amcp_memory_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(json!({ "memory": catalog.list_memory_records(host_id, project_id)? }))
        }
        "amcp_config_layers_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(json!({ "config_layers": catalog.list_config_layers(host_id, project_id)? }))
        }
        "amcp_guidance_chain_get" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(json!({ "guidance": catalog.list_guidance(host_id, project_id)? }))
        }
        "amcp_retrieve_context" => {
            let query = arguments
                .get("query")
                .and_then(Value::as_str)
                .context("amcp_retrieve_context requires query")?;
            let scope = parse_scope(arguments.get("scope"));
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(5)
                .clamp(1, 20) as usize;
            let manager = DisabledRagManager::default();
            Ok(serde_json::to_value(
                manager.retrieve(query, &scope, limit)?,
            )?)
        }
        "amcp_change_review" => {
            let change_set_id = arguments
                .get("change_set_id")
                .and_then(Value::as_str)
                .context("amcp_change_review requires change_set_id")?;
            Ok(json!({
                "change_set": catalog.load_change_set(change_set_id)?,
                "approval_required": true,
                "writes_performed": false
            }))
        }
        "amcp_change_propose" => propose_change(args, arguments),
        _ => anyhow::bail!("unknown AMCP tool: {name}"),
    }
}

fn propose_change(args: &Args, arguments: Value) -> Result<Value> {
    let host_id = arguments
        .get("host_id")
        .and_then(Value::as_str)
        .context("amcp_change_propose requires host_id")?;
    let source = arguments
        .get("source")
        .and_then(Value::as_str)
        .context("amcp_change_propose requires source")?;
    let replacement = arguments
        .get("replacement")
        .and_then(Value::as_str)
        .context("amcp_change_propose requires replacement")?;
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .context("amcp_change_propose requires reason")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let replacement_file = env::temp_dir().join(format!(
        "amcp-mcp-replacement-{}-{nonce}.txt",
        std::process::id()
    ));
    fs::write(&replacement_file, replacement).context("write ephemeral proposal input")?;

    let mut command = Command::new(&args.controller_bin);
    command
        .args(["propose-change", "--socket"])
        .arg(&args.agent_socket)
        .args(["--source", source, "--replacement-file"])
        .arg(&replacement_file)
        .args(["--reason", reason, "--host-id", host_id, "--db"])
        .arg(&args.db)
        .arg("--token")
        .arg(&args.agent_token)
        .arg("--json");
    if let Some(codex_home) = &args.codex_home {
        command.args(["--codex-home"]).arg(codex_home);
    }
    if let Some(agent_url) = &args.agent_url {
        command.args(["--agent-url", agent_url]);
    }
    if let Some(tls_ca) = &args.tls_ca {
        command.args(["--tls-ca"]).arg(tls_ca);
    }
    if let Some(server_name) = &args.tls_server_name {
        command.args(["--tls-server-name", server_name]);
    }
    let output = command.output().context("start Controller proposal")?;
    let _ = fs::remove_file(&replacement_file);
    if !output.status.success() {
        anyhow::bail!(
            "Controller proposal failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let change_set: Value =
        serde_json::from_slice(&output.stdout).context("decode Controller proposal")?;
    Ok(json!({
        "change_set": change_set,
        "approval_required": true,
        "writes_performed": false,
        "next_step": "Review and approve this change set in the AMCP Controller UI."
    }))
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: JsonRpcResponse,
) -> Result<()> {
    let encoded = serde_json::to_string(&response)?;
    writer.write_all(encoded.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn success_response(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn error_response(id: Value, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}

fn parse_scope(value: Option<&Value>) -> Scope {
    Scope {
        host_id: value
            .and_then(|value| value.get("host_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        provider_id: value
            .and_then(|value| value.get("provider_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        project_id: value
            .and_then(|value| value.get("project_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}
