use amcp_core::CatalogService;
use amcp_domain::{LifecycleState, Scope};
use amcp_platform::default_agent_socket_path;
use amcp_rag::{
    DisabledRagManager, EmbeddingProvider, HashedEmbeddingProvider, LexicalRagManager,
    OpenAiEmbeddingProvider, PersistentRagIndex, RagConfig, RagDocument, RagManager,
};
use anyhow::{Context, Result};
use chrono::Utc;
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
        default_value_os_t = default_agent_socket_path()
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
                "name": "amcp_artifact_read",
                "description": "Read one bounded, redacted provider document from its owning Agent. The host and provider scope are mandatory; native credentials and unsupported documents are never returned.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string", "default": "codex" },
                        "source_reference": { "type": "string", "description": "Provider-owned source reference returned by AMCP search." }
                    },
                    "required": ["host_id", "source_reference"]
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_providers_list",
                "description": "List provider adapters and negotiated capabilities by host. Inventory-only providers are valid and expose no mutation capability.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "host_id": { "type": "string" } }
                },
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
                "name": "amcp_session_items_list",
                "description": "List metadata-only items for a normalized session. Transcript content is not returned by default.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" },
                        "host_id": { "type": "string" }
                    },
                    "required": ["session_id"]
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
                "name": "amcp_events_list",
                "description": "List persisted, deduplicated AMCP runtime events for diagnostics and collection freshness.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_runtime_threads_list",
                "description": "Read bounded live runtime thread metadata from the selected Agent. Transcript content and provider response internals are excluded.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string", "default": "codex" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 64 }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_runtime_thread_read",
                "description": "Read one bounded live Codex thread snapshot. Only normalized thread metadata and item kind/role counts are returned; transcript content is excluded.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "thread_id": { "type": "string" },
                        "provider_id": { "type": "string", "default": "codex" }
                    },
                    "required": ["thread_id"]
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_runtime_thread_change_propose",
                "description": "Propose a Codex runtime archive/unarchive operation for human review. This creates an AMCP change set but does not mutate the provider.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "thread_id": { "type": "string" },
                        "provider_id": { "type": "string", "default": "codex" },
                        "archived": { "type": "boolean" },
                        "reason": { "type": "string" }
                    },
                    "required": ["thread_id", "archived", "reason"]
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": false }
            },
            {
                "name": "amcp_retrieve_context",
                "description": "Retrieve optional cited context. It is disabled by default; AMCP uses bounded lexical chunks from redacted FTS evidence. local-hash is offline; OpenAI embeddings require AMCP_RAG_EMBEDDING_PROVIDER=openai, OPENAI_API_KEY and explicit AMCP_RAG_EGRESS_CONSENT=true.",
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
                "name": "amcp_rag_status",
                "description": "Report metadata for the optional derived RAG projection. This never returns indexed content and never changes native provider state.",
                "inputSchema": { "type": "object", "properties": {} },
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
                        "provider_id": { "type": "string", "default": "codex" },
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
        "amcp_artifact_read" => read_artifact(args, arguments),
        "amcp_hosts_list" => Ok(json!({ "hosts": catalog.list_hosts()? })),
        "amcp_providers_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            Ok(json!({ "providers": catalog.list_providers(host_id)? }))
        }
        "amcp_projects_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            Ok(json!({ "projects": catalog.list_projects(host_id)? }))
        }
        "amcp_sessions_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(json!({ "sessions": catalog.list_sessions(host_id, project_id)? }))
        }
        "amcp_session_items_list" => {
            let session_id = arguments
                .get("session_id")
                .and_then(Value::as_str)
                .context("amcp_session_items_list requires session_id")?;
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            Ok(json!({ "items": catalog.list_session_items(session_id, host_id)? }))
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
        "amcp_events_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .clamp(1, 100) as usize;
            Ok(json!({ "events": catalog.list_runtime_events(host_id, provider_id, limit)? }))
        }
        "amcp_runtime_threads_list" => runtime_threads_list(args, arguments),
        "amcp_runtime_thread_read" => runtime_thread_read(args, arguments),
        "amcp_runtime_thread_change_propose" => runtime_thread_change_propose(args, arguments),
        "amcp_rag_status" => {
            let index = PersistentRagIndex::open(&args.db)?;
            Ok(json!({
                "enabled": env::var("AMCP_RAG_ENABLED").ok().is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE")),
                "embedding_provider": env::var("AMCP_RAG_EMBEDDING_PROVIDER").ok(),
                "egress_consent": env::var("AMCP_RAG_EGRESS_CONSENT").ok().is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE")),
                "index": index.stats()?
            }))
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
            if env::var("AMCP_RAG_ENABLED")
                .ok()
                .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            {
                let hits = catalog.search_scoped(
                    query,
                    (limit * 3).min(50),
                    scope.host_id.as_deref(),
                    scope.provider_id.as_deref(),
                    scope.project_id.as_deref(),
                )?;
                let allowed_scopes = if scope.host_id.is_some()
                    || scope.provider_id.is_some()
                    || scope.project_id.is_some()
                {
                    vec![scope.clone()]
                } else {
                    Vec::new()
                };
                let rag_config = RagConfig {
                    enabled: true,
                    allowed_scopes,
                    embedding_provider: env::var("AMCP_RAG_EMBEDDING_PROVIDER").ok(),
                    embedding_model: env::var("AMCP_RAG_EMBEDDING_MODEL").ok(),
                    retention_days: env::var("AMCP_RAG_RETENTION_DAYS")
                        .ok()
                        .and_then(|value| value.parse::<u32>().ok()),
                    ..RagConfig::default()
                };
                let embedding_provider: Option<Box<dyn EmbeddingProvider>> = if rag_config
                    .embedding_provider
                    .as_deref()
                    .is_some_and(|provider| matches!(provider, "local-hash" | "hash"))
                {
                    let dimensions = env::var("AMCP_RAG_EMBEDDING_DIMENSIONS")
                        .ok()
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(256);
                    let provider = HashedEmbeddingProvider::new(
                        rag_config
                            .embedding_model
                            .clone()
                            .unwrap_or_else(|| "hash-v1".into()),
                        dimensions,
                    )?;
                    Some(Box::new(provider))
                } else if rag_config.embedding_provider.as_deref() == Some("openai")
                    && env::var("AMCP_RAG_EGRESS_CONSENT")
                        .ok()
                        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
                {
                    let api_key = env::var("OPENAI_API_KEY")
                        .context("OPENAI_API_KEY is required when OpenAI RAG egress is enabled")?;
                    let model = rag_config
                        .embedding_model
                        .clone()
                        .unwrap_or_else(|| "text-embedding-3-small".into());
                    let dimensions = env::var("AMCP_RAG_EMBEDDING_DIMENSIONS")
                        .ok()
                        .and_then(|value| value.parse::<usize>().ok());
                    let endpoint = env::var("AMCP_RAG_EMBEDDING_ENDPOINT")
                        .unwrap_or_else(|_| "https://api.openai.com/v1/embeddings".into());
                    let provider = OpenAiEmbeddingProvider::with_endpoint(
                        api_key, model, dimensions, endpoint,
                    )?;
                    Some(Box::new(provider))
                } else {
                    None
                };
                let mut persistent_index = PersistentRagIndex::open(&args.db)?;
                let current_sources = catalog.artifact_source_hashes()?;
                persistent_index.invalidate_stale_sources(&current_sources)?;
                let mut manager = LexicalRagManager::load_from_index(
                    rag_config,
                    embedding_provider,
                    &persistent_index,
                )?;
                let documents = hits
                    .into_iter()
                    .map(|hit| RagDocument {
                        record_id: hit.artifact_id,
                        scope: Scope {
                            host_id: Some(hit.host_id),
                            provider_id: Some(hit.provider_id),
                            project_id: scope.project_id.clone(),
                        },
                        title: hit.title,
                        content: hit.preview,
                        source_reference: hit.source_reference,
                        source_hash: hit.source_hash,
                        sensitivity: hit.sensitivity,
                        lifecycle: LifecycleState::Active,
                    })
                    .collect::<Vec<_>>();
                manager.index(&documents)?;
                let purged = manager.purge_expired(Utc::now())?;
                manager.persist_to_index(&mut persistent_index)?;
                let mut context = manager.retrieve(query, &scope, limit)?;
                manager.record_retrieval(
                    &mut persistent_index,
                    query,
                    &scope,
                    context.citations.len(),
                )?;
                if purged > 0 {
                    context.warning = Some(format!(
                        "{purged} expired RAG chunks were purged before retrieval."
                    ));
                }
                Ok(serde_json::to_value(context)?)
            } else {
                let manager = DisabledRagManager::default();
                Ok(serde_json::to_value(
                    manager.retrieve(query, &scope, limit)?,
                )?)
            }
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

fn read_artifact(args: &Args, arguments: Value) -> Result<Value> {
    let host_id = arguments
        .get("host_id")
        .and_then(Value::as_str)
        .context("amcp_artifact_read requires host_id")?;
    let provider_id = arguments
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    let source_reference = arguments
        .get("source_reference")
        .and_then(Value::as_str)
        .context("amcp_artifact_read requires source_reference")?;
    if source_reference.len() > 4_096 {
        anyhow::bail!("source_reference exceeds the safety limit");
    }
    let mut command = Command::new(&args.controller_bin);
    command
        .args(["read-artifact", "--socket"])
        .arg(&args.agent_socket)
        .args([
            "--host-id",
            host_id,
            "--provider-id",
            provider_id,
            "--source",
            source_reference,
            "--token",
            &args.agent_token,
            "--json",
            "--no-start-agent",
        ]);
    if let Some(agent_url) = &args.agent_url {
        command.args(["--agent-url", agent_url]);
    }
    if let Some(tls_ca) = &args.tls_ca {
        command.args(["--tls-ca", tls_ca.to_string_lossy().as_ref()]);
    }
    if let Some(server_name) = &args.tls_server_name {
        command.args(["--tls-server-name", server_name]);
    }
    if let Some(codex_home) = &args.codex_home {
        command.args(["--codex-home", codex_home.to_string_lossy().as_ref()]);
    }
    let output = command.output().context("start Controller artifact read")?;
    if !output.status.success() {
        anyhow::bail!(
            "Controller artifact read failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let artifact: Value =
        serde_json::from_slice(&output.stdout).context("decode Controller artifact response")?;
    Ok(json!({
        "artifact": artifact,
        "host_id": host_id,
        "provider_id": provider_id,
        "source_reference": source_reference,
        "redacted": true,
        "citation": format!("{source_reference}#live-read")
    }))
}

fn runtime_threads_list(args: &Args, arguments: Value) -> Result<Value> {
    let requested_host = arguments.get("host_id").and_then(Value::as_str);
    let provider_id = arguments
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 64);
    let mut command = Command::new(&args.controller_bin);
    command
        .args(["runtime-list", "--socket"])
        .arg(&args.agent_socket)
        .args([
            "--limit",
            &limit.to_string(),
            "--provider-id",
            provider_id,
            "--token",
            &args.agent_token,
            "--json",
            "--no-start-agent",
        ]);
    if let Some(agent_url) = &args.agent_url {
        command.args(["--agent-url", agent_url]);
    }
    if let Some(tls_ca) = &args.tls_ca {
        command.args(["--tls-ca"]).arg(tls_ca);
    }
    if let Some(server_name) = &args.tls_server_name {
        command.args(["--tls-server-name", server_name]);
    }
    if let Some(codex_home) = &args.codex_home {
        command.args(["--codex-home"]).arg(codex_home);
    }
    let output = command.output().context("start Controller runtime read")?;
    if !output.status.success() {
        anyhow::bail!(
            "Controller runtime read failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let result: Value =
        serde_json::from_slice(&output.stdout).context("decode Controller runtime read")?;
    if requested_host
        .is_some_and(|host_id| result.get("host_id").and_then(Value::as_str) != Some(host_id))
    {
        anyhow::bail!("runtime response host does not match requested host scope");
    }
    Ok(result)
}

fn runtime_thread_read(args: &Args, arguments: Value) -> Result<Value> {
    let requested_host = arguments.get("host_id").and_then(Value::as_str);
    let thread_id = arguments
        .get("thread_id")
        .and_then(Value::as_str)
        .context("amcp_runtime_thread_read requires thread_id")?;
    let provider_id = arguments
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    let mut command = Command::new(&args.controller_bin);
    command
        .args(["runtime-read", "--socket"])
        .arg(&args.agent_socket)
        .args(["--provider-id", provider_id, "--token", &args.agent_token])
        .arg(thread_id)
        .args(["--json", "--no-start-agent"]);
    if let Some(agent_url) = &args.agent_url {
        command.args(["--agent-url", agent_url]);
    }
    if let Some(tls_ca) = &args.tls_ca {
        command.args(["--tls-ca"]).arg(tls_ca);
    }
    if let Some(server_name) = &args.tls_server_name {
        command.args(["--tls-server-name", server_name]);
    }
    if let Some(codex_home) = &args.codex_home {
        command.args(["--codex-home"]).arg(codex_home);
    }
    let output = command
        .output()
        .context("start Controller runtime thread read")?;
    if !output.status.success() {
        anyhow::bail!(
            "Controller runtime thread read failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let result: Value =
        serde_json::from_slice(&output.stdout).context("decode Controller runtime thread read")?;
    if requested_host
        .is_some_and(|host_id| result.get("host_id").and_then(Value::as_str) != Some(host_id))
    {
        anyhow::bail!("runtime response host does not match requested host scope");
    }
    Ok(result)
}

fn runtime_thread_change_propose(args: &Args, arguments: Value) -> Result<Value> {
    let requested_host = arguments.get("host_id").and_then(Value::as_str);
    let thread_id = arguments
        .get("thread_id")
        .and_then(Value::as_str)
        .context("amcp_runtime_thread_change_propose requires thread_id")?;
    let archived = arguments
        .get("archived")
        .and_then(Value::as_bool)
        .context("amcp_runtime_thread_change_propose requires archived")?;
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .context("amcp_runtime_thread_change_propose requires reason")?;
    let provider_id = arguments
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("codex");
    let mut command = Command::new(&args.controller_bin);
    command
        .args(["runtime-propose", "--socket"])
        .arg(&args.agent_socket)
        .args(["--provider-id", provider_id, "--db"])
        .arg(&args.db)
        .args(["--token", &args.agent_token, "--reason", reason])
        .arg(if archived { "--archive" } else { "--unarchive" })
        .arg(thread_id)
        .arg("--json")
        .arg("--no-start-agent");
    if let Some(agent_url) = &args.agent_url {
        command.args(["--agent-url", agent_url]);
    }
    if let Some(tls_ca) = &args.tls_ca {
        command.args(["--tls-ca"]).arg(tls_ca);
    }
    if let Some(server_name) = &args.tls_server_name {
        command.args(["--tls-server-name", server_name]);
    }
    if let Some(codex_home) = &args.codex_home {
        command.args(["--codex-home"]).arg(codex_home);
    }
    let output = command
        .output()
        .context("start Controller runtime change proposal")?;
    if !output.status.success() {
        anyhow::bail!(
            "Controller runtime change proposal failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let result: Value =
        serde_json::from_slice(&output.stdout).context("decode runtime change proposal")?;
    if requested_host.is_some_and(|host_id| {
        result
            .get("scope")
            .and_then(|scope| scope.get("host_id"))
            .and_then(Value::as_str)
            != Some(host_id)
    }) {
        anyhow::bail!("runtime proposal does not match requested host scope");
    }
    Ok(result)
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
    let provider_id = arguments
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("codex");
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
        .args([
            "--provider-id",
            provider_id,
            "--source",
            source,
            "--replacement-file",
        ])
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
