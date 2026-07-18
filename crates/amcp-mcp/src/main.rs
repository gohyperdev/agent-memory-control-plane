use amcp_core::CatalogService;
use amcp_domain::{ChangeStatus, LifecycleState, Scope, new_id};
use amcp_platform::default_agent_socket_path;
use amcp_rag::{
    DisabledRagManager, EmbeddingProvider, HashedEmbeddingProvider, LexicalRagManager,
    OpenAiEmbeddingProvider, PersistentRagIndex, RagConfig, RagDocument, RagManager,
    validate_rag_config,
};
use amcp_storage::{SearchFilters, SessionFilters};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
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
            let output = call_tool(args, &params.name, params.arguments.clone())?;
            let output = structured_tool_result(&params.name, &params.arguments, output);
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

/// Keep the MCP transport contract consistent without forcing every tool to
/// reimplement request metadata. Tool-specific payloads stay under `data` so
/// callers can distinguish evidence about an AMCP request from the request's
/// own normalized results.
fn structured_tool_result(name: &str, arguments: &Value, data: Value) -> Value {
    let scope = arguments.get("scope").unwrap_or(arguments);
    let host_id = scope
        .get("host_id")
        .and_then(Value::as_str)
        .or_else(|| data.get("host_id").and_then(Value::as_str));
    let provider_id = scope
        .get("provider_id")
        .and_then(Value::as_str)
        .or_else(|| data.get("provider_id").and_then(Value::as_str));
    let evidence = data
        .get("results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .filter_map(|result| result.get("citation").cloned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let warnings = data
        .get("warnings")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    json!({
        "request_id": new_id("mcp-request"),
        "tool": name,
        "host_id": host_id,
        "provider_id": provider_id,
        "result_status": data.get("result_status").and_then(Value::as_str).unwrap_or("ok"),
        "evidence": evidence,
        "warnings": warnings,
        "data": data,
    })
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
                        },
                        "artifact_types": { "type": "array", "items": { "type": "string", "enum": ["Configuration", "Instruction", "Memory", "Session", "Tooling", "ProjectContext", "RuntimeEvent"] } },
                        "project_trust_levels": { "type": "array", "items": { "type": "string", "enum": ["trusted", "untrusted", "unknown", "inaccessible"] } },
                        "lifecycle_states": { "type": "array", "items": { "type": "string", "enum": ["Discovered", "Candidate", "Approved", "Active", "Stale", "Superseded", "Deleted"] } },
                        "sensitivity_max": { "type": "string", "enum": ["Public", "Internal", "Sensitive", "SecretLike"] },
                        "observed_after": { "type": "string", "format": "date-time" },
                        "observed_before": { "type": "string", "format": "date-time" }
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
                "description": "List normalized session metadata without exposing transcript bodies by default. Filters are enforced by the shared Controller catalog.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string" },
                        "project_id": { "type": "string" },
                        "branch": { "type": "string" },
                        "model": { "type": "string" },
                        "archived": { "type": "boolean" },
                        "started_after": { "type": "string", "format": "date-time" },
                        "started_before": { "type": "string", "format": "date-time" }
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
                        "provider_id": { "type": "string" },
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
                        "provider_id": { "type": "string" },
                        "project_id": { "type": "string" }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_guidance_chain_get",
                "description": "List applicable AGENTS.md, rules and user skills in effective precedence order for a host or project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string" },
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
                "name": "amcp_audit_events_list",
                "description": "List bounded AMCP audit metadata for sensitive reads and approved writes. It never returns artifact bodies, diffs, or provider payloads.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": { "type": "string" },
                        "provider_id": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                    }
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            },
            {
                "name": "amcp_diagnostics_run",
                "description": "Return bounded, content-free AMCP health metadata: hosts, provider capabilities, recent collection and search counters/latency, latest index run, pending approvals, event count, and derived RAG statistics. It never reads native provider files or returns transcript, memory, or artifact content.",
                "inputSchema": { "type": "object", "properties": {} },
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

fn parse_enum_filter<T: serde::de::DeserializeOwned>(
    value: Option<&Value>,
    field: &str,
) -> Result<Vec<T>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    serde_json::from_value(value.clone())
        .with_context(|| format!("{field} must be an array of supported values"))
}

fn parse_string_filter(value: Option<&Value>, field: &str) -> Result<Vec<String>> {
    parse_enum_filter(value, field)
}

fn parse_optional_enum_filter<T: serde::de::DeserializeOwned>(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<T>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    serde_json::from_value(value.clone())
        .map(Some)
        .with_context(|| format!("{field} must be a supported value"))
}

fn parse_optional_timestamp(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<Utc>>> {
    let Some(value) = value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| Some(value.with_timezone(&Utc)))
        .with_context(|| format!("{field} must be an ISO 8601 timestamp"))
}

fn parse_optional_bool(value: Option<&Value>, field: &str) -> Result<Option<bool>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .with_context(|| format!("{field} must be a boolean"))
}

fn call_tool(args: &Args, name: &str, arguments: Value) -> Result<Value> {
    let mut catalog = CatalogService::open(&args.db)?;
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
            let hits = catalog.search_filtered(
                query,
                limit,
                &SearchFilters {
                    host_id: host_id.map(str::to_owned),
                    provider_id: provider_id.map(str::to_owned),
                    project_id: project_id.map(str::to_owned),
                    project_trust_levels: parse_string_filter(
                        arguments.get("project_trust_levels"),
                        "project_trust_levels",
                    )?,
                    artifact_kinds: parse_enum_filter(
                        arguments.get("artifact_types"),
                        "artifact_types",
                    )?,
                    lifecycle_states: parse_enum_filter(
                        arguments.get("lifecycle_states"),
                        "lifecycle_states",
                    )?,
                    sensitivity_max: parse_optional_enum_filter(
                        arguments.get("sensitivity_max"),
                        "sensitivity_max",
                    )?,
                    observed_after: parse_optional_timestamp(
                        arguments.get("observed_after"),
                        "observed_after",
                    )?,
                    observed_before: parse_optional_timestamp(
                        arguments.get("observed_before"),
                        "observed_before",
                    )?,
                },
            )?;
            catalog.audit_sensitive_search_results("mcp.search", &hits)?;
            let result_status = if hits.is_empty() {
                if catalog.artifact_count()? == 0 {
                    "not_indexed"
                } else {
                    "not_found"
                }
            } else {
                "ok"
            };
            Ok(json!({
                "query": query,
                "scope": { "host_id": host_id, "provider_id": provider_id, "project_id": project_id },
                "result_status": result_status,
                "results": hits.into_iter().map(|hit| json!({
                    "artifact_id": hit.artifact_id,
                    "project_id": hit.project_id,
                    "project_trust_level": hit.project_trust_level,
                    "kind": hit.kind,
                    "lifecycle": hit.lifecycle,
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
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            let branch = arguments.get("branch").and_then(Value::as_str);
            let model = arguments.get("model").and_then(Value::as_str);
            Ok(
                json!({ "sessions": catalog.list_sessions_filtered(&SessionFilters {
                host_id: host_id.map(str::to_owned),
                provider_id: provider_id.map(str::to_owned),
                project_id: project_id.map(str::to_owned),
                branch: branch.map(str::to_owned),
                model: model.map(str::to_owned),
                archived: parse_optional_bool(arguments.get("archived"), "archived")?,
                started_after: parse_optional_timestamp(arguments.get("started_after"), "started_after")?,
                started_before: parse_optional_timestamp(arguments.get("started_before"), "started_before")?,
            })? }),
            )
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
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(
                json!({ "memory": catalog.list_memory_records_scoped(host_id, provider_id, project_id)? }),
            )
        }
        "amcp_config_layers_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(
                json!({ "config_layers": catalog.list_config_layers_scoped(host_id, provider_id, project_id)? }),
            )
        }
        "amcp_guidance_chain_get" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let project_id = arguments.get("project_id").and_then(Value::as_str);
            Ok(
                json!({ "guidance": catalog.list_guidance_scoped(host_id, provider_id, project_id)? }),
            )
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
        "amcp_audit_events_list" => {
            let host_id = arguments.get("host_id").and_then(Value::as_str);
            let provider_id = arguments.get("provider_id").and_then(Value::as_str);
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .clamp(1, 100) as usize;
            Ok(json!({ "audit_events": catalog.list_audit_events(host_id, provider_id, limit)? }))
        }
        "amcp_diagnostics_run" => diagnostics_run(&catalog, &args.db),
        "amcp_runtime_threads_list" => runtime_threads_list(args, arguments),
        "amcp_runtime_thread_read" => runtime_thread_read(args, arguments),
        "amcp_runtime_thread_change_propose" => runtime_thread_change_propose(args, arguments),
        "amcp_rag_status" => {
            let index = PersistentRagIndex::open(&args.db)?;
            let config = rag_config_from_environment(index.load_config()?)?;
            Ok(json!({
                "enabled": config.enabled,
                "embedding_provider": config.embedding_provider,
                "egress_consent": rag_egress_consent(),
                "config": config,
                "index": index.stats()?
            }))
        }
        "amcp_retrieve_context" => {
            let query = arguments
                .get("query")
                .and_then(Value::as_str)
                .context("amcp_retrieve_context requires query")?;
            let scope = parse_scope(arguments.get("scope"));
            let mut persistent_index = PersistentRagIndex::open(&args.db)?;
            let rag_config = rag_config_from_environment(persistent_index.load_config()?)?;
            let limit = arguments
                .get("limit")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(rag_config.retrieval_limit)
                .clamp(1, 20) as usize;
            if rag_config.enabled {
                let hits = catalog.search_scoped(
                    query,
                    (limit * 3).min(50),
                    scope.host_id.as_deref(),
                    scope.provider_id.as_deref(),
                    scope.project_id.as_deref(),
                )?;
                catalog.audit_sensitive_search_results("mcp.retrieve_context", &hits)?;
                let embedding_provider: Option<Box<dyn EmbeddingProvider>> = if rag_config
                    .embedding_provider
                    .as_deref()
                    .is_some_and(|provider| provider == "local-hash")
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
                    && rag_egress_consent()
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
                            project_id: hit.project_id,
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
                let retrieval_started = Instant::now();
                let mut context = manager.retrieve(query, &scope, limit)?;
                manager.record_retrieval(
                    &mut persistent_index,
                    &scope,
                    context.context.len(),
                    context.citations.len(),
                    retrieval_started
                        .elapsed()
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
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

fn diagnostics_run(catalog: &CatalogService, db: &std::path::Path) -> Result<Value> {
    let hosts = catalog.list_hosts()?;
    let providers = catalog.list_providers(None)?;
    let pending_change_count = catalog
        .list_change_sets(Some(ChangeStatus::Proposed))?
        .len();
    let recent_event_count = catalog.list_runtime_events(None, None, 20)?.len();
    let recent_collection_runs = catalog.list_collection_runs(None, None, 20)?;
    let recent_search_runs = catalog.list_search_runs(None, None, 20)?;
    let index = catalog.latest_index_run()?;
    let catalog_diagnostics = catalog.diagnostics()?;
    let rag = PersistentRagIndex::open(db)?.stats()?;
    Ok(json!({
        "generated_at": Utc::now(),
        "hosts": hosts,
        "providers": providers,
        "latest_index_run": index,
        "pending_change_count": pending_change_count,
        "recent_event_count": recent_event_count,
        "recent_collection_runs": recent_collection_runs,
        "recent_search_runs": recent_search_runs,
        "catalog_diagnostics": catalog_diagnostics,
        "rag": rag,
        "content_included": false
    }))
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
        .arg("--db")
        .arg(&args.db)
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
        error: Some(JsonRpcError {
            code,
            data: (code == -32000).then(|| {
                json!({
                    "result_status": tool_error_status(&message),
                })
            }),
            message,
        }),
    }
}

/// Tool errors are intentionally classified without carrying native paths,
/// provider payloads, or policy details. This lets an MCP client distinguish
/// absence from an Agent-side safety denial while keeping the raw error useful
/// for the human-controlled Controller workflow.
fn tool_error_status(message: &str) -> &'static str {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("unsupported") {
        "unsupported"
    } else if normalized.contains("untrusted")
        || normalized.contains("outside a trusted project")
        || normalized.contains("not a trusted project")
    {
        "untrusted"
    } else if normalized.contains("permission denied")
        || normalized.contains("access denied")
        || normalized.contains("forbidden")
        || normalized.contains("denied by")
        || normalized.contains("scope_denied")
        || normalized.contains("read_denied")
        || normalized.contains("proposal_denied")
        || normalized.contains("runtime_change_denied")
    {
        "permission_denied"
    } else if normalized.contains("not found") || normalized.contains("not indexed") {
        "not_found"
    } else {
        "failed"
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

/// The central, persisted policy controls RAG behavior. Environment variables
/// remain a backwards-compatible deployment override; notably, egress consent
/// is deliberately *not* persisted and must still be supplied by the process
/// that owns the embedding credential.
fn rag_config_from_environment(mut config: RagConfig) -> Result<RagConfig> {
    if let Ok(value) = env::var("AMCP_RAG_ENABLED") {
        config.enabled = matches!(value.as_str(), "1" | "true" | "TRUE");
    }
    if let Ok(provider) = env::var("AMCP_RAG_EMBEDDING_PROVIDER") {
        config.embedding_provider = Some(match provider.as_str() {
            "hash" => "local-hash".to_owned(),
            _ => provider,
        });
    }
    if let Ok(model) = env::var("AMCP_RAG_EMBEDDING_MODEL") {
        config.embedding_model = Some(model);
    }
    if let Ok(days) = env::var("AMCP_RAG_RETENTION_DAYS") {
        config.retention_days = Some(
            days.parse()
                .context("AMCP_RAG_RETENTION_DAYS must be an unsigned integer")?,
        );
    }
    if let Ok(chunk_size) = env::var("AMCP_RAG_CHUNK_SIZE") {
        config.chunk_size = chunk_size
            .parse()
            .context("AMCP_RAG_CHUNK_SIZE must be an unsigned integer")?;
    }
    if let Ok(retrieval_limit) = env::var("AMCP_RAG_RETRIEVAL_LIMIT") {
        config.retrieval_limit = retrieval_limit
            .parse()
            .context("AMCP_RAG_RETRIEVAL_LIMIT must be an unsigned integer")?;
    }
    validate_rag_config(&config)?;
    Ok(config)
}

fn rag_egress_consent() -> bool {
    env::var("AMCP_RAG_EGRESS_CONSENT")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_args() -> Args {
        Args {
            db: PathBuf::from(":memory:"),
            controller_bin: PathBuf::from("amcp-controller"),
            agent_socket: PathBuf::from("/tmp/amcp-mcp-test.sock"),
            agent_url: None,
            tls_ca: None,
            tls_server_name: None,
            agent_token: "test-token".into(),
            codex_home: None,
        }
    }

    #[test]
    fn diagnostics_tool_is_advertised_and_content_free() {
        let tool_list = tool_list();
        let tools = tool_list["tools"].as_array().expect("MCP tool list array");
        assert!(
            tools
                .iter()
                .any(|tool| tool["name"] == "amcp_diagnostics_run")
        );

        let diagnostics =
            call_tool(&test_args(), "amcp_diagnostics_run", json!({})).expect("run diagnostics");
        assert_eq!(diagnostics["content_included"], false);
        assert!(diagnostics["hosts"].is_array());
        assert!(diagnostics["providers"].is_array());
        assert!(diagnostics["recent_collection_runs"].is_array());
        assert!(diagnostics["recent_search_runs"].is_array());
        assert!(diagnostics["catalog_diagnostics"]["stale_source_ratio"].is_number());
        assert!(diagnostics["catalog_diagnostics"]["search_index_coverage_ratio"].is_number());
        assert!(diagnostics["catalog_diagnostics"]["database_size_bytes"].is_number());
        assert!(diagnostics["catalog_diagnostics"]["applied_change_count"].is_number());
        assert!(diagnostics["catalog_diagnostics"]["stale_artifacts"].is_array());
        assert!(diagnostics["catalog_diagnostics"]["projects_requiring_attention"].is_array());
        assert!(diagnostics["catalog_diagnostics"]["conflicted_changes"].is_array());
        assert!(diagnostics["rag"].is_object());
        assert!(diagnostics["rag"]["retrieval_citation_coverage_basis_points"].is_number());
        assert!(diagnostics.get("events").is_none());
    }

    #[test]
    fn rag_status_exposes_the_private_policy_without_credentials() {
        let status = call_tool(&test_args(), "amcp_rag_status", json!({})).expect("RAG status");
        assert_eq!(status["enabled"], false);
        assert_eq!(status["config"]["chunk_size"], 800);
        assert_eq!(status["config"]["retrieval_limit"], 5);
        assert!(status["config"]["allowed_scopes"].is_array());
        assert!(status.get("api_key").is_none());
    }

    #[test]
    fn audit_tool_is_advertised_as_a_bounded_metadata_only_read() {
        let tools = tool_list();
        let audit = tools["tools"]
            .as_array()
            .expect("tool list")
            .iter()
            .find(|tool| tool["name"] == "amcp_audit_events_list")
            .expect("audit tool");
        assert_eq!(audit["annotations"]["readOnlyHint"], true);
        assert!(audit["inputSchema"]["properties"]["host_id"].is_object());
        assert!(audit["inputSchema"]["properties"]["provider_id"].is_object());
        assert_eq!(
            call_tool(
                &test_args(),
                "amcp_audit_events_list",
                json!({ "limit": 1 })
            )
            .expect("list audit events")["audit_events"]
                .as_array()
                .expect("audit event array")
                .len(),
            0
        );
    }

    #[test]
    fn tool_results_have_a_scoped_contract_envelope() {
        let request = JsonRpcRequest {
            _jsonrpc: Some("2.0".into()),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({
                "name": "amcp_diagnostics_run",
                "arguments": { "scope": { "host_id": "host-test", "provider_id": "codex" } }
            }),
        };

        let result = handle_request(&test_args(), &request).expect("call diagnostics tool");
        let output = &result["structuredContent"];
        assert!(
            output["request_id"]
                .as_str()
                .is_some_and(|request_id| request_id.starts_with("mcp-request_"))
        );
        assert_eq!(output["host_id"], "host-test");
        assert_eq!(output["provider_id"], "codex");
        assert_eq!(output["result_status"], "ok");
        assert!(output["evidence"].is_array());
        assert!(output["warnings"].is_array());
        assert_eq!(output["data"]["content_included"], false);
    }

    #[test]
    fn search_tool_advertises_and_validates_shared_catalog_filters() {
        let tools = tool_list();
        let search = tools["tools"]
            .as_array()
            .expect("tool list")
            .iter()
            .find(|tool| tool["name"] == "amcp_search")
            .expect("search tool");
        let properties = &search["inputSchema"]["properties"];
        assert!(properties["artifact_types"].is_object());
        assert!(properties["project_trust_levels"].is_object());
        assert!(properties["lifecycle_states"].is_object());
        assert!(properties["sensitivity_max"].is_object());
        assert!(properties["observed_after"].is_object());
        assert!(
            parse_optional_timestamp(Some(&json!("2026-07-18T12:00:00Z")), "after")
                .expect("valid timestamp")
                .is_some()
        );
        assert!(parse_optional_timestamp(Some(&json!("not-a-timestamp")), "after").is_err());
        assert_eq!(
            parse_string_filter(Some(&json!(["trusted"])), "project_trust_levels").unwrap(),
            vec!["trusted"]
        );
    }

    #[test]
    fn session_tool_advertises_metadata_filters_without_transcript_access() {
        let tools = tool_list();
        let sessions = tools["tools"]
            .as_array()
            .expect("tool list")
            .iter()
            .find(|tool| tool["name"] == "amcp_sessions_list")
            .expect("sessions tool");
        let properties = &sessions["inputSchema"]["properties"];
        for filter in [
            "provider_id",
            "branch",
            "model",
            "archived",
            "started_after",
        ] {
            assert!(properties[filter].is_object(), "missing {filter}");
        }
        assert_eq!(
            parse_optional_bool(Some(&json!(false)), "archived").unwrap(),
            Some(false)
        );
        assert!(parse_optional_bool(Some(&json!("false")), "archived").is_err());
    }

    #[test]
    fn search_result_and_tool_errors_expose_safe_outcome_statuses() {
        let empty_search = call_tool(&test_args(), "amcp_search", json!({ "query": "missing" }))
            .expect("search empty catalog");
        assert_eq!(empty_search["result_status"], "not_indexed");

        let request = JsonRpcRequest {
            _jsonrpc: Some("2.0".into()),
            id: Some(json!(2)),
            method: "tools/call".into(),
            params: json!({
                "name": "amcp_artifact_read",
                "arguments": { "host_id": "host-test", "source_reference": "a" }
            }),
        };
        let response = match handle_request(&test_args(), &request) {
            Ok(_) => panic!("read without a Controller must fail"),
            Err(error) => error_response(json!(2), -32000, error.to_string()),
        };
        assert!(response.error.is_some());
        assert_eq!(tool_error_status("provider is unsupported"), "unsupported");
        assert_eq!(tool_error_status("project is untrusted"), "untrusted");
        assert_eq!(
            tool_error_status("change target is outside a trusted project root"),
            "untrusted"
        );
        assert_eq!(
            tool_error_status("request denied by local policy"),
            "permission_denied"
        );
        assert_eq!(tool_error_status("scope_denied"), "permission_denied");
        assert_eq!(tool_error_status("artifact not found"), "not_found");
        assert_eq!(
            response
                .error
                .expect("MCP error")
                .data
                .expect("outcome data")["result_status"],
            "failed"
        );
    }
}
