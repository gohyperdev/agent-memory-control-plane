#![allow(clippy::collapsible_if)]
#![allow(clippy::items_after_test_module)]
#![allow(clippy::ptr_arg)]

use amcp_app_server::AppServerClient;
use amcp_codex::CodexAdapter;
use amcp_domain::{
    ApprovalEnvelope, ArtifactRef, ChangeOperation, ChangeOperationKind, ChangeReceipt, ChangeSet,
    ChangeStatus, HostIdentity, RuntimeEvent, RuntimeThreadSnapshot, new_id,
};
use amcp_domain::{change_set_operations_hash, runtime_thread_state_hash};
use amcp_file_providers::{AntigravityAdapter, ClaudeCodeAdapter, KiroAdapter};
use amcp_platform::{
    MacOsKeychain, SecretStore, default_agent_socket_path, keychain_account_for_host,
};
use amcp_protocol::{
    PROTOCOL_VERSION, ProtocolError, RequestEnvelope, RequestMethod, ResponseEnvelope,
    ResponsePayload,
};
use amcp_provider_api::{ProviderAdapter, ProviderRegistry};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use std::{
    collections::HashSet,
    env,
    fs::File,
    io::BufReader as StdBufReader,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration as StdDuration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixListener},
    time::{interval, sleep},
};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Parser)]
#[command(name = "amcp-agent", about = "AMCP local host Agent")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(
        long,
        default_value_os_t = default_agent_socket_path(),
        env = "AMCP_AGENT_SOCKET"
    )]
    socket: PathBuf,
    #[arg(long, env = "CODEX_HOME")]
    codex_home: Option<PathBuf>,
    #[arg(
        long,
        default_value = "amcp-development-token",
        env = "AMCP_AGENT_TOKEN"
    )]
    token: String,
    #[arg(long, env = "AMCP_AGENT_TCP_BIND")]
    tcp_bind: Option<String>,
    #[arg(long, env = "AMCP_AGENT_TLS_CERT")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "AMCP_AGENT_TLS_KEY")]
    tls_key: Option<PathBuf>,
    #[arg(long, env = "AMCP_AGENT_PAIRING_CODE")]
    pairing_code: Option<String>,
    #[arg(
        long,
        default_value_t = 300,
        env = "AMCP_AGENT_PAIRING_TIMEOUT_SECONDS"
    )]
    pairing_timeout_seconds: u64,
    #[arg(long, default_value_t = false, env = "AMCP_AGENT_APP_SERVER_ENABLED")]
    app_server_enabled: bool,
    #[arg(long, default_value = "codex", env = "AMCP_CODEX_BIN")]
    codex_bin: PathBuf,
    #[arg(long, default_value_t = 5_000, env = "AMCP_AGENT_RUNTIME_POLL_MS")]
    runtime_poll_ms: u64,
    #[arg(long, env = "AMCP_AGENT_RUNTIME_CWD")]
    runtime_cwd: Option<PathBuf>,
}

struct AgentAuth {
    bootstrap_token: String,
    enrolled_credential: Option<String>,
    credential_expires_at: Option<chrono::DateTime<Utc>>,
    pairing_code: Option<String>,
    pairing_expires_at: chrono::DateTime<Utc>,
    consumed_approval_ids: HashSet<String>,
}

impl AgentAuth {
    fn new(token: String, pairing_code: Option<String>, timeout_seconds: u64) -> Self {
        let pairing_code = pairing_code.unwrap_or_else(|| {
            new_id("pairing")
                .split('_')
                .nth(1)
                .unwrap_or("00000000")
                .chars()
                .take(8)
                .collect()
        });
        Self {
            bootstrap_token: token,
            enrolled_credential: None,
            credential_expires_at: None,
            pairing_code: Some(pairing_code),
            pairing_expires_at: Utc::now() + Duration::seconds(timeout_seconds.max(1) as i64),
            consumed_approval_ids: HashSet::new(),
        }
    }

    fn accepts(&self, token: Option<&str>) -> bool {
        let Some(token) = token else { return false };
        if token == self.bootstrap_token {
            return true;
        }
        self.enrolled_credential.as_deref() == Some(token)
            && self
                .credential_expires_at
                .is_some_and(|expires_at| Utc::now() <= expires_at)
    }
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    Once {
        #[arg(long)]
        json: bool,
    },
    Serve,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command.clone().unwrap_or(Command::Serve) {
        Command::Once { json } => collect_once(args, json),
        Command::Serve => serve(args).await,
    }
}

fn collect_once(args: Args, json: bool) -> Result<()> {
    let adapter = CodexAdapter::from_environment(args.codex_home);
    let batch = adapter.discover(host_identity())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&batch)?);
    } else {
        println!(
            "AMCP Agent discovered {} Codex artifacts",
            batch.artifacts.len()
        );
        for artifact in batch.artifacts.iter().take(20) {
            println!("- {} [{}]", artifact.source_reference, artifact.title);
        }
    }
    Ok(())
}

async fn serve(args: Args) -> Result<()> {
    let token = resolve_agent_token(&args.token);
    let auth = Arc::new(Mutex::new(AgentAuth::new(
        token,
        args.pairing_code.clone(),
        args.pairing_timeout_seconds,
    )));
    let pairing_code = auth
        .lock()
        .expect("Agent auth mutex")
        .pairing_code
        .clone()
        .unwrap_or_default();
    eprintln!(
        "AMCP Agent pairing code (expires in {}s): {pairing_code}",
        args.pairing_timeout_seconds
    );
    let _local_watcher = start_local_watcher(
        CodexAdapter::from_environment(args.codex_home.clone()).codex_home,
        default_state_dir(),
    );
    let _runtime_connector = if args.app_server_enabled {
        Some(start_runtime_connector(
            args.codex_bin.clone(),
            args.codex_home.clone(),
            args.runtime_cwd.clone(),
            default_state_dir(),
            args.runtime_poll_ms,
        ))
    } else {
        None
    };
    if args.app_server_enabled {
        eprintln!(
            "AMCP Codex app-server runtime connector enabled (poll={}ms)",
            args.runtime_poll_ms.max(250)
        );
    }
    if let Some(bind) = args.tcp_bind.clone() {
        return serve_tls(args, bind, auth).await;
    }
    serve_unix(args, auth).await
}

fn start_local_watcher(
    codex_home: PathBuf,
    state_dir: PathBuf,
) -> Option<std::thread::JoinHandle<()>> {
    if !codex_home.exists() {
        eprintln!(
            "AMCP local watcher skipped because Codex home does not exist: {}",
            codex_home.display()
        );
        return None;
    }
    let watch_root = std::fs::canonicalize(&codex_home).unwrap_or(codex_home);
    let _ = std::fs::create_dir_all(&state_dir);
    let state_root = std::fs::canonicalize(&state_dir).unwrap_or(state_dir.clone());
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut watcher = match RecommendedWatcher::new(
        move |result| {
            let _ = sender.send(result);
        },
        Config::default(),
    ) {
        Ok(watcher) => watcher,
        Err(error) => {
            eprintln!("AMCP local watcher unavailable: {error}");
            return None;
        }
    };
    if let Err(error) = watcher.watch(&watch_root, RecursiveMode::Recursive) {
        eprintln!(
            "AMCP local watcher could not watch {}: {error}",
            watch_root.display()
        );
        return None;
    }
    Some(
        std::thread::Builder::new()
            .name("amcp-codex-watcher".into())
            .spawn(move || {
                let _watcher = watcher;
                let mut sequence = 0i64;
                let mut last_fingerprint = String::new();
                while let Ok(first) = receiver.recv() {
                    let mut notifications = vec![first];
                    while let Ok(next) = receiver.recv_timeout(std::time::Duration::from_millis(50))
                    {
                        notifications.push(next);
                    }
                    let mut kinds = Vec::new();
                    let mut relative_paths = Vec::new();
                    for result in notifications {
                        let Ok(event) = result else {
                            continue;
                        };
                        kinds.push(format!("{:?}", event.kind));
                        relative_paths.extend(event.paths.into_iter().filter_map(|path| {
                            if path.starts_with(&state_root) {
                                return None;
                            }
                            let relative = path.strip_prefix(&watch_root).unwrap_or(&path);
                            let relative = relative.to_string_lossy().into_owned();
                            if relative.ends_with("auth.json") || relative.is_empty() {
                                None
                            } else {
                                Some(relative)
                            }
                        }));
                    }
                    let kind = kinds.join(",");
                    relative_paths.truncate(32);
                    relative_paths.sort();
                    relative_paths.dedup();
                    if relative_paths.is_empty() {
                        continue;
                    }
                    let fingerprint = format!("{kind}:{relative_paths:?}");
                    if fingerprint == last_fingerprint {
                        continue;
                    }
                    last_fingerprint = fingerprint;
                    sequence += 1;
                    let event = RuntimeEvent {
                        event_id: new_id("event"),
                        host_id: host_identity().host_id,
                        provider_id: "codex".to_owned(),
                        event_type: "source.changed".to_owned(),
                        sequence,
                        payload_json: serde_json::json!({
                            "watcher": "notify",
                            "kind": kind,
                            "paths": relative_paths,
                        })
                        .to_string(),
                        occurred_at: Utc::now(),
                    };
                    if let Err(error) = append_runtime_event_outbox(&state_dir, &[event]) {
                        eprintln!("AMCP local watcher could not persist event: {error}");
                    }
                }
            })
            .expect("spawn AMCP local watcher thread"),
    )
}

fn start_runtime_connector(
    codex_bin: PathBuf,
    codex_home: Option<PathBuf>,
    working_directory: Option<PathBuf>,
    state_dir: PathBuf,
    poll_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        runtime_connector_loop(codex_bin, codex_home, working_directory, state_dir, poll_ms).await;
    })
}

async fn runtime_connector_loop(
    codex_bin: PathBuf,
    codex_home: Option<PathBuf>,
    working_directory: Option<PathBuf>,
    state_dir: PathBuf,
    poll_ms: u64,
) {
    let poll_duration = std::time::Duration::from_millis(poll_ms.max(250));
    let mut reconnect_delay = std::time::Duration::from_secs(1);
    let registry = provider_registry(codex_home.clone());
    let provider = match registry.get("codex") {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("AMCP runtime connector disabled: Codex provider unavailable: {error:#}");
            return;
        }
    };
    loop {
        match AppServerClient::spawn(
            &codex_bin,
            codex_home.as_deref(),
            working_directory.as_deref(),
        )
        .await
        {
            Ok(mut client) => {
                match client
                    .initialize("amcp-agent-runtime", env!("CARGO_PKG_VERSION"))
                    .await
                {
                    Ok(_) => {
                        eprintln!("AMCP Agent connected to Codex app-server runtime");
                        reconnect_delay = std::time::Duration::from_secs(1);
                        let host = host_identity();
                        let mut sequence = 0i64;
                        loop {
                            match poll_runtime_threads(&mut client, provider, &host, &mut sequence)
                                .await
                            {
                                Ok(events) => {
                                    if let Err(error) =
                                        append_runtime_event_outbox(&state_dir, &events)
                                    {
                                        eprintln!(
                                            "AMCP runtime connector could not persist events: {error}"
                                        );
                                    }
                                }
                                Err(error) => {
                                    eprintln!(
                                        "AMCP Codex app-server runtime poll failed; reconnecting: {error:#}"
                                    );
                                    break;
                                }
                            }
                            sleep(poll_duration).await;
                        }
                    }
                    Err(error) => eprintln!(
                        "AMCP Codex app-server initialization failed; retrying: {error:#}"
                    ),
                }
                let _ = client.shutdown().await;
            }
            Err(error) => eprintln!(
                "AMCP Codex app-server runtime unavailable; retrying in {}s: {error:#}",
                reconnect_delay.as_secs()
            ),
        }
        sleep(reconnect_delay).await;
        reconnect_delay = (reconnect_delay * 2).min(std::time::Duration::from_secs(30));
    }
}

async fn poll_runtime_threads(
    client: &mut AppServerClient,
    provider: &dyn ProviderAdapter,
    host: &HostIdentity,
    sequence: &mut i64,
) -> Result<Vec<RuntimeEvent>> {
    let mut events = Vec::new();
    let mut cursor = None;
    for _ in 0..8 {
        let response = client.list_threads(cursor.as_deref(), Some(64)).await?;
        for thread in extract_thread_values(&response) {
            if let Some(event) = provider.map_runtime_thread(host, &thread, sequence)? {
                events.push(event);
            }
        }
        let next_cursor = extract_next_thread_cursor(&response);
        if next_cursor.is_none() || next_cursor == cursor {
            break;
        }
        cursor = next_cursor;
    }
    Ok(events)
}

fn extract_thread_values(value: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .filter(|value| value.is_object())
            .cloned()
            .collect();
    }
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    for key in ["threads", "data", "items", "results"] {
        if let Some(nested) = object.get(key) {
            let values = extract_thread_values(nested);
            if !values.is_empty() {
                return values;
            }
        }
    }
    if object
        .get("id")
        .or_else(|| object.get("threadId"))
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        return vec![value.clone()];
    }
    Vec::new()
}

fn extract_runtime_thread_value(value: &serde_json::Value) -> Option<serde_json::Value> {
    if value.is_object()
        && value
            .get("id")
            .or_else(|| value.get("threadId"))
            .or_else(|| value.get("thread_id"))
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        return Some(value.clone());
    }
    let object = value.as_object()?;
    for key in ["thread", "data", "result"] {
        if let Some(nested) = object.get(key)
            && let Some(thread) = extract_runtime_thread_value(nested)
        {
            return Some(thread);
        }
    }
    None
}

fn summarize_runtime_items(value: &serde_json::Value) -> (usize, Vec<String>, Vec<String>) {
    let Some(items) = extract_runtime_items(value) else {
        return (0, Vec::new(), Vec::new());
    };
    let item_count = items.len().min(4_096);
    let mut kinds = Vec::new();
    let mut roles = Vec::new();
    for item in items.iter().take(item_count) {
        let Some(object) = item.as_object() else {
            continue;
        };
        if let Some(value) = ["type", "kind", "itemType"]
            .iter()
            .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
            .map(str::to_owned)
            && !value.is_empty()
            && !kinds.iter().any(|existing| existing == &value)
            && kinds.len() < 32
        {
            kinds.push(value);
        }
        if let Some(value) = object
            .get("role")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            && !value.is_empty()
            && !roles.iter().any(|existing| existing == &value)
            && roles.len() < 32
        {
            roles.push(value);
        }
    }
    (item_count, kinds, roles)
}

fn extract_runtime_items(value: &serde_json::Value) -> Option<&[serde_json::Value]> {
    let object = value.as_object()?;
    if let Some(items) = object.get("items").and_then(serde_json::Value::as_array) {
        return Some(items.as_slice());
    }
    for key in ["thread", "data", "result"] {
        if let Some(nested) = object.get(key)
            && let Some(items) = extract_runtime_items(nested)
        {
            return Some(items);
        }
    }
    None
}

fn extract_next_thread_cursor(value: &serde_json::Value) -> Option<String> {
    let object = value.as_object()?;
    for key in ["nextCursor", "next_cursor"] {
        if let Some(cursor) = object.get(key).and_then(serde_json::Value::as_str) {
            return Some(cursor.to_owned());
        }
    }
    for key in ["data", "result"] {
        if let Some(nested) = object.get(key)
            && let Some(cursor) = extract_next_thread_cursor(nested)
        {
            return Some(cursor);
        }
    }
    None
}

async fn serve_unix(args: Args, auth: Arc<Mutex<AgentAuth>>) -> Result<()> {
    let secure_default_socket = args.socket == default_agent_socket_path();
    if let Some(parent) = args.socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
        if secure_default_socket {
            #[cfg(unix)]
            tokio::fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .await?;
        }
    }
    if args.socket.exists() {
        tokio::fs::remove_file(&args.socket)
            .await
            .context("remove stale Agent socket")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind Agent Unix socket")?;
    #[cfg(unix)]
    tokio::fs::set_permissions(
        &args.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .await?;
    println!("AMCP Agent listening on {}", args.socket.display());

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accept Controller connection")?;
        let auth = auth.clone();
        let codex_home = args.codex_home.clone();
        let codex_bin = args.codex_bin.clone();
        let runtime_cwd = args.runtime_cwd.clone();
        let backup_dir = default_backup_dir();
        let state_dir = default_state_dir();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(
                stream,
                auth,
                codex_home,
                codex_bin,
                runtime_cwd,
                backup_dir,
                state_dir,
            )
            .await
            {
                eprintln!("AMCP Agent connection error: {error:#}");
            }
        });
    }
}

async fn serve_tls(args: Args, bind: String, auth: Arc<Mutex<AgentAuth>>) -> Result<()> {
    let cert_path = args
        .tls_cert
        .as_deref()
        .context("--tls-cert is required for TCP Agent listeners")?;
    let key_path = args
        .tls_key
        .as_deref()
        .context("--tls-key is required for TCP Agent listeners")?;
    let config = load_server_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind AMCP Agent TLS listener at {bind}"))?;
    eprintln!("AMCP Agent listening on TLS TCP {bind}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let auth = auth.clone();
        let codex_home = args.codex_home.clone();
        let codex_bin = args.codex_bin.clone();
        let runtime_cwd = args.runtime_cwd.clone();
        let backup_dir = default_backup_dir();
        let state_dir = default_state_dir();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    if let Err(error) = handle_connection(
                        stream,
                        auth,
                        codex_home,
                        codex_bin,
                        runtime_cwd,
                        backup_dir,
                        state_dir,
                    )
                    .await
                    {
                        eprintln!("AMCP Agent TLS connection error from {peer}: {error:#}");
                    }
                }
                Err(error) => eprintln!("AMCP Agent TLS handshake error from {peer}: {error:#}"),
            }
        });
    }
}

async fn handle_connection<S>(
    stream: S,
    auth: Arc<Mutex<AgentAuth>>,
    codex_home: Option<PathBuf>,
    codex_bin: PathBuf,
    runtime_cwd: Option<PathBuf>,
    backup_dir: PathBuf,
    state_dir: PathBuf,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let request: RequestEnvelope = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut writer,
                    ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id: "unknown".into(),
                        result: Err(ProtocolError::new("invalid_json", error.to_string())),
                    },
                )
                .await?;
                continue;
            }
        };
        if matches!(&request.method, RequestMethod::OpenEventStream { .. }) {
            let (response, stream_config) = open_event_stream(request, &auth);
            write_response(&mut writer, response).await?;
            if let Some(config) = stream_config {
                serve_event_stream(&mut lines, &mut writer, &auth, &state_dir, config).await?;
                break;
            }
            continue;
        }
        let response = if matches!(&request.method, RequestMethod::SubscribeEvents { .. }) {
            process_subscribe_request(request, &auth, &state_dir).await
        } else if matches!(&request.method, RequestMethod::RuntimeListThreads { .. }) {
            process_runtime_list_request(
                request,
                &auth,
                codex_home.clone(),
                &codex_bin,
                runtime_cwd.as_deref(),
            )
            .await
        } else if matches!(&request.method, RequestMethod::RuntimeReadThread { .. }) {
            process_runtime_read_request(
                request,
                &auth,
                codex_home.clone(),
                &codex_bin,
                runtime_cwd.as_deref(),
            )
            .await
        } else if matches!(
            &request.method,
            RequestMethod::RuntimeProposeThreadChange { .. }
                | RequestMethod::RuntimeApplyThreadChange { .. }
        ) {
            process_runtime_change_request(
                request,
                &auth,
                codex_home.clone(),
                &codex_bin,
                runtime_cwd.as_deref(),
                &state_dir,
            )
            .await
        } else {
            process_request(request, &auth, codex_home.clone(), &backup_dir, &state_dir)
        };
        let should_close = matches!(&response.result, Ok(ResponsePayload::ShutdownAck));
        write_response(&mut writer, response).await?;
        if should_close {
            break;
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct EventStreamConfig {
    stream_id: String,
    after_event_id: Option<String>,
    scope: Option<amcp_domain::Scope>,
    max_in_flight: usize,
    heartbeat: StdDuration,
}

fn open_event_stream(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
) -> (ResponseEnvelope, Option<EventStreamConfig>) {
    let request_id = request.request_id.clone();
    let (after_event_id, scope, max_in_flight, heartbeat_ms) = match request.method {
        RequestMethod::OpenEventStream {
            after_event_id,
            scope,
            max_in_flight,
            heartbeat_ms,
        } => (after_event_id, scope, max_in_flight, heartbeat_ms),
        _ => {
            return (
                ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Err(ProtocolError::new(
                        "invalid_event_stream_request",
                        "not an event stream open request",
                    )),
                },
                None,
            );
        }
    };
    let authenticated = auth
        .lock()
        .expect("Agent auth mutex")
        .accepts(request.token.as_deref());
    if request.protocol_version != PROTOCOL_VERSION {
        return (
            ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "protocol_version_mismatch",
                    "unsupported protocol version",
                )),
            },
            None,
        );
    }
    if !authenticated {
        return (
            ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
            },
            None,
        );
    }
    if scope
        .as_ref()
        .and_then(|scope| scope.host_id.as_deref())
        .is_some_and(|host_id| host_id != host_identity().host_id)
    {
        return (
            ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "scope_denied",
                    "requested host is not this Agent",
                )),
            },
            None,
        );
    }
    let stream_id = new_id("event-stream");
    let max_in_flight = max_in_flight.clamp(1, 64);
    let heartbeat_ms = heartbeat_ms.clamp(250, 30_000);
    let config = EventStreamConfig {
        stream_id: stream_id.clone(),
        after_event_id,
        scope,
        max_in_flight,
        heartbeat: StdDuration::from_millis(heartbeat_ms),
    };
    (
        ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Ok(ResponsePayload::EventStreamOpened {
                stream_id,
                max_in_flight,
                heartbeat_ms,
            }),
        },
        Some(config),
    )
}

async fn serve_event_stream<R, W>(
    lines: &mut tokio::io::Lines<BufReader<R>>,
    writer: &mut W,
    auth: &Arc<Mutex<AgentAuth>>,
    state_dir: &Path,
    config: EventStreamConfig,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut cursor = config.after_event_id.clone();
    let mut in_flight = HashSet::new();
    let mut sent_ids = HashSet::new();
    let mut ticks = interval(StdDuration::from_millis(100));
    let mut last_heartbeat = Instant::now();

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()); };
                let request: RequestEnvelope = match serde_json::from_str(&line) {
                    Ok(request) => request,
                    Err(error) => {
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id: "unknown".into(),
                            result: Err(ProtocolError::new("invalid_json", error.to_string())),
                        }).await?;
                        continue;
                    }
                };
                let request_id = request.request_id.clone();
                let authenticated = auth
                    .lock()
                    .expect("Agent auth mutex")
                    .accepts(request.token.as_deref());
                if request.protocol_version != PROTOCOL_VERSION {
                    write_response(writer, ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new("protocol_version_mismatch", "unsupported protocol version")),
                    }).await?;
                    continue;
                }
                if !authenticated {
                    write_response(writer, ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
                    }).await?;
                    continue;
                }
                match request.method {
                    RequestMethod::AckEvents { event_ids } => {
                        let allowed = event_ids
                            .into_iter()
                            .filter(|event_id| in_flight.contains(event_id))
                            .collect::<Vec<_>>();
                        let removed = acknowledge_runtime_events(state_dir, &allowed)?;
                        for event_id in allowed {
                            in_flight.remove(&event_id);
                        }
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Ok(ResponsePayload::RuntimeEventsAcked(removed)),
                        }).await?;
                    }
                    RequestMethod::CloseEventStream { stream_id } if stream_id == config.stream_id => {
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Ok(ResponsePayload::EventStreamClosed {
                                stream_id: config.stream_id.clone(),
                                reason: "client_closed".into(),
                            }),
                        }).await?;
                        return Ok(());
                    }
                    RequestMethod::Shutdown => {
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Ok(ResponsePayload::ShutdownAck),
                        }).await?;
                        return Ok(());
                    }
                    _ => {
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Err(ProtocolError::new(
                                "event_stream_request_not_supported",
                                "only AckEvents, CloseEventStream and Shutdown are accepted on an event stream",
                            )),
                        }).await?;
                    }
                }
            }
            _ = ticks.tick() => {
                let available = config.max_in_flight.saturating_sub(in_flight.len());
                let mut emitted = false;
                if available > 0 {
                    let events = runtime_event_stream_page(
                        state_dir,
                        cursor.as_deref(),
                        config.scope.as_ref(),
                        &sent_ids,
                        available,
                    )?;
                    if !events.is_empty() {
                        let next_event_id = events.last().map(|event| event.event_id.clone());
                        for event in &events {
                            in_flight.insert(event.event_id.clone());
                            sent_ids.insert(event.event_id.clone());
                        }
                        cursor = next_event_id.clone();
                        write_response(writer, ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id: new_id("event-stream-page"),
                            result: Ok(ResponsePayload::EventStreamPage {
                                stream_id: config.stream_id.clone(),
                                events,
                                next_event_id,
                                heartbeat: false,
                            }),
                        }).await?;
                        last_heartbeat = Instant::now();
                        emitted = true;
                    }
                }
                if !emitted && last_heartbeat.elapsed() >= config.heartbeat {
                    write_response(writer, ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id: new_id("event-stream-heartbeat"),
                        result: Ok(ResponsePayload::EventStreamPage {
                            stream_id: config.stream_id.clone(),
                            events: Vec::new(),
                            next_event_id: cursor.clone(),
                            heartbeat: true,
                        }),
                    }).await?;
                    last_heartbeat = Instant::now();
                }
            }
        }
    }
}

fn runtime_event_stream_page(
    state_dir: &Path,
    after_event_id: Option<&str>,
    scope: Option<&amcp_domain::Scope>,
    sent_ids: &HashSet<String>,
    limit: usize,
) -> Result<Vec<RuntimeEvent>> {
    let events = load_runtime_event_outbox(state_dir)?;
    let start = after_event_id
        .and_then(|event_id| {
            events
                .iter()
                .position(|event| event.event_id == event_id)
                .map(|position| position + 1)
        })
        .unwrap_or(0);
    Ok(events
        .into_iter()
        .skip(start)
        .filter(|event| !sent_ids.contains(&event.event_id) && event_matches_scope(event, scope))
        .take(limit.clamp(1, 64))
        .collect())
}

fn event_matches_scope(event: &RuntimeEvent, scope: Option<&amcp_domain::Scope>) -> bool {
    let Some(scope) = scope else { return true };
    if scope
        .host_id
        .as_deref()
        .is_some_and(|host_id| host_id != event.host_id)
        || scope
            .provider_id
            .as_deref()
            .is_some_and(|provider_id| provider_id != event.provider_id)
    {
        return false;
    }
    scope.project_id.as_deref().is_none_or(|project_id| {
        serde_json::from_str::<serde_json::Value>(&event.payload_json)
            .ok()
            .and_then(|payload| {
                payload
                    .get("project_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .is_some_and(|event_project_id| event_project_id == project_id)
    })
}

fn process_request(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
    codex_home: Option<PathBuf>,
    backup_dir: &PathBuf,
    state_dir: &Path,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let request_token = request.token.clone();
    let is_enroll = matches!(&request.method, RequestMethod::Enroll { .. });
    let authenticated = {
        let guard = auth.lock().expect("Agent auth mutex");
        if is_enroll {
            guard.pairing_code.as_deref() == request.pairing_code.as_deref()
                && Utc::now() <= guard.pairing_expires_at
        } else {
            guard.accepts(request.token.as_deref())
        }
    };
    let response = if request.protocol_version != PROTOCOL_VERSION {
        Err(ProtocolError::new(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ))
    } else if !authenticated {
        Err(ProtocolError::new("unauthorized", "invalid Agent token"))
    } else {
        match request.method {
            RequestMethod::Register { .. } => Ok(ResponsePayload::Registered {
                agent_id: host_identity().host_id,
                host: host_identity(),
            }),
            RequestMethod::Enroll { .. } => {
                let mut guard = auth.lock().expect("Agent auth mutex");
                let credential = new_id("agent-credential");
                let expires_at = Utc::now() + Duration::days(365);
                guard.enrolled_credential = Some(credential.clone());
                guard.credential_expires_at = Some(expires_at);
                guard.pairing_code = None;
                match persist_enrolled_credential(&credential) {
                    Ok(()) => Ok(ResponsePayload::Enrolled {
                        agent_id: host_identity().host_id,
                        host: host_identity(),
                        credential,
                        expires_at: expires_at.to_rfc3339(),
                    }),
                    Err(error) => Err(ProtocolError::new(
                        "credential_store_failed",
                        error.to_string(),
                    )),
                }
            }
            RequestMethod::Heartbeat => Ok(ResponsePayload::Heartbeat {
                healthy: true,
                host_id: host_identity().host_id,
                timestamp: Utc::now().to_rfc3339(),
            }),
            RequestMethod::Capabilities => {
                let descriptors = provider_registry(codex_home.clone()).descriptors();
                Ok(ResponsePayload::Capabilities {
                    platform: host_identity().platform,
                    providers: descriptors
                        .iter()
                        .map(|provider| provider.id.clone())
                        .collect(),
                    capabilities: descriptors
                        .iter()
                        .flat_map(|provider| provider.capabilities.clone())
                        .collect(),
                    provider_descriptors: descriptors,
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                })
            }
            RequestMethod::Collect { scope, cursor } => {
                if let Some(scope) = &scope {
                    if scope.host_id.as_deref() != Some(host_identity().host_id.as_str()) {
                        return ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Err(ProtocolError::new(
                                "scope_denied",
                                "requested host is not this Agent",
                            )),
                        };
                    }
                }
                let provider_id = scope
                    .as_ref()
                    .and_then(|scope| scope.provider_id.as_deref())
                    .unwrap_or("codex");
                let registry = provider_registry(codex_home);
                let provider = match registry.get(provider_id) {
                    Ok(provider) => provider,
                    Err(error) => {
                        return ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Err(ProtocolError::new(
                                "provider_unavailable",
                                error.to_string(),
                            )),
                        };
                    }
                };
                let current_cursor = provider.collection_cursor();
                if current_cursor.is_some() && current_cursor.as_deref() == cursor.as_deref() {
                    if let Ok(Some(mut batch)) = load_collection_cache(state_dir, provider_id) {
                        batch.next_cursor = current_cursor.clone();
                        return ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Ok(ResponsePayload::Collection(batch)),
                        };
                    }
                }
                match provider.discover(host_identity()) {
                    Ok(mut batch) => {
                        batch.next_cursor = current_cursor;
                        let _ = save_collection_cache(state_dir, provider_id, &batch);
                        let _ = append_collection_outbox(state_dir, provider_id, &batch);
                        match append_runtime_event_outbox(state_dir, &batch.runtime_events) {
                            Ok(()) => Ok(ResponsePayload::Collection(batch)),
                            Err(error) => {
                                Err(ProtocolError::new("event_outbox_failed", error.to_string()))
                            }
                        }
                    }
                    Err(error) => match load_collection_cache(state_dir, provider_id) {
                        Ok(Some(batch)) => Ok(ResponsePayload::Collection(batch)),
                        _ => Err(ProtocolError::new("collection_failed", error.to_string())),
                    },
                }
            }
            RequestMethod::ReplayCollection { provider_id, limit } => {
                match load_collection_outbox(state_dir, &provider_id) {
                    Ok(batches) => Ok(ResponsePayload::CollectionReplay {
                        provider_id,
                        batches: batches.into_iter().rev().take(limit.clamp(1, 32)).collect(),
                    }),
                    Err(error) => Err(ProtocolError::new("replay_failed", error.to_string())),
                }
            }
            RequestMethod::ReplayEvents {
                after_event_id,
                limit,
            } => match load_runtime_event_outbox(state_dir) {
                Ok(events) => {
                    let start = after_event_id
                        .as_deref()
                        .and_then(|event_id| {
                            events
                                .iter()
                                .position(|event| event.event_id == event_id)
                                .map(|position| position + 1)
                        })
                        .unwrap_or(0);
                    Ok(ResponsePayload::RuntimeEvents(
                        events
                            .into_iter()
                            .skip(start)
                            .take(limit.clamp(1, 256))
                            .collect(),
                    ))
                }
                Err(error) => Err(ProtocolError::new("event_replay_failed", error.to_string())),
            },
            RequestMethod::SubscribeEvents {
                after_event_id,
                limit,
                wait_ms: _,
            } => match runtime_event_page(state_dir, after_event_id.as_deref(), limit) {
                Ok((events, next_event_id)) => Ok(ResponsePayload::RuntimeEventPage {
                    events,
                    next_event_id,
                    timed_out: false,
                }),
                Err(error) => Err(ProtocolError::new(
                    "event_subscribe_failed",
                    error.to_string(),
                )),
            },
            RequestMethod::RuntimeListThreads { .. }
            | RequestMethod::RuntimeReadThread { .. }
            | RequestMethod::RuntimeProposeThreadChange { .. }
            | RequestMethod::RuntimeApplyThreadChange { .. }
            | RequestMethod::OpenEventStream { .. }
            | RequestMethod::CloseEventStream { .. } => Err(ProtocolError::new(
                "runtime_request_requires_async_handler",
                "runtime thread requests must use the Agent async handler",
            )),
            RequestMethod::AckEvents { event_ids } => {
                match acknowledge_runtime_events(state_dir, &event_ids) {
                    Ok(removed) => Ok(ResponsePayload::RuntimeEventsAcked(removed)),
                    Err(error) => Err(ProtocolError::new("event_ack_failed", error.to_string())),
                }
            }
            RequestMethod::ReadArtifact {
                target,
                redacted: _,
            } => {
                let host = host_identity();
                match provider_registry(codex_home)
                    .get(&target.provider_id)
                    .and_then(|provider| provider.read_artifact(&target, &host))
                {
                    Ok(artifact) => Ok(ResponsePayload::Artifact(artifact)),
                    Err(error) => Err(ProtocolError::new("read_denied", error.to_string())),
                }
            }
            RequestMethod::ProposeChange { request } => {
                if request.target.host_id != host_identity().host_id {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "scope_denied",
                            "requested change is not for this Agent host",
                        )),
                    };
                }
                match provider_registry(codex_home)
                    .get(&request.target.provider_id)
                    .and_then(|provider| provider.propose_change(&request))
                {
                    Ok(change_set) => Ok(ResponsePayload::ChangeSet(change_set)),
                    Err(error) => Err(ProtocolError::new("proposal_denied", error.to_string())),
                }
            }
            RequestMethod::ApplyChange {
                change_set,
                approval,
            } => {
                if change_set.scope.host_id.as_deref() != Some(host_identity().host_id.as_str()) {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "scope_denied",
                            "requested change is not for this Agent host",
                        )),
                    };
                }
                let operations_hash = change_set_operations_hash(&change_set);
                let approval_valid = match consume_approval(
                    auth,
                    state_dir,
                    &approval,
                    request_token.as_deref().unwrap_or_default(),
                    &change_set.change_set_id,
                    &operations_hash,
                ) {
                    Ok(valid) => valid,
                    Err(error) => {
                        return ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Err(ProtocolError::new(
                                "approval_replay_store_failed",
                                error.to_string(),
                            )),
                        };
                    }
                };
                if !approval_valid
                    || approval.change_set_id != change_set.change_set_id
                    || approval.operations_hash != operations_hash
                {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "approval_invalid",
                            "approval envelope is invalid, expired, or not bound to change set",
                        )),
                    };
                }
                match provider_registry(codex_home)
                    .get(&change_set.provider_id)
                    .and_then(|provider| provider.apply_change(&change_set, backup_dir))
                {
                    Ok(receipt) => Ok(ResponsePayload::ChangeReceipt(receipt)),
                    Err(error) => Err(ProtocolError::new("apply_failed", error.to_string())),
                }
            }
            RequestMethod::Rollback {
                change_set,
                approval,
            } => {
                if change_set.scope.host_id.as_deref() != Some(host_identity().host_id.as_str()) {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "scope_denied",
                            "requested rollback is not for this Agent host",
                        )),
                    };
                }
                let operations_hash = change_set_operations_hash(&change_set);
                let approval_valid = match consume_approval(
                    auth,
                    state_dir,
                    &approval,
                    request_token.as_deref().unwrap_or_default(),
                    &change_set.change_set_id,
                    &operations_hash,
                ) {
                    Ok(valid) => valid,
                    Err(error) => {
                        return ResponseEnvelope {
                            protocol_version: PROTOCOL_VERSION,
                            request_id,
                            result: Err(ProtocolError::new(
                                "approval_replay_store_failed",
                                error.to_string(),
                            )),
                        };
                    }
                };
                if !approval_valid
                    || approval.change_set_id != change_set.change_set_id
                    || approval.operations_hash != operations_hash
                {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "approval_invalid",
                            "rollback approval envelope is invalid or not bound to change set",
                        )),
                    };
                }
                match provider_registry(codex_home)
                    .get(&change_set.provider_id)
                    .and_then(|provider| provider.rollback_change(&change_set, backup_dir))
                {
                    Ok(receipt) => Ok(ResponsePayload::ChangeReceipt(receipt)),
                    Err(error) => Err(ProtocolError::new("rollback_failed", error.to_string())),
                }
            }
            RequestMethod::Shutdown => Ok(ResponsePayload::ShutdownAck),
        }
    };
    ResponseEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        result: response,
    }
}

async fn process_subscribe_request(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
    state_dir: &Path,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let (after_event_id, limit, wait_ms) = match request.method {
        RequestMethod::SubscribeEvents {
            after_event_id,
            limit,
            wait_ms,
        } => (after_event_id, limit, wait_ms.min(30_000)),
        _ => {
            return ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "invalid_subscription",
                    "not an event subscription",
                )),
            };
        }
    };
    let authenticated = auth
        .lock()
        .expect("Agent auth mutex")
        .accepts(request.token.as_deref());
    if request.protocol_version != PROTOCOL_VERSION {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "protocol_version_mismatch",
                "unsupported protocol version",
            )),
        };
    }
    if !authenticated {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
        };
    }
    let deadline = Instant::now() + std::time::Duration::from_millis(wait_ms);
    loop {
        match runtime_event_page(state_dir, after_event_id.as_deref(), limit) {
            Ok((events, next_event_id)) if !events.is_empty() || Instant::now() >= deadline => {
                return ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Ok(ResponsePayload::RuntimeEventPage {
                        timed_out: events.is_empty() && wait_ms > 0,
                        events,
                        next_event_id,
                    }),
                };
            }
            Ok(_) => sleep(std::time::Duration::from_millis(50)).await,
            Err(error) => {
                return ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Err(ProtocolError::new(
                        "event_subscribe_failed",
                        error.to_string(),
                    )),
                };
            }
        }
    }
}

async fn process_runtime_list_request(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
    codex_home: Option<PathBuf>,
    codex_bin: &Path,
    runtime_cwd: Option<&Path>,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let (provider_id, scope, cursor, limit) = match request.method {
        RequestMethod::RuntimeListThreads {
            provider_id,
            scope,
            cursor,
            limit,
        } => (provider_id, scope, cursor, limit.clamp(1, 64)),
        _ => {
            return ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "invalid_runtime_request",
                    "not a runtime thread request",
                )),
            };
        }
    };
    let authenticated = auth
        .lock()
        .expect("Agent auth mutex")
        .accepts(request.token.as_deref());
    if request.protocol_version != PROTOCOL_VERSION {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "protocol_version_mismatch",
                "unsupported protocol version",
            )),
        };
    }
    if !authenticated {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
        };
    }
    if scope
        .as_ref()
        .and_then(|scope| scope.host_id.as_deref())
        .is_some_and(|host_id| host_id != host_identity().host_id)
    {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "scope_denied",
                "requested host is not this Agent",
            )),
        };
    }
    if scope
        .as_ref()
        .and_then(|scope| scope.provider_id.as_deref())
        .is_some_and(|scope_provider_id| scope_provider_id != provider_id)
    {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "scope_denied",
                "requested provider does not match the runtime provider",
            )),
        };
    }
    let registry = provider_registry(codex_home.clone());
    let provider = match registry.get(&provider_id) {
        Ok(provider) if runtime_provider_supports(provider, "list") => provider,
        _ => {
            return ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "runtime_unavailable",
                    "provider does not expose runtime capability",
                )),
            };
        }
    };
    let result = async {
        let mut client = AppServerClient::spawn(codex_bin, codex_home.as_deref(), runtime_cwd)
            .await
            .context("start Codex app-server for runtime read")?;
        client
            .initialize("amcp-agent-runtime-read", env!("CARGO_PKG_VERSION"))
            .await
            .context("initialize Codex app-server for runtime read")?;
        let response = client
            .list_threads(cursor.as_deref(), Some(limit as u32))
            .await
            .context("list Codex runtime threads")?;
        let host = host_identity();
        let mut threads = Vec::new();
        for thread in extract_thread_values(&response) {
            if let Some(record) = provider.map_runtime_thread_record(&host, &thread)? {
                threads.push(record);
            }
        }
        let next_cursor = extract_next_thread_cursor(&response);
        let _ = client.shutdown().await;
        Ok::<_, anyhow::Error>((threads, next_cursor))
    }
    .await;
    match result {
        Ok((threads, next_cursor)) => ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Ok(ResponsePayload::RuntimeThreadPage {
                provider_id,
                threads,
                next_cursor,
            }),
        },
        Err(error) => ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("runtime_read_failed", error.to_string())),
        },
    }
}

async fn process_runtime_read_request(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
    codex_home: Option<PathBuf>,
    codex_bin: &Path,
    runtime_cwd: Option<&Path>,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let (provider_id, scope, thread_id) = match request.method {
        RequestMethod::RuntimeReadThread {
            provider_id,
            scope,
            thread_id,
        } => (provider_id, scope, thread_id),
        _ => {
            return ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "invalid_runtime_request",
                    "not a runtime thread read request",
                )),
            };
        }
    };
    let authenticated = auth
        .lock()
        .expect("Agent auth mutex")
        .accepts(request.token.as_deref());
    if request.protocol_version != PROTOCOL_VERSION {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "protocol_version_mismatch",
                "unsupported protocol version",
            )),
        };
    }
    if !authenticated {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
        };
    }
    if thread_id.trim().is_empty() || thread_id.len() > 512 {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "invalid_runtime_request",
                "thread id must be non-empty and bounded",
            )),
        };
    }
    if scope
        .as_ref()
        .and_then(|scope| scope.host_id.as_deref())
        .is_some_and(|host_id| host_id != host_identity().host_id)
    {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "scope_denied",
                "requested host is not this Agent",
            )),
        };
    }
    if scope
        .as_ref()
        .and_then(|scope| scope.provider_id.as_deref())
        .is_some_and(|scope_provider_id| scope_provider_id != provider_id)
    {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "scope_denied",
                "requested provider does not match the runtime provider",
            )),
        };
    }
    let registry = provider_registry(codex_home.clone());
    let provider = match registry.get(&provider_id) {
        Ok(provider) if runtime_provider_supports(provider, "read") => provider,
        _ => {
            return ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                result: Err(ProtocolError::new(
                    "runtime_unavailable",
                    "provider does not expose runtime capability",
                )),
            };
        }
    };
    let result = async {
        let mut client = AppServerClient::spawn(codex_bin, codex_home.as_deref(), runtime_cwd)
            .await
            .context("start Codex app-server for runtime thread read")?;
        client
            .initialize("amcp-agent-runtime-thread-read", env!("CARGO_PKG_VERSION"))
            .await
            .context("initialize Codex app-server for runtime thread read")?;
        let response = client
            .read_thread(&thread_id)
            .await
            .context("read Codex runtime thread")?;
        let thread = extract_runtime_thread_value(&response)
            .context("Codex runtime read returned no thread metadata")?;
        let host = host_identity();
        let thread = provider
            .map_runtime_thread_record(&host, &thread)?
            .context("Codex runtime read returned an unmappable thread")?;
        let (item_count, item_kinds, item_roles) = summarize_runtime_items(&response);
        let _ = client.shutdown().await;
        Ok::<_, anyhow::Error>(RuntimeThreadSnapshot {
            thread,
            item_count,
            item_kinds,
            item_roles,
        })
    }
    .await;
    match result {
        Ok(snapshot) => ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Ok(ResponsePayload::RuntimeThreadSnapshot(snapshot)),
        },
        Err(error) => ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("runtime_read_failed", error.to_string())),
        },
    }
}

async fn process_runtime_change_request(
    request: RequestEnvelope,
    auth: &Arc<Mutex<AgentAuth>>,
    codex_home: Option<PathBuf>,
    codex_bin: &Path,
    runtime_cwd: Option<&Path>,
    state_dir: &Path,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let request_token = request.token.clone();
    let authenticated = auth
        .lock()
        .expect("Agent auth mutex")
        .accepts(request.token.as_deref());
    if request.protocol_version != PROTOCOL_VERSION {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "protocol_version_mismatch",
                "unsupported protocol version",
            )),
        };
    }
    if !authenticated {
        return ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new("unauthorized", "invalid Agent token")),
        };
    }
    match request.method {
        RequestMethod::RuntimeProposeThreadChange { request } => {
            let (thread_id, desired_archived) = match runtime_change_parts(
                &request.scope,
                &request.target,
                &request.operation,
                &host_identity().host_id,
            ) {
                Ok(parts) => parts,
                Err(error) => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "runtime_change_denied",
                            error.to_string(),
                        )),
                    };
                }
            };
            let registry = provider_registry(codex_home.clone());
            let provider = match registry.get(&request.target.provider_id) {
                Ok(provider)
                    if runtime_provider_supports(
                        provider,
                        runtime_operation_name(&request.operation),
                    ) =>
                {
                    provider
                }
                _ => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "runtime_unavailable",
                            "provider does not expose runtime capability",
                        )),
                    };
                }
            };
            let result = async {
                let mut client =
                    AppServerClient::spawn(codex_bin, codex_home.as_deref(), runtime_cwd)
                        .await
                        .context("start Codex app-server for runtime change proposal")?;
                client
                    .initialize(
                        "amcp-agent-runtime-change-proposal",
                        env!("CARGO_PKG_VERSION"),
                    )
                    .await
                    .context("initialize Codex app-server for runtime change proposal")?;
                let response = client.read_thread(&thread_id).await?;
                let thread = extract_runtime_thread_value(&response)
                    .context("Codex runtime read returned no thread metadata")?;
                let record = provider
                    .map_runtime_thread_record(&host_identity(), &thread)?
                    .context("Codex runtime read returned an unmappable thread")?;
                let before_hash = runtime_thread_state_hash(record.archived);
                if let Some(expected) = &request.expected_source_hash
                    && expected != &before_hash
                {
                    anyhow::bail!(
                        "runtime state conflict: expected {expected}, found {before_hash}"
                    );
                }
                if record.archived == desired_archived {
                    anyhow::bail!("runtime thread is already in the requested archive state");
                }
                let _ = client.shutdown().await;
                let now = Utc::now();
                Ok::<_, anyhow::Error>(ChangeSet {
                    change_set_id: new_id("change"),
                    actor: request.actor.clone(),
                    scope: request.scope.clone(),
                    provider_id: request.target.provider_id.clone(),
                    reason: request.reason.clone(),
                    evidence_ids: request.evidence_ids.clone(),
                    status: ChangeStatus::Proposed,
                    created_at: now,
                    updated_at: now,
                    operations: vec![ChangeOperation {
                        operation_id: new_id("op"),
                        target: request.target.clone(),
                        operation: request.operation.clone(),
                        expected_source_hash: Some(before_hash.clone()),
                        before_hash: Some(before_hash),
                        after_hash: Some(runtime_thread_state_hash(desired_archived)),
                        replacement_content: None,
                        diff: format!(
                            "Codex runtime thread {thread_id}: {} -> {}",
                            if record.archived {
                                "archived"
                            } else {
                                "active"
                            },
                            if desired_archived {
                                "archived"
                            } else {
                                "active"
                            }
                        ),
                    }],
                })
            }
            .await;
            match result {
                Ok(change_set) => ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Ok(ResponsePayload::ChangeSet(change_set)),
                },
                Err(error) => ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Err(ProtocolError::new(
                        "runtime_change_proposal_failed",
                        error.to_string(),
                    )),
                },
            }
        }
        RequestMethod::RuntimeApplyThreadChange {
            change_set,
            approval,
        } => {
            let operation = match change_set.operations.as_slice() {
                [operation] => operation,
                _ => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "runtime_change_denied",
                            "runtime change must contain exactly one operation",
                        )),
                    };
                }
            };
            let (thread_id, desired_archived) = match runtime_change_parts(
                &change_set.scope,
                &operation.target,
                &operation.operation,
                &host_identity().host_id,
            ) {
                Ok(parts) => parts,
                Err(error) => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "runtime_change_denied",
                            error.to_string(),
                        )),
                    };
                }
            };
            let operations_hash = change_set_operations_hash(&change_set);
            let approval_valid = match consume_approval(
                auth,
                state_dir,
                &approval,
                request_token.as_deref().unwrap_or_default(),
                &change_set.change_set_id,
                &operations_hash,
            ) {
                Ok(valid) => valid,
                Err(error) => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "approval_replay_store_failed",
                            error.to_string(),
                        )),
                    };
                }
            };
            if !approval_valid
                || approval.change_set_id != change_set.change_set_id
                || approval.operations_hash != operations_hash
            {
                return ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Err(ProtocolError::new(
                        "approval_invalid",
                        "approval envelope is invalid, expired, or not bound to runtime change",
                    )),
                };
            }
            let registry = provider_registry(codex_home.clone());
            let provider = match registry.get(&change_set.provider_id) {
                Ok(provider)
                    if runtime_provider_supports(
                        provider,
                        runtime_operation_name(&operation.operation),
                    ) =>
                {
                    provider
                }
                _ => {
                    return ResponseEnvelope {
                        protocol_version: PROTOCOL_VERSION,
                        request_id,
                        result: Err(ProtocolError::new(
                            "runtime_unavailable",
                            "provider does not expose runtime capability",
                        )),
                    };
                }
            };
            let result = async {
                let mut client =
                    AppServerClient::spawn(codex_bin, codex_home.as_deref(), runtime_cwd)
                        .await
                        .context("start Codex app-server for runtime change")?;
                client
                    .initialize("amcp-agent-runtime-change", env!("CARGO_PKG_VERSION"))
                    .await
                    .context("initialize Codex app-server for runtime change")?;
                let before_response = client.read_thread(&thread_id).await?;
                let before_thread = extract_runtime_thread_value(&before_response)
                    .context("Codex runtime read returned no thread metadata")?;
                let before = provider
                    .map_runtime_thread_record(&host_identity(), &before_thread)?
                    .context("Codex runtime read returned an unmappable thread")?;
                let before_hash = runtime_thread_state_hash(before.archived);
                if operation.expected_source_hash.as_deref() != Some(before_hash.as_str()) {
                    let _ = client.shutdown().await;
                    return Ok::<_, anyhow::Error>(ChangeReceipt {
                        change_set_id: change_set.change_set_id.clone(),
                        status: ChangeStatus::Conflict,
                        applied_at: Utc::now(),
                        backup_references: Vec::new(),
                        before_hashes: vec![before_hash],
                        after_hashes: Vec::new(),
                        message: "runtime thread state changed before apply".into(),
                    });
                }
                if before.archived == desired_archived {
                    let _ = client.shutdown().await;
                    return Ok::<_, anyhow::Error>(ChangeReceipt {
                        change_set_id: change_set.change_set_id.clone(),
                        status: ChangeStatus::Conflict,
                        applied_at: Utc::now(),
                        backup_references: Vec::new(),
                        before_hashes: vec![before_hash],
                        after_hashes: Vec::new(),
                        message: "runtime thread is already in the requested archive state".into(),
                    });
                }
                if desired_archived {
                    client.archive_thread(&thread_id).await?;
                } else {
                    client.unarchive_thread(&thread_id).await?;
                }
                let after_response = client.read_thread(&thread_id).await?;
                let after_thread = extract_runtime_thread_value(&after_response)
                    .context("Codex runtime read returned no thread metadata after apply")?;
                let after = provider
                    .map_runtime_thread_record(&host_identity(), &after_thread)?
                    .context("Codex runtime apply returned an unmappable thread")?;
                let after_hash = runtime_thread_state_hash(after.archived);
                let _ = client.shutdown().await;
                if after.archived != desired_archived
                    || operation.after_hash.as_deref() != Some(after_hash.as_str())
                {
                    anyhow::bail!("runtime thread post-apply state verification failed");
                }
                Ok::<_, anyhow::Error>(ChangeReceipt {
                    change_set_id: change_set.change_set_id.clone(),
                    status: ChangeStatus::Applied,
                    applied_at: Utc::now(),
                    backup_references: Vec::new(),
                    before_hashes: vec![before_hash],
                    after_hashes: vec![after_hash],
                    message: "runtime thread archive state applied and verified".into(),
                })
            }
            .await;
            match result {
                Ok(receipt) => ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Ok(ResponsePayload::ChangeReceipt(receipt)),
                },
                Err(error) => ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    result: Err(ProtocolError::new(
                        "runtime_change_apply_failed",
                        error.to_string(),
                    )),
                },
            }
        }
        _ => ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: Err(ProtocolError::new(
                "invalid_runtime_request",
                "not a runtime change request",
            )),
        },
    }
}

fn runtime_change_parts(
    scope: &amcp_domain::Scope,
    target: &ArtifactRef,
    operation: &ChangeOperationKind,
    host_id: &str,
) -> Result<(String, bool)> {
    if target.host_id != host_id || scope.host_id.as_deref() != Some(host_id) {
        anyhow::bail!("runtime mutation target is outside this Agent host");
    }
    if scope
        .provider_id
        .as_deref()
        .is_some_and(|provider_id| provider_id != target.provider_id)
    {
        anyhow::bail!("runtime mutation provider scope does not match target");
    }
    if target.native_id.trim().is_empty() || target.native_id.len() > 512 {
        anyhow::bail!("runtime thread id must be non-empty and bounded");
    }
    if target.source_reference != format!("{}://thread/{}", target.provider_id, target.native_id) {
        anyhow::bail!("runtime mutation source reference is invalid");
    }
    let desired_archived = match operation {
        ChangeOperationKind::RuntimeArchive => true,
        ChangeOperationKind::RuntimeUnarchive => false,
        _ => anyhow::bail!("change operation is not a runtime archive operation"),
    };
    Ok((target.native_id.clone(), desired_archived))
}

fn runtime_operation_name(operation: &ChangeOperationKind) -> &'static str {
    match operation {
        ChangeOperationKind::RuntimeArchive => "archive",
        ChangeOperationKind::RuntimeUnarchive => "unarchive",
        _ => "unsupported",
    }
}

fn runtime_provider_supports(provider: &dyn ProviderAdapter, operation: &str) -> bool {
    provider.runtime_descriptor().is_some_and(|descriptor| {
        descriptor.transport == "codex-app-server"
            && descriptor
                .operations
                .iter()
                .any(|candidate| candidate == operation)
    })
}

fn runtime_event_page(
    state_dir: &Path,
    after_event_id: Option<&str>,
    limit: usize,
) -> Result<(Vec<RuntimeEvent>, Option<String>)> {
    let events = load_runtime_event_outbox(state_dir)?;
    let start = after_event_id
        .and_then(|event_id| {
            events
                .iter()
                .position(|event| event.event_id == event_id)
                .map(|position| position + 1)
        })
        .unwrap_or(0);
    let events = events
        .into_iter()
        .skip(start)
        .take(limit.clamp(1, 256))
        .collect::<Vec<_>>();
    let next_event_id = events.last().map(|event| event.event_id.clone());
    Ok((events, next_event_id))
}

fn provider_registry(codex_home: Option<PathBuf>) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(CodexAdapter::from_environment(codex_home)));
    if env_flag("AMCP_ENABLE_FUTURE_PROVIDERS") {
        registry.register(Box::new(ClaudeCodeAdapter::claude_code_from_environment()));
        registry.register(Box::new(KiroAdapter::kiro_from_environment()));
        registry.register(Box::new(AntigravityAdapter::antigravity_from_environment()));
    }
    registry
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: ResponseEnvelope,
) -> Result<()> {
    let encoded = serde_json::to_string(&response)?;
    writer.write_all(encoded.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn host_identity() -> HostIdentity {
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());
    let host_id =
        env::var("AMCP_HOST_ID").unwrap_or_else(|_| format!("host_{}", hostname.replace('.', "-")));
    HostIdentity {
        host_id,
        display_name: hostname.clone(),
        platform: std::env::consts::OS.to_owned(),
        hostname,
    }
}

fn resolve_agent_token(token: &str) -> String {
    const DEVELOPMENT_TOKEN: &str = "amcp-development-token";
    if token != DEVELOPMENT_TOKEN {
        return token.to_owned();
    }
    let account = env::var("AMCP_AGENT_KEYCHAIN_ACCOUNT")
        .unwrap_or_else(|_| keychain_account_for_host(&host_identity().host_id));
    MacOsKeychain::new(account)
        .get()
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| token.to_owned())
}

fn persist_enrolled_credential(credential: &str) -> Result<()> {
    #[cfg(not(test))]
    {
        MacOsKeychain::new(keychain_account_for_host(&host_identity().host_id)).set(credential)?;
    }
    #[cfg(test)]
    {
        let _ = credential;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_enrolls_credential_and_allows_registered_session() {
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "bootstrap".into(),
            Some("12345678".into()),
            300,
        )));
        let enroll = RequestEnvelope::new(
            RequestMethod::Enroll {
                controller_id: "controller-test".into(),
            },
            None,
        )
        .with_pairing_code("12345678");
        let response = process_request(
            enroll,
            &auth,
            None,
            &PathBuf::from("/tmp"),
            Path::new("/tmp"),
        );
        let credential = match response.result.expect("enrollment should succeed") {
            ResponsePayload::Enrolled { credential, .. } => credential,
            other => panic!("unexpected response: {other:?}"),
        };
        let registered = RequestEnvelope::new(
            RequestMethod::Register {
                controller_id: "controller-test".into(),
            },
            Some(credential),
        );
        let response = process_request(
            registered,
            &auth,
            None,
            &PathBuf::from("/tmp"),
            Path::new("/tmp"),
        );
        assert!(matches!(
            response.result,
            Ok(ResponsePayload::Registered { .. })
        ));
    }

    #[test]
    fn invalid_pairing_code_is_rejected() {
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "bootstrap".into(),
            Some("12345678".into()),
            300,
        )));
        let request = RequestEnvelope::new(
            RequestMethod::Enroll {
                controller_id: "controller-test".into(),
            },
            None,
        )
        .with_pairing_code("wrong");
        let response = process_request(
            request,
            &auth,
            None,
            &PathBuf::from("/tmp"),
            Path::new("/tmp"),
        );
        assert_eq!(response.result.unwrap_err().code, "unauthorized");
    }

    #[test]
    fn redacted_collection_cache_round_trips() {
        let directory = tempfile::tempdir().expect("cache directory");
        let host = host_identity();
        let batch = CodexAdapter::from_environment(Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex"),
        ))
        .discover(host)
        .expect("fixture collection");
        save_collection_cache(directory.path(), "codex", &batch).expect("save cache");
        let restored = load_collection_cache(directory.path(), "codex")
            .expect("load cache")
            .expect("cached batch");
        assert_eq!(restored.artifacts.len(), batch.artifacts.len());
        assert!(restored.artifacts.iter().all(|artifact| {
            !artifact
                .content
                .contains("fixture-secret-must-not-be-indexed")
        }));
    }

    #[test]
    fn collection_outbox_is_bounded_and_deduplicates_runs() {
        let directory = tempfile::tempdir().expect("outbox directory");
        let host = host_identity();
        let batch = CodexAdapter::from_environment(Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex"),
        ))
        .discover(host)
        .expect("fixture collection");
        append_collection_outbox(directory.path(), "codex", &batch).expect("append batch");
        append_collection_outbox(directory.path(), "codex", &batch).expect("deduplicate batch");
        let mut second = batch.clone();
        second.collection_run_id = "second-run".into();
        append_collection_outbox(directory.path(), "codex", &second).expect("append second");
        let queued = load_collection_outbox(directory.path(), "codex").expect("load outbox");
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[1].collection_run_id, "second-run");
    }

    #[test]
    fn runtime_event_outbox_deduplicates_stable_event_ids() {
        let directory = tempfile::tempdir().expect("event outbox directory");
        let host = host_identity();
        let batch = CodexAdapter::from_environment(Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex"),
        ))
        .discover(host)
        .expect("fixture collection");
        append_runtime_event_outbox(directory.path(), &batch.runtime_events)
            .expect("append events");
        append_runtime_event_outbox(directory.path(), &batch.runtime_events)
            .expect("deduplicate events");
        let events = load_runtime_event_outbox(directory.path()).expect("load events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "inventory.completed");
    }

    #[test]
    fn runtime_event_outbox_acknowledges_only_requested_ids() {
        let directory = tempfile::tempdir().expect("event outbox directory");
        let host = host_identity();
        let mut batch = CodexAdapter::from_environment(Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex"),
        ))
        .discover(host)
        .expect("fixture collection");
        batch.runtime_events.push(RuntimeEvent {
            event_id: "event-keep".into(),
            host_id: "fixture-host".into(),
            provider_id: "codex".into(),
            event_type: "diagnostic.updated".into(),
            sequence: 2,
            payload_json: "{}".into(),
            occurred_at: Utc::now(),
        });
        append_runtime_event_outbox(directory.path(), &batch.runtime_events)
            .expect("append events");
        let removed = acknowledge_runtime_events(
            directory.path(),
            &[batch.runtime_events[0].event_id.clone()],
        )
        .expect("ack events");
        assert_eq!(removed, 1);
        let remaining = load_runtime_event_outbox(directory.path()).expect("load events");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].event_id, "event-keep");
    }

    #[tokio::test]
    async fn event_subscription_times_out_and_returns_bounded_pages() {
        let directory = tempfile::tempdir().expect("subscription directory");
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "subscription-token".into(),
            None,
            300,
        )));
        let empty = process_subscribe_request(
            RequestEnvelope::new(
                RequestMethod::SubscribeEvents {
                    after_event_id: None,
                    limit: 4,
                    wait_ms: 1,
                },
                Some("subscription-token".into()),
            ),
            &auth,
            directory.path(),
        )
        .await;
        assert!(matches!(
            empty.result,
            Ok(ResponsePayload::RuntimeEventPage {
                events,
                timed_out: true,
                ..
            }) if events.is_empty()
        ));
        append_runtime_event_outbox(
            directory.path(),
            &[RuntimeEvent {
                event_id: "event-subscribe".into(),
                host_id: "host-subscribe".into(),
                provider_id: "codex".into(),
                event_type: "source.changed".into(),
                sequence: 1,
                payload_json: "{}".into(),
                occurred_at: Utc::now(),
            }],
        )
        .expect("append subscription event");
        let page = process_subscribe_request(
            RequestEnvelope::new(
                RequestMethod::SubscribeEvents {
                    after_event_id: None,
                    limit: 1,
                    wait_ms: 0,
                },
                Some("subscription-token".into()),
            ),
            &auth,
            directory.path(),
        )
        .await;
        let next_event_id = match page.result.expect("subscription page") {
            ResponsePayload::RuntimeEventPage {
                events,
                next_event_id: Some(next_event_id),
                timed_out: false,
            } => {
                assert_eq!(events.len(), 1);
                next_event_id
            }
            other => panic!("unexpected subscription page: {other:?}"),
        };
        append_runtime_event_outbox(
            directory.path(),
            &[
                RuntimeEvent {
                    event_id: "event-subscribe-2".into(),
                    host_id: "host-subscribe".into(),
                    provider_id: "codex".into(),
                    event_type: "source.changed".into(),
                    sequence: 2,
                    payload_json: "{}".into(),
                    occurred_at: Utc::now(),
                },
                RuntimeEvent {
                    event_id: "event-subscribe-3".into(),
                    host_id: "host-subscribe".into(),
                    provider_id: "codex".into(),
                    event_type: "source.changed".into(),
                    sequence: 3,
                    payload_json: "{}".into(),
                    occurred_at: Utc::now(),
                },
            ],
        )
        .expect("append ordered subscription events");
        let continued = process_subscribe_request(
            RequestEnvelope::new(
                RequestMethod::SubscribeEvents {
                    after_event_id: Some(next_event_id),
                    limit: 2,
                    wait_ms: 0,
                },
                Some("subscription-token".into()),
            ),
            &auth,
            directory.path(),
        )
        .await;
        match continued.result.expect("continued subscription page") {
            ResponsePayload::RuntimeEventPage { events, .. } => {
                assert_eq!(events.len(), 2);
                assert_eq!(events[0].event_id, "event-subscribe-2");
                assert_eq!(events[1].event_id, "event-subscribe-3");
            }
            other => panic!("unexpected continued subscription page: {other:?}"),
        }
    }

    #[tokio::test]
    async fn event_stream_delivers_with_backpressure_and_ack() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().expect("stream directory");
        let host = host_identity();
        append_runtime_event_outbox(
            directory.path(),
            &[
                RuntimeEvent {
                    event_id: "stream-event-1".into(),
                    host_id: host.host_id.clone(),
                    provider_id: "codex".into(),
                    event_type: "session.updated".into(),
                    sequence: 1,
                    payload_json: serde_json::json!({"thread_id": "thread-1"}).to_string(),
                    occurred_at: Utc::now(),
                },
                RuntimeEvent {
                    event_id: "stream-event-2".into(),
                    host_id: host.host_id.clone(),
                    provider_id: "codex".into(),
                    event_type: "session.updated".into(),
                    sequence: 2,
                    payload_json: serde_json::json!({"thread_id": "thread-2"}).to_string(),
                    occurred_at: Utc::now(),
                },
            ],
        )
        .expect("append stream events");
        let auth = Arc::new(Mutex::new(AgentAuth::new("stream-token".into(), None, 300)));
        let (client, server) = tokio::io::duplex(16 * 1024);
        let server_auth = auth.clone();
        let server_directory = directory.path().to_path_buf();
        let server_task = tokio::spawn(async move {
            handle_connection(
                server,
                server_auth,
                None,
                PathBuf::from("codex"),
                None,
                PathBuf::from("/tmp/amcp-stream-backup"),
                server_directory,
            )
            .await
        });
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_lines = BufReader::new(client_read).lines();
        let open = RequestEnvelope::new(
            RequestMethod::OpenEventStream {
                after_event_id: None,
                scope: Some(amcp_domain::Scope {
                    host_id: Some(host.host_id),
                    provider_id: Some("codex".into()),
                    project_id: None,
                }),
                max_in_flight: 1,
                heartbeat_ms: 250,
            },
            Some("stream-token".into()),
        );
        let open_id = open.request_id.clone();
        client_write
            .write_all(format!("{}\n", serde_json::to_string(&open).unwrap()).as_bytes())
            .await
            .expect("write stream open");
        client_write.flush().await.expect("flush stream open");
        let opened: ResponseEnvelope = serde_json::from_str(
            &client_lines
                .next_line()
                .await
                .expect("read stream open")
                .expect("stream open response"),
        )
        .expect("decode stream open");
        assert_eq!(opened.request_id, open_id);
        let stream_id = match opened.result.expect("stream open should succeed") {
            ResponsePayload::EventStreamOpened {
                stream_id,
                max_in_flight: 1,
                ..
            } => stream_id,
            other => panic!("unexpected stream open response: {other:?}"),
        };
        let first: ResponseEnvelope = serde_json::from_str(
            &tokio::time::timeout(StdDuration::from_secs(2), client_lines.next_line())
                .await
                .expect("first event timeout")
                .expect("read first event")
                .expect("first event response"),
        )
        .expect("decode first event");
        match first.result.expect("first event should succeed") {
            ResponsePayload::EventStreamPage { events, .. } => {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].event_id, "stream-event-1");
            }
            other => panic!("unexpected first stream frame: {other:?}"),
        }
        let ack = RequestEnvelope::new(
            RequestMethod::AckEvents {
                event_ids: vec!["stream-event-1".into()],
            },
            Some("stream-token".into()),
        );
        let ack_id = ack.request_id.clone();
        client_write
            .write_all(format!("{}\n", serde_json::to_string(&ack).unwrap()).as_bytes())
            .await
            .expect("write stream ack");
        client_write.flush().await.expect("flush stream ack");
        let ack_response: ResponseEnvelope = serde_json::from_str(
            &client_lines
                .next_line()
                .await
                .expect("read stream ack")
                .expect("stream ack response"),
        )
        .expect("decode stream ack");
        assert_eq!(ack_response.request_id, ack_id);
        assert!(matches!(
            ack_response.result.expect("ack should succeed"),
            ResponsePayload::RuntimeEventsAcked(1)
        ));
        let second: ResponseEnvelope = serde_json::from_str(
            &tokio::time::timeout(StdDuration::from_secs(2), client_lines.next_line())
                .await
                .expect("second event timeout")
                .expect("read second event")
                .expect("second event response"),
        )
        .expect("decode second event");
        assert!(matches!(
            second.result.expect("second event should succeed"),
            ResponsePayload::EventStreamPage { events, .. }
                if events.len() == 1 && events[0].event_id == "stream-event-2"
        ));
        let close = RequestEnvelope::new(
            RequestMethod::CloseEventStream {
                stream_id: stream_id.clone(),
            },
            Some("stream-token".into()),
        );
        let close_id = close.request_id.clone();
        client_write
            .write_all(format!("{}\n", serde_json::to_string(&close).unwrap()).as_bytes())
            .await
            .expect("write stream close");
        client_write.flush().await.expect("flush stream close");
        let closed: ResponseEnvelope = serde_json::from_str(
            &client_lines
                .next_line()
                .await
                .expect("read stream close")
                .expect("stream close response"),
        )
        .expect("decode stream close");
        assert_eq!(closed.request_id, close_id);
        assert!(matches!(
            closed.result.expect("close should succeed"),
            ResponsePayload::EventStreamClosed { stream_id: id, .. } if id == stream_id
        ));
        server_task
            .await
            .expect("join stream server")
            .expect("stream server");
    }

    #[tokio::test]
    async fn runtime_thread_list_rejects_a_different_host_scope() {
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "runtime-token".into(),
            None,
            300,
        )));
        let response = process_runtime_list_request(
            RequestEnvelope::new(
                RequestMethod::RuntimeListThreads {
                    provider_id: "codex".into(),
                    scope: Some(amcp_domain::Scope::host("other-host")),
                    cursor: None,
                    limit: 10,
                },
                Some("runtime-token".into()),
            ),
            &auth,
            None,
            Path::new("/does/not/exist"),
            None,
        )
        .await;
        assert_eq!(response.result.unwrap_err().code, "scope_denied");
    }

    #[tokio::test]
    async fn runtime_thread_read_rejects_a_different_provider_scope() {
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "runtime-token".into(),
            None,
            300,
        )));
        let response = process_runtime_list_request(
            RequestEnvelope::new(
                RequestMethod::RuntimeListThreads {
                    provider_id: "codex".into(),
                    scope: Some(amcp_domain::Scope {
                        host_id: None,
                        provider_id: Some("claude-code".into()),
                        project_id: None,
                    }),
                    cursor: None,
                    limit: 10,
                },
                Some("runtime-token".into()),
            ),
            &auth,
            None,
            Path::new("/does/not/exist"),
            None,
        )
        .await;
        assert_eq!(response.result.unwrap_err().code, "scope_denied");
    }

    #[tokio::test]
    async fn runtime_thread_snapshot_read_rejects_a_different_host_scope() {
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "runtime-token".into(),
            None,
            300,
        )));
        let response = process_runtime_read_request(
            RequestEnvelope::new(
                RequestMethod::RuntimeReadThread {
                    provider_id: "codex".into(),
                    scope: Some(amcp_domain::Scope::host("other-host")),
                    thread_id: "thread-1".into(),
                },
                Some("runtime-token".into()),
            ),
            &auth,
            None,
            Path::new("/does/not/exist"),
            None,
        )
        .await;
        assert_eq!(response.result.unwrap_err().code, "scope_denied");
    }

    #[test]
    fn runtime_thread_read_summarizes_item_metadata_without_content() {
        let response = serde_json::json!({
            "thread": { "id": "thread-1" },
            "items": [
                { "type": "userMessage", "role": "user", "text": "secret transcript" },
                { "type": "agentMessage", "role": "assistant", "delta": "secret delta" },
                { "type": "agentMessage", "role": "assistant", "text": "secret answer" }
            ]
        });
        let (count, kinds, roles) = summarize_runtime_items(&response);
        assert_eq!(count, 3);
        assert_eq!(kinds, vec!["userMessage", "agentMessage"]);
        assert_eq!(roles, vec!["user", "assistant"]);
        let summary = serde_json::json!({
            "item_count": count,
            "item_kinds": kinds,
            "item_roles": roles,
        });
        let encoded = serde_json::to_string(&summary).expect("encode metadata summary");
        assert!(!encoded.contains("secret transcript"));
        assert!(!encoded.contains("secret delta"));
        assert!(!encoded.contains("secret answer"));
    }

    #[tokio::test]
    async fn runtime_archive_proposal_and_apply_use_approval_and_verify_state() {
        let directory = tempfile::tempdir().expect("runtime change directory");
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "runtime-token".into(),
            None,
            300,
        )));
        let host = host_identity();
        let request = RequestEnvelope::new(
            RequestMethod::RuntimeProposeThreadChange {
                request: amcp_domain::ChangeRequest {
                    actor: "test-human".into(),
                    scope: amcp_domain::Scope {
                        host_id: Some(host.host_id.clone()),
                        provider_id: Some("codex".into()),
                        project_id: None,
                    },
                    target: ArtifactRef {
                        host_id: host.host_id.clone(),
                        provider_id: "codex".into(),
                        native_id: "thread-fixture".into(),
                        source_reference: "codex://thread/thread-fixture".into(),
                    },
                    expected_source_hash: None,
                    operation: ChangeOperationKind::RuntimeArchive,
                    replacement_content: None,
                    reason: "archive completed fixture session".into(),
                    evidence_ids: Vec::new(),
                },
            },
            Some("runtime-token".into()),
        );
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/fake-codex-app-server.py");
        let response =
            process_runtime_change_request(request, &auth, None, &fixture, None, directory.path())
                .await;
        let change_set = match response.result.expect("proposal should succeed") {
            ResponsePayload::ChangeSet(change_set) => change_set,
            other => panic!("unexpected proposal response: {other:?}"),
        };
        assert!(matches!(
            change_set.operations[0].operation,
            ChangeOperationKind::RuntimeArchive
        ));
        assert!(!change_set.operations[0].diff.contains("secret"));
        let now = Utc::now();
        let approval = ApprovalEnvelope::issue(
            "runtime-token",
            change_set.change_set_id.clone(),
            "test-human",
            now,
            now + chrono::Duration::minutes(5),
            "runtime-approval-1",
            change_set_operations_hash(&change_set),
        );
        let response = process_runtime_change_request(
            RequestEnvelope::new(
                RequestMethod::RuntimeApplyThreadChange {
                    change_set,
                    approval,
                },
                Some("runtime-token".into()),
            ),
            &auth,
            None,
            &fixture,
            None,
            directory.path(),
        )
        .await;
        match response.result.expect("runtime apply should succeed") {
            ResponsePayload::ChangeReceipt(receipt) => {
                assert_eq!(receipt.status, ChangeStatus::Applied);
                assert!(receipt.backup_references.is_empty());
            }
            other => panic!("unexpected apply response: {other:?}"),
        }
    }

    #[test]
    fn runtime_connector_emits_redacted_metadata_only_session_events() {
        let host = HostIdentity {
            host_id: "host-runtime".into(),
            display_name: "Runtime host".into(),
            platform: "macos".into(),
            hostname: "runtime.local".into(),
        };
        let mut sequence = 0;
        let provider = CodexAdapter::from_environment(Some(PathBuf::from("/tmp/codex")));
        let event = provider
            .map_runtime_thread(
                &host,
                &serde_json::json!({
                    "id": "thread-1",
                    "title": "Safe title api_key=secret-value",
                    "cwd": "/work/project",
                    "model": "gpt-test",
                    "status": "idle",
                    "archived": false,
                    "delta": "must not be persisted"
                }),
                &mut sequence,
            )
            .expect("runtime event conversion")
            .expect("thread id");
        assert_eq!(event.event_type, "session.updated");
        assert_eq!(event.sequence, 1);
        assert!(event.payload_json.contains("metadata_only"));
        assert!(event.payload_json.contains("Safe title"));
        assert!(!event.payload_json.contains("secret-value"));
        assert!(!event.payload_json.contains("must not be persisted"));
    }

    #[test]
    fn runtime_connector_extracts_common_thread_list_shapes() {
        let response = serde_json::json!({
            "data": {
                "threads": [
                    { "id": "thread-1" },
                    { "id": "thread-2" }
                ],
                "nextCursor": "page-2"
            }
        });
        let threads = extract_thread_values(&response);
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[1]["id"], "thread-2");
        assert_eq!(
            extract_next_thread_cursor(&response).as_deref(),
            Some("page-2")
        );
    }

    #[test]
    fn approval_replay_store_allows_an_envelope_only_once() {
        let directory = tempfile::tempdir().expect("approval replay directory");
        let auth = Arc::new(Mutex::new(AgentAuth::new("bootstrap".into(), None, 300)));
        let now = Utc::now();
        let approval = ApprovalEnvelope::issue(
            "shared-secret",
            "change-test",
            "human",
            now,
            now + Duration::minutes(5),
            "idem-test",
            "operations-hash",
        );
        assert!(
            consume_approval(
                &auth,
                directory.path(),
                &approval,
                "shared-secret",
                "change-test",
                "operations-hash",
            )
            .expect("consume first approval")
        );
        assert!(
            !consume_approval(
                &auth,
                directory.path(),
                &approval,
                "shared-secret",
                "change-test",
                "operations-hash",
            )
            .expect("reject replayed approval")
        );
        assert_eq!(
            load_consumed_approvals(directory.path())
                .expect("load approval replay store")
                .len(),
            1
        );
    }

    #[test]
    fn apply_request_rejects_a_replayed_approval_envelope() {
        let directory = tempfile::tempdir().expect("approval replay directory");
        let host = host_identity();
        let auth = Arc::new(Mutex::new(AgentAuth::new(
            "shared-secret".into(),
            None,
            300,
        )));
        let now = Utc::now();
        let change_set = amcp_domain::ChangeSet {
            change_set_id: "change-replay-test".into(),
            actor: "human".into(),
            scope: amcp_domain::Scope::host(host.host_id.clone()),
            provider_id: "codex".into(),
            reason: "replay test".into(),
            evidence_ids: Vec::new(),
            status: amcp_domain::ChangeStatus::Proposed,
            created_at: now,
            updated_at: now,
            operations: Vec::new(),
        };
        let approval = ApprovalEnvelope::issue(
            "shared-secret",
            change_set.change_set_id.clone(),
            "human",
            now,
            now + Duration::minutes(5),
            "idem-replay-test",
            amcp_domain::change_set_operations_hash(&change_set),
        );
        let request = || {
            RequestEnvelope::new(
                RequestMethod::ApplyChange {
                    change_set: change_set.clone(),
                    approval: approval.clone(),
                },
                Some("shared-secret".into()),
            )
        };
        let first = process_request(
            request(),
            &auth,
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex")),
            &directory.path().join("backups"),
            directory.path(),
        );
        assert_eq!(first.result.unwrap_err().code, "apply_failed");
        let second = process_request(
            request(),
            &auth,
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex")),
            &directory.path().join("backups"),
            directory.path(),
        );
        assert_eq!(second.result.unwrap_err().code, "approval_invalid");
    }
}

fn default_backup_dir() -> PathBuf {
    env::var_os("AMCP_AGENT_BACKUP_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home).join("Library/Application Support/AMCP/agent-backups")
            })
        })
        .unwrap_or_else(|| PathBuf::from(".amcp/agent-backups"))
}

fn default_state_dir() -> PathBuf {
    env::var_os("AMCP_AGENT_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home).join("Library/Application Support/AMCP/agent-state")
            })
        })
        .unwrap_or_else(|| PathBuf::from(".amcp/agent-state"))
}

fn collection_cache_path(state_dir: &Path, provider_id: &str) -> PathBuf {
    state_dir.join(format!("collection-{provider_id}.json"))
}

fn collection_outbox_path(state_dir: &Path, provider_id: &str) -> PathBuf {
    state_dir.join(format!("collection-outbox-{provider_id}.json"))
}

fn runtime_event_outbox_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime-events-outbox.json")
}

fn approval_replay_path(state_dir: &Path) -> PathBuf {
    state_dir.join("approval-replay.json")
}

fn consume_approval(
    auth: &Arc<Mutex<AgentAuth>>,
    state_dir: &Path,
    approval: &ApprovalEnvelope,
    secret: &str,
    expected_change_set_id: &str,
    operations_hash: &str,
) -> Result<bool> {
    if approval.change_set_id.trim().is_empty()
        || approval.change_set_id != expected_change_set_id
        || approval.operations_hash != operations_hash
        || !approval.is_valid(secret, Utc::now())
    {
        return Ok(false);
    }
    let replay_key = format!("{}:{}", approval.approval_id, approval.nonce);
    let mut guard = auth.lock().expect("Agent auth mutex");
    if guard.consumed_approval_ids.contains(&replay_key) {
        return Ok(false);
    }
    let mut consumed = load_consumed_approvals(state_dir)?;
    if consumed.iter().any(|key| key == &replay_key) {
        guard.consumed_approval_ids.insert(replay_key);
        return Ok(false);
    }
    consumed.push(replay_key.clone());
    if consumed.len() > 4_096 {
        let keep_from = consumed.len() - 4_096;
        consumed.drain(..keep_from);
    }
    std::fs::create_dir_all(state_dir)?;
    let path = approval_replay_path(state_dir);
    let temporary = path.with_extension(format!("{}.tmp", new_id("approvals")));
    std::fs::write(&temporary, serde_json::to_vec(&consumed)?)?;
    std::fs::rename(temporary, path)?;
    guard.consumed_approval_ids = consumed.into_iter().collect();
    Ok(true)
}

fn load_consumed_approvals(state_dir: &Path) -> Result<Vec<String>> {
    match std::fs::read(approval_replay_path(state_dir)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn save_collection_cache(
    state_dir: &Path,
    provider_id: &str,
    batch: &amcp_domain::CollectionBatch,
) -> Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = collection_cache_path(state_dir, provider_id);
    let temporary = path.with_extension(format!("{}.tmp", new_id("cache")));
    std::fs::write(&temporary, serde_json::to_vec(batch)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn load_collection_cache(
    state_dir: &Path,
    provider_id: &str,
) -> Result<Option<amcp_domain::CollectionBatch>> {
    let path = collection_cache_path(state_dir, provider_id);
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn append_collection_outbox(
    state_dir: &Path,
    provider_id: &str,
    batch: &amcp_domain::CollectionBatch,
) -> Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = collection_outbox_path(state_dir, provider_id);
    let mut batches = load_collection_outbox(state_dir, provider_id)?;
    batches.retain(|queued| queued.collection_run_id != batch.collection_run_id);
    batches.push(batch.clone());
    if batches.len() > 8 {
        let keep_from = batches.len() - 8;
        batches.drain(..keep_from);
    }
    let temporary = path.with_extension(format!("{}.tmp", new_id("outbox")));
    std::fs::write(&temporary, serde_json::to_vec(&batches)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn load_collection_outbox(
    state_dir: &Path,
    provider_id: &str,
) -> Result<Vec<amcp_domain::CollectionBatch>> {
    match std::fs::read(collection_outbox_path(state_dir, provider_id)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn append_runtime_event_outbox(state_dir: &Path, events: &[RuntimeEvent]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let _lock = runtime_event_outbox_lock()
        .lock()
        .expect("event outbox mutex");
    std::fs::create_dir_all(state_dir)?;
    let path = runtime_event_outbox_path(state_dir);
    let mut queued = load_runtime_event_outbox(state_dir)?;
    for event in events {
        if !queued
            .iter()
            .any(|existing| existing.event_id == event.event_id)
        {
            queued.push(event.clone());
        }
    }
    if queued.len() > 256 {
        let keep_from = queued.len() - 256;
        queued.drain(..keep_from);
    }
    let temporary = path.with_extension(format!("{}.tmp", new_id("events")));
    std::fs::write(&temporary, serde_json::to_vec(&queued)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn load_runtime_event_outbox(state_dir: &Path) -> Result<Vec<RuntimeEvent>> {
    match std::fs::read(runtime_event_outbox_path(state_dir)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn acknowledge_runtime_events(state_dir: &Path, event_ids: &[String]) -> Result<usize> {
    if event_ids.is_empty() {
        return Ok(0);
    }
    let _lock = runtime_event_outbox_lock()
        .lock()
        .expect("event outbox mutex");
    let path = runtime_event_outbox_path(state_dir);
    let queued = load_runtime_event_outbox(state_dir)?;
    let before = queued.len();
    let acknowledged = queued
        .into_iter()
        .filter(|event| !event_ids.iter().any(|id| id == &event.event_id))
        .collect::<Vec<_>>();
    if acknowledged.len() == before {
        return Ok(0);
    }
    let temporary = path.with_extension(format!("{}.tmp", new_id("events")));
    std::fs::write(&temporary, serde_json::to_vec(&acknowledged)?)?;
    std::fs::rename(temporary, path)?;
    Ok(before - acknowledged.len())
}

fn runtime_event_outbox_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn load_server_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<ServerConfig> {
    let mut cert_reader = StdBufReader::new(File::open(cert_path)?);
    let certificates =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        anyhow::bail!("TLS certificate file contains no certificates");
    }
    let mut key_reader = StdBufReader::new(File::open(key_path)?);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .context("TLS key file contains no private key")?;
    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?)
}
