use amcp_codex::CodexAdapter;
use amcp_domain::change_set_operations_hash;
use amcp_domain::{HostIdentity, new_id};
use amcp_platform::{MacOsKeychain, SecretStore, keychain_account_for_host};
use amcp_protocol::{
    PROTOCOL_VERSION, ProtocolError, RequestEnvelope, RequestMethod, ResponseEnvelope,
    ResponsePayload,
};
use amcp_provider_api::ProviderRegistry;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use std::{
    env,
    fs::File,
    io::BufReader as StdBufReader,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixListener},
};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Parser)]
#[command(name = "amcp-agent", about = "AMCP local host Agent")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(
        long,
        default_value = "/tmp/amcp-agent.sock",
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
}

struct AgentAuth {
    bootstrap_token: String,
    enrolled_credential: Option<String>,
    credential_expires_at: Option<chrono::DateTime<Utc>>,
    pairing_code: Option<String>,
    pairing_expires_at: chrono::DateTime<Utc>,
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
    if let Some(bind) = args.tcp_bind.clone() {
        return serve_tls(args, bind, auth).await;
    }
    serve_unix(args, auth).await
}

async fn serve_unix(args: Args, auth: Arc<Mutex<AgentAuth>>) -> Result<()> {
    if let Some(parent) = args.socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if args.socket.exists() {
        tokio::fs::remove_file(&args.socket)
            .await
            .context("remove stale Agent socket")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind Agent Unix socket")?;
    println!("AMCP Agent listening on {}", args.socket.display());

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accept Controller connection")?;
        let auth = auth.clone();
        let codex_home = args.codex_home.clone();
        let backup_dir = default_backup_dir();
        let state_dir = default_state_dir();
        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(stream, auth, codex_home, backup_dir, state_dir).await
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
        let backup_dir = default_backup_dir();
        let state_dir = default_state_dir();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    if let Err(error) =
                        handle_connection(stream, auth, codex_home, backup_dir, state_dir).await
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
        let response = process_request(request, &auth, codex_home.clone(), &backup_dir, &state_dir);
        let should_close = matches!(&response.result, Ok(ResponsePayload::ShutdownAck));
        write_response(&mut writer, response).await?;
        if should_close {
            break;
        }
    }
    Ok(())
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
            RequestMethod::Capabilities => Ok(ResponsePayload::Capabilities {
                platform: host_identity().platform,
                providers: provider_registry(codex_home.clone())
                    .descriptors()
                    .iter()
                    .map(|provider| provider.id.clone())
                    .collect(),
                capabilities: provider_registry(codex_home.clone())
                    .descriptors()
                    .into_iter()
                    .flat_map(|provider| provider.capabilities)
                    .collect(),
                agent_version: env!("CARGO_PKG_VERSION").into(),
            }),
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
                        Ok(ResponsePayload::Collection(batch))
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
                if !approval.is_valid(request_token.as_deref().unwrap_or_default(), Utc::now())
                    || approval.change_set_id != change_set.change_set_id
                    || approval.operations_hash != change_set_operations_hash(&change_set)
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
                if !approval.is_valid(request_token.as_deref().unwrap_or_default(), Utc::now())
                    || approval.change_set_id != change_set.change_set_id
                    || approval.operations_hash != change_set_operations_hash(&change_set)
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

fn provider_registry(codex_home: Option<PathBuf>) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(CodexAdapter::from_environment(codex_home)));
    registry
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
