use amcp_codex::CodexAdapter;
use amcp_domain::HostIdentity;
use amcp_domain::change_set_operations_hash;
use amcp_platform::{MacOsKeychain, SecretStore, keychain_account_for_host};
use amcp_protocol::{
    PROTOCOL_VERSION, ProtocolError, RequestEnvelope, RequestMethod, ResponseEnvelope,
    ResponsePayload,
};
use amcp_provider_api::ProviderRegistry;
use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use std::{env, fs::File, io::BufReader as StdBufReader, path::PathBuf, sync::Arc};
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
    if let Some(bind) = args.tcp_bind.clone() {
        return serve_tls(args, bind, token).await;
    }
    serve_unix(args, token).await
}

async fn serve_unix(args: Args, token: String) -> Result<()> {
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
        let token = token.clone();
        let codex_home = args.codex_home.clone();
        let backup_dir = default_backup_dir();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, token, codex_home, backup_dir).await {
                eprintln!("AMCP Agent connection error: {error:#}");
            }
        });
    }
}

async fn serve_tls(args: Args, bind: String, token: String) -> Result<()> {
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
        let token = token.clone();
        let codex_home = args.codex_home.clone();
        let backup_dir = default_backup_dir();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    if let Err(error) =
                        handle_connection(stream, token, codex_home, backup_dir).await
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
    token: String,
    codex_home: Option<PathBuf>,
    backup_dir: PathBuf,
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
        let response = process_request(request, &token, codex_home.clone(), &backup_dir);
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
    expected_token: &str,
    codex_home: Option<PathBuf>,
    backup_dir: &PathBuf,
) -> ResponseEnvelope {
    let request_id = request.request_id.clone();
    let response = if request.protocol_version != PROTOCOL_VERSION {
        Err(ProtocolError::new(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ))
    } else if request.token.as_deref() != Some(expected_token) {
        Err(ProtocolError::new("unauthorized", "invalid Agent token"))
    } else {
        match request.method {
            RequestMethod::Register { .. } => Ok(ResponsePayload::Registered {
                agent_id: host_identity().host_id,
                host: host_identity(),
            }),
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
            RequestMethod::Collect { scope, .. } => {
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
                match provider_registry(codex_home)
                    .get(provider_id)
                    .and_then(|provider| provider.discover(host_identity()))
                {
                    Ok(batch) => Ok(ResponsePayload::Collection(batch)),
                    Err(error) => Err(ProtocolError::new("collection_failed", error.to_string())),
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
                if !approval.is_valid(expected_token, Utc::now())
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
                if !approval.is_valid(expected_token, Utc::now())
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
