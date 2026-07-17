use amcp_codex::CodexAdapter;
use amcp_domain::HostIdentity;
use amcp_protocol::{
    PROTOCOL_VERSION, ProtocolError, RequestEnvelope, RequestMethod, ResponseEnvelope,
    ResponsePayload,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{env, path::PathBuf};
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

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
        let token = args.token.clone();
        let codex_home = args.codex_home.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, token, codex_home).await {
                eprintln!("AMCP Agent connection error: {error:#}");
            }
        });
    }
}

async fn handle_connection(
    stream: UnixStream,
    token: String,
    codex_home: Option<PathBuf>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
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
        let response = process_request(request, &token, codex_home.clone());
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
            }),
            RequestMethod::Heartbeat => Ok(ResponsePayload::Heartbeat { healthy: true }),
            RequestMethod::Capabilities => Ok(ResponsePayload::Capabilities {
                platform: host_identity().platform,
                providers: vec!["codex".into()],
            }),
            RequestMethod::Collect { scope, .. } => {
                if let Some(scope) = scope {
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
                match CodexAdapter::from_environment(codex_home).discover(host_identity()) {
                    Ok(batch) => Ok(ResponsePayload::Collection(batch)),
                    Err(error) => Err(ProtocolError::new("collection_failed", error.to_string())),
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
