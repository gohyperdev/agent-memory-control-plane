use amcp_domain::Scope;
use amcp_protocol::{RequestEnvelope, RequestMethod, ResponseEnvelope, ResponsePayload};
use amcp_storage::Catalog;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{env, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::{Child, Command},
    time::sleep,
};

#[derive(Debug, Parser)]
#[command(name = "amcp-controller", about = "AMCP Collector/Controller")]
struct Args {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    RunOnce {
        #[arg(
            long,
            default_value = "/tmp/amcp-agent.sock",
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(
            long,
            default_value = "amcp-development-token",
            env = "AMCP_AGENT_TOKEN"
        )]
        token: String,
        #[arg(long)]
        codex_home: Option<PathBuf>,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        agent_bin: Option<PathBuf>,
        #[arg(long)]
        no_start_agent: bool,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Search {
        query: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        CommandKind::RunOnce {
            socket,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            query,
            json,
        } => {
            run_once(
                socket,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                query,
                json,
            )
            .await
        }
        CommandKind::Search { query, db, limit } => {
            search(db.unwrap_or_else(default_db_path), query, limit)
        }
    }
}

async fn run_once(
    socket: PathBuf,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    query: Option<String>,
    json: bool,
) -> Result<()> {
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).context("create Controller data directory")?;
    }
    let mut child = if no_start_agent {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let stream = connect_with_retry(&socket)
        .await
        .context("connect to AMCP Agent")?;
    let mut client = AgentClient::new(stream);
    client
        .request(
            RequestMethod::Register {
                controller_id: "amcp-controller-local".into(),
            },
            &token,
        )
        .await?;
    let batch = match client
        .request(
            RequestMethod::Collect {
                scope: Some(Scope::host(host_id_from_env())),
                cursor: None,
            },
            &token,
        )
        .await?
    {
        ResponsePayload::Collection(batch) => batch,
        other => bail!("Agent returned unexpected collection response: {other:?}"),
    };

    let mut catalog = Catalog::open(&db)?;
    let inserted = catalog.ingest(&batch)?;
    let search_results = query
        .as_deref()
        .map(|value| catalog.search(value, 20))
        .transpose()?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "host_id": batch.host.host_id,
                "collection_run_id": batch.collection_run_id,
                "discovered": batch.artifacts.len(),
                "inserted": inserted,
                "search": search_results.as_ref().map(|hits| hits.iter().map(|hit| serde_json::json!({"title": hit.title, "source": hit.source_reference, "preview": hit.preview})).collect::<Vec<_>>())
            })
        );
    } else {
        println!(
            "Collected {} Codex artifacts ({} new) into {}",
            batch.artifacts.len(),
            inserted,
            db.display()
        );
        for artifact in batch.artifacts.iter().take(20) {
            println!("- {} [{}]", artifact.source_reference, artifact.title);
        }
        if let Some(hits) = search_results {
            println!("\nSearch results:");
            for hit in hits {
                println!("- {} — {}", hit.title, hit.preview);
            }
        }
    }

    let _ = client.request(RequestMethod::Shutdown, &token).await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    Ok(())
}

fn search(db: PathBuf, query: String, limit: usize) -> Result<()> {
    let catalog = Catalog::open(&db)?;
    for hit in catalog.search(&query, limit)? {
        println!("{}\t{}\t{}", hit.title, hit.source_reference, hit.preview);
    }
    Ok(())
}

async fn start_agent(
    socket: &PathBuf,
    token: &str,
    codex_home: Option<&PathBuf>,
    agent_bin: Option<PathBuf>,
) -> Result<Child> {
    let executable = agent_bin.unwrap_or_else(default_agent_binary);
    let mut command = Command::new(executable);
    command
        .arg("--socket")
        .arg(socket)
        .arg("--token")
        .arg(token);
    if let Some(codex_home) = codex_home {
        command.arg("--codex-home").arg(codex_home);
    }
    command
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    Ok(command.spawn().context("start AMCP Agent")?)
}

async fn connect_with_retry(socket: &PathBuf) -> Result<UnixStream> {
    for _ in 0..40 {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }
    bail!(
        "Agent socket did not become available: {}",
        socket.display()
    )
}

struct AgentClient {
    reader: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl AgentClient {
    fn new(stream: UnixStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    async fn request(&mut self, method: RequestMethod, token: &str) -> Result<ResponsePayload> {
        let request = RequestEnvelope::new(method, Some(token.to_owned()));
        let request_id = request.request_id.clone();
        let encoded = serde_json::to_string(&request)?;
        self.writer.write_all(encoded.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        let line = self
            .reader
            .next_line()
            .await?
            .context("Agent closed connection")?;
        let response: ResponseEnvelope = serde_json::from_str(&line)?;
        if response.request_id != request_id {
            bail!("Agent response request ID mismatch")
        }
        response
            .result
            .map_err(|error| anyhow::anyhow!("Agent {}: {}", error.code, error.message))
    }
}

fn default_db_path() -> PathBuf {
    env::var_os("AMCP_DB_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home).join("Library/Application Support/AMCP/controller.sqlite")
            })
        })
        .unwrap_or_else(|| PathBuf::from(".amcp/controller.sqlite"))
}

fn default_agent_binary() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("amcp-agent")))
        .unwrap_or_else(|| PathBuf::from("amcp-agent"))
}

fn host_id_from_env() -> String {
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into());
    env::var("AMCP_HOST_ID").unwrap_or_else(|_| format!("host_{}", hostname.replace('.', "-")))
}
