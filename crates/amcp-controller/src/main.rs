use amcp_core::CatalogService;
use amcp_domain::{
    ApprovalEnvelope, ArtifactRef, AuditEvent, ChangeRequest, ChangeStatus, HostIdentity, Scope,
    change_set_operations_hash, new_id,
};
use amcp_platform::{
    MacOsKeychain, SecretStore, default_agent_socket_path, keychain_account_for_host,
};
use amcp_protocol::{RequestEnvelope, RequestMethod, ResponseEnvelope, ResponsePayload};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::{
    env,
    fs::File,
    io::BufReader as StdBufReader,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::{TcpStream, UnixStream},
    process::{Child, Command},
    time::sleep,
};
use tokio_rustls::TlsConnector;

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
            default_value_os_t = default_agent_socket_path(),
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(long, env = "AMCP_AGENT_URL")]
        agent_url: Option<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
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
    Watch {
        #[arg(long = "agent-url", env = "AMCP_AGENT_URL")]
        agent_urls: Vec<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
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
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,
        #[arg(long)]
        iterations: Option<usize>,
    },
    Search {
        query: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    ProposeChange {
        #[arg(
            long,
            default_value_os_t = default_agent_socket_path(),
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(long, env = "AMCP_AGENT_URL")]
        agent_url: Option<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
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
        source: PathBuf,
        #[arg(long)]
        replacement_file: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    ApproveChange {
        #[arg(
            long,
            default_value_os_t = default_agent_socket_path(),
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(long, env = "AMCP_AGENT_URL")]
        agent_url: Option<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
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
        change_set_id: String,
        #[arg(long, default_value = "human")]
        approved_by: String,
        #[arg(long, default_value_t = 10)]
        expires_minutes: i64,
        #[arg(long)]
        json: bool,
    },
    RollbackChange {
        #[arg(
            long,
            default_value_os_t = default_agent_socket_path(),
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(long, env = "AMCP_AGENT_URL")]
        agent_url: Option<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
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
        change_set_id: String,
        #[arg(long, default_value = "human")]
        approved_by: String,
        #[arg(long, default_value_t = 10)]
        expires_minutes: i64,
        #[arg(long)]
        json: bool,
    },
    Hosts {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    KeychainStore {
        #[arg(long, env = "AMCP_HOST_ID")]
        host_id: String,
        #[arg(long, env = "AMCP_AGENT_TOKEN")]
        token: String,
    },
    Enroll {
        #[arg(
            long,
            default_value_os_t = default_agent_socket_path(),
            env = "AMCP_AGENT_SOCKET"
        )]
        socket: PathBuf,
        #[arg(long, env = "AMCP_AGENT_URL")]
        agent_url: Option<String>,
        #[arg(long, env = "AMCP_AGENT_TLS_CA")]
        tls_ca: Option<PathBuf>,
        #[arg(long, env = "AMCP_AGENT_TLS_SERVER_NAME")]
        tls_server_name: Option<String>,
        #[arg(long)]
        pairing_code: String,
        #[arg(
            long,
            default_value = "amcp-development-token",
            env = "AMCP_AGENT_TOKEN"
        )]
        bootstrap_token: String,
        #[arg(long, default_value = "amcp-controller-local")]
        controller_id: String,
        #[arg(long)]
        codex_home: Option<PathBuf>,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        agent_bin: Option<PathBuf>,
        #[arg(long)]
        no_start_agent: bool,
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        CommandKind::RunOnce {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
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
                agent_url,
                tls_ca,
                tls_server_name,
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
        CommandKind::Watch {
            agent_urls,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            interval_seconds,
            iterations,
        } => {
            watch(
                agent_urls,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                interval_seconds,
                iterations,
            )
            .await
        }
        CommandKind::ProposeChange {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            source,
            replacement_file,
            reason,
            host_id,
            json,
        } => {
            propose_change(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                source,
                replacement_file,
                reason,
                host_id.unwrap_or_else(host_id_from_env),
                json,
            )
            .await
        }
        CommandKind::ApproveChange {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            change_set_id,
            approved_by,
            expires_minutes,
            json,
        } => {
            approve_change(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                change_set_id,
                approved_by,
                expires_minutes,
                json,
            )
            .await
        }
        CommandKind::RollbackChange {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            change_set_id,
            approved_by,
            expires_minutes,
            json,
        } => {
            rollback_change(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                change_set_id,
                approved_by,
                expires_minutes,
                json,
            )
            .await
        }
        CommandKind::Hosts { db } => list_hosts(db.unwrap_or_else(default_db_path)),
        CommandKind::KeychainStore { host_id, token } => {
            store_keychain_credential(&host_id, &token)
        }
        CommandKind::Enroll {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            pairing_code,
            bootstrap_token,
            controller_id,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            json,
        } => {
            enroll(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                pairing_code,
                bootstrap_token,
                controller_id,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                json,
            )
            .await
        }
    }
}

async fn run_once(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    query: Option<String>,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).context("create Controller data directory")?;
    }
    let mut child = if no_start_agent || agent_url.is_some() {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let stream = connect_with_retry(
        &socket,
        agent_url.as_deref(),
        tls_ca.as_deref(),
        tls_server_name.as_deref(),
    )
    .await
    .context("connect to AMCP Agent")?;
    let mut client = AgentClient::new(stream);
    let (registered_host, agent_version, capabilities) =
        register_and_refresh(&mut client, &token).await?;
    let mut catalog = CatalogService::open(&db)?;
    let replayed = match client
        .request(
            RequestMethod::ReplayCollection {
                provider_id: "codex".into(),
                limit: 8,
            },
            &token,
        )
        .await
    {
        Ok(ResponsePayload::CollectionReplay { batches, .. }) => {
            let mut count = 0usize;
            for replay in batches {
                catalog.ingest(&replay)?;
                catalog.save_cursor(
                    &replay.host.host_id,
                    "codex",
                    replay
                        .next_cursor
                        .as_deref()
                        .or(Some(replay.collection_run_id.as_str())),
                    &replay.collection_run_id,
                )?;
                count += 1;
            }
            count
        }
        Ok(_) => 0,
        Err(error) => {
            eprintln!("AMCP replay unavailable; continuing with live collection: {error:#}");
            0
        }
    };
    let cursor = catalog.latest_cursor(&registered_host.host_id, "codex")?;
    let batch = match client
        .request(
            RequestMethod::Collect {
                scope: if agent_url.is_some() {
                    None
                } else {
                    Some(Scope::host(host_id_from_env()))
                },
                cursor,
            },
            &token,
        )
        .await?
    {
        ResponsePayload::Collection(batch) => batch,
        other => bail!("Agent returned unexpected collection response: {other:?}"),
    };

    let endpoint = agent_url
        .clone()
        .unwrap_or_else(|| format!("unix://{}", socket.display()));
    catalog.register_connection(
        &registered_host,
        Some(&endpoint),
        Some(&agent_version),
        &capabilities,
    )?;
    let inserted = catalog.ingest(&batch)?;
    catalog.save_cursor(
        &batch.host.host_id,
        "codex",
        batch
            .next_cursor
            .as_deref()
            .or(Some(batch.collection_run_id.as_str())),
        &batch.collection_run_id,
    )?;
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
                "replayed": replayed,
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

async fn watch(
    agent_urls: Vec<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    interval_seconds: u64,
    iterations: Option<usize>,
) -> Result<()> {
    let endpoints = if agent_urls.is_empty() {
        vec![None]
    } else {
        agent_urls.into_iter().map(Some).collect()
    };
    let mut completed = 0usize;
    loop {
        for endpoint in &endpoints {
            let result = run_once(
                PathBuf::from(
                    env::var_os("AMCP_AGENT_SOCKET")
                        .unwrap_or_else(|| default_agent_socket_path().into_os_string()),
                ),
                endpoint.clone(),
                tls_ca.clone(),
                tls_server_name.clone(),
                token.clone(),
                codex_home.clone(),
                db.clone(),
                agent_bin.clone(),
                endpoint.is_some(),
                None,
                true,
            )
            .await;
            if let Err(error) = result {
                eprintln!("AMCP watch collection failed for {:?}: {error:#}", endpoint);
            }
        }
        completed += 1;
        if iterations.is_some_and(|limit| completed >= limit) {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = sleep(StdDuration::from_secs(interval_seconds.max(1))) => {}
        }
    }
}

async fn enroll(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    pairing_code: String,
    bootstrap_token: String,
    controller_id: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    json: bool,
) -> Result<()> {
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).context("create Controller data directory")?;
    }
    let mut child = if no_start_agent || agent_url.is_some() {
        None
    } else {
        Some(
            start_enrollment_agent(
                &socket,
                &bootstrap_token,
                &pairing_code,
                codex_home.as_ref(),
                agent_bin,
            )
            .await?,
        )
    };
    let result = async {
        let stream = connect_with_retry(
            &socket,
            agent_url.as_deref(),
            tls_ca.as_deref(),
            tls_server_name.as_deref(),
        )
        .await
        .context("connect to Agent for enrollment")?;
        let mut client = AgentClient::new(stream);
        let enrolled = match client
            .request_with_auth(
                RequestMethod::Enroll { controller_id },
                None,
                Some(&pairing_code),
            )
            .await?
        {
            ResponsePayload::Enrolled {
                host,
                credential,
                expires_at,
                ..
            } => (host, credential, expires_at),
            other => bail!("Agent returned unexpected enrollment response: {other:?}"),
        };
        let (host, credential, expires_at) = enrolled;
        let (agent_version, capabilities) = match client
            .request(RequestMethod::Capabilities, &credential)
            .await?
        {
            ResponsePayload::Capabilities {
                agent_version,
                capabilities,
                ..
            } => (agent_version, capabilities),
            other => bail!("Agent returned unexpected capabilities response: {other:?}"),
        };
        match client
            .request(RequestMethod::Heartbeat, &credential)
            .await?
        {
            ResponsePayload::Heartbeat { healthy: true, .. } => {}
            other => bail!("Agent returned unexpected heartbeat response: {other:?}"),
        }
        MacOsKeychain::new(keychain_account_for_host(&host.host_id)).set(&credential)?;
        let endpoint = agent_url
            .clone()
            .unwrap_or_else(|| format!("unix://{}", socket.display()));
        let mut catalog = CatalogService::open(&db)?;
        catalog.register_connection(&host, Some(&endpoint), Some(&agent_version), &capabilities)?;
        let _ = client.request(RequestMethod::Shutdown, &credential).await;
        Ok::<_, anyhow::Error>((host, expires_at))
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let (host, expires_at) = result?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "host_id": host.host_id,
                "display_name": host.display_name,
                "credential_stored": true,
                "expires_at": expires_at,
            })
        );
    } else {
        println!("Enrolled host {} ({})", host.host_id, host.display_name);
        println!("Credential stored in the macOS Keychain; expires at {expires_at}");
    }
    Ok(())
}

fn search(db: PathBuf, query: String, limit: usize) -> Result<()> {
    let catalog = CatalogService::open(&db)?;
    for hit in catalog.search(&query, limit)? {
        println!("{}\t{}\t{}", hit.title, hit.source_reference, hit.preview);
    }
    Ok(())
}

async fn propose_change(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    source: PathBuf,
    replacement_file: PathBuf,
    reason: String,
    host_id: String,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
    let replacement_content = std::fs::read_to_string(&replacement_file)
        .with_context(|| format!("read replacement file {}", replacement_file.display()))?;
    let mut child = if no_start_agent || agent_url.is_some() {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let result = async {
        let stream = connect_with_retry(
            &socket,
            agent_url.as_deref(),
            tls_ca.as_deref(),
            tls_server_name.as_deref(),
        )
        .await?;
        let mut client = AgentClient::new(stream);
        let (registered_host, agent_version, capabilities) =
            register_and_refresh(&mut client, &token).await?;
        let target_path = source
            .canonicalize()
            .unwrap_or(source)
            .to_string_lossy()
            .into_owned();
        let request = ChangeRequest {
            actor: "human-or-controller".into(),
            scope: Scope::host(host_id.clone()),
            target: ArtifactRef {
                host_id,
                provider_id: "codex".into(),
                native_id: target_path.clone(),
                source_reference: target_path,
            },
            expected_source_hash: None,
            operation: amcp_domain::ChangeOperationKind::ReplaceText,
            replacement_content: Some(replacement_content),
            reason,
            evidence_ids: Vec::new(),
        };
        let change_set = match client
            .request(RequestMethod::ProposeChange { request }, &token)
            .await?
        {
            ResponsePayload::ChangeSet(change_set) => change_set,
            other => bail!("Agent returned unexpected proposal response: {other:?}"),
        };
        let mut catalog = CatalogService::open(&db)?;
        let endpoint = agent_url
            .clone()
            .unwrap_or_else(|| format!("unix://{}", socket.display()));
        catalog.register_connection(
            &registered_host,
            Some(&endpoint),
            Some(&agent_version),
            &capabilities,
        )?;
        catalog.save_change_set(&change_set)?;
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        Ok::<_, anyhow::Error>(change_set)
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let change_set = result?;
    if json {
        println!("{}", serde_json::to_string_pretty(&change_set)?);
    } else {
        println!(
            "Proposed {} with {} operation(s): {}",
            change_set.change_set_id,
            change_set.operations.len(),
            change_set.reason
        );
        for operation in &change_set.operations {
            println!("{}", operation.diff);
        }
    }
    Ok(())
}

async fn approve_change(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    change_set_id: String,
    approved_by: String,
    expires_minutes: i64,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
    let mut catalog = CatalogService::open(&db)?;
    let mut change_set = catalog
        .load_change_set(&change_set_id)?
        .with_context(|| format!("change set not found: {change_set_id}"))?;
    let now = Utc::now();
    let approval = ApprovalEnvelope::issue(
        &token,
        change_set.change_set_id.clone(),
        approved_by.clone(),
        now,
        now + Duration::minutes(expires_minutes.max(1)),
        new_id("idempotency"),
        change_set_operations_hash(&change_set),
    );
    change_set.status = ChangeStatus::Approved;
    change_set.updated_at = now;
    catalog.save_change_set(&change_set)?;

    let mut child = if no_start_agent || agent_url.is_some() {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let result = async {
        let stream = connect_with_retry(
            &socket,
            agent_url.as_deref(),
            tls_ca.as_deref(),
            tls_server_name.as_deref(),
        )
        .await?;
        let mut client = AgentClient::new(stream);
        register_and_refresh(&mut client, &token).await?;
        let receipt = match client
            .request(
                RequestMethod::ApplyChange {
                    change_set: change_set.clone(),
                    approval,
                },
                &token,
            )
            .await?
        {
            ResponsePayload::ChangeReceipt(receipt) => receipt,
            other => bail!("Agent returned unexpected apply response: {other:?}"),
        };
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        Ok::<_, anyhow::Error>(receipt)
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => {
            change_set.status = ChangeStatus::Failed;
            change_set.updated_at = Utc::now();
            catalog.save_change_set(&change_set)?;
            return Err(error);
        }
    };
    change_set.status = receipt.status.clone();
    change_set.updated_at = receipt.applied_at;
    catalog.save_change_set(&change_set)?;
    catalog.record_audit(&AuditEvent {
        audit_event_id: new_id("audit"),
        actor: approved_by,
        operation: "change.apply".into(),
        target: change_set
            .operations
            .first()
            .map(|operation| operation.target.source_reference.clone())
            .unwrap_or_else(|| change_set.change_set_id.clone()),
        host_id: change_set.scope.host_id.clone(),
        provider_id: Some(change_set.provider_id.clone()),
        before_hash: receipt.before_hashes.first().cloned(),
        after_hash: receipt.after_hashes.first().cloned(),
        result: format!("{:?}: {}", receipt.status, receipt.message),
        correlation_id: new_id("correlation"),
        timestamp: receipt.applied_at,
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!("{:?}: {}", receipt.status, receipt.message);
        for backup in receipt.backup_references {
            println!("backup: {backup}");
        }
    }
    Ok(())
}

async fn rollback_change(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    change_set_id: String,
    approved_by: String,
    expires_minutes: i64,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
    let mut catalog = CatalogService::open(&db)?;
    let mut change_set = catalog
        .load_change_set(&change_set_id)?
        .with_context(|| format!("change set not found: {change_set_id}"))?;
    let now = Utc::now();
    let approval = ApprovalEnvelope::issue(
        &token,
        change_set.change_set_id.clone(),
        approved_by.clone(),
        now,
        now + Duration::minutes(expires_minutes.max(1)),
        new_id("idempotency"),
        change_set_operations_hash(&change_set),
    );
    change_set.status = ChangeStatus::Approved;
    change_set.updated_at = now;
    catalog.save_change_set(&change_set)?;

    let mut child = if no_start_agent || agent_url.is_some() {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let result = async {
        let stream = connect_with_retry(
            &socket,
            agent_url.as_deref(),
            tls_ca.as_deref(),
            tls_server_name.as_deref(),
        )
        .await?;
        let mut client = AgentClient::new(stream);
        register_and_refresh(&mut client, &token).await?;
        let receipt = match client
            .request(
                RequestMethod::Rollback {
                    change_set: change_set.clone(),
                    approval,
                },
                &token,
            )
            .await?
        {
            ResponsePayload::ChangeReceipt(receipt) => receipt,
            other => bail!("Agent returned unexpected rollback response: {other:?}"),
        };
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        Ok::<_, anyhow::Error>(receipt)
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let receipt = match result {
        Ok(receipt) => receipt,
        Err(error) => {
            change_set.status = ChangeStatus::Failed;
            change_set.updated_at = Utc::now();
            catalog.save_change_set(&change_set)?;
            return Err(error);
        }
    };
    change_set.status = receipt.status.clone();
    change_set.updated_at = receipt.applied_at;
    catalog.save_change_set(&change_set)?;
    catalog.record_audit(&AuditEvent {
        audit_event_id: new_id("audit"),
        actor: approved_by,
        operation: "change.rollback".into(),
        target: change_set
            .operations
            .first()
            .map(|operation| operation.target.source_reference.clone())
            .unwrap_or_else(|| change_set.change_set_id.clone()),
        host_id: change_set.scope.host_id.clone(),
        provider_id: Some(change_set.provider_id.clone()),
        before_hash: receipt.before_hashes.first().cloned(),
        after_hash: receipt.after_hashes.first().cloned(),
        result: format!("{:?}: {}", receipt.status, receipt.message),
        correlation_id: new_id("correlation"),
        timestamp: receipt.applied_at,
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!("{:?}: {}", receipt.status, receipt.message);
    }
    Ok(())
}

fn list_hosts(db: PathBuf) -> Result<()> {
    let catalog = CatalogService::open(&db)?;
    for host in catalog.list_hosts()? {
        println!(
            "{}\t{}\t{:?}\t{}",
            host.identity.host_id, host.identity.platform, host.status, host.identity.hostname
        );
    }
    Ok(())
}

fn store_keychain_credential(host_id: &str, token: &str) -> Result<()> {
    MacOsKeychain::new(keychain_account_for_host(host_id)).set(token)?;
    println!("Stored AMCP Agent credential for {host_id} in the macOS Keychain");
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

async fn start_enrollment_agent(
    socket: &PathBuf,
    token: &str,
    pairing_code: &str,
    codex_home: Option<&PathBuf>,
    agent_bin: Option<PathBuf>,
) -> Result<Child> {
    let executable = agent_bin.unwrap_or_else(default_agent_binary);
    let mut command = Command::new(executable);
    command
        .arg("--socket")
        .arg(socket)
        .arg("--token")
        .arg(token)
        .arg("--pairing-code")
        .arg(pairing_code);
    if let Some(codex_home) = codex_home {
        command.arg("--codex-home").arg(codex_home);
    }
    command
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    Ok(command.spawn().context("start AMCP Agent for enrollment")?)
}

trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AgentStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type DynAgentStream = Box<dyn AgentStream>;

async fn connect_with_retry(
    socket: &Path,
    agent_url: Option<&str>,
    tls_ca: Option<&Path>,
    tls_server_name: Option<&str>,
) -> Result<DynAgentStream> {
    if let Some(agent_url) = agent_url {
        let address = agent_url
            .strip_prefix("tcp://")
            .context("Agent URL must use tcp://")?;
        let connector =
            load_tls_connector(tls_ca.context("--tls-ca is required for remote Agents")?)?;
        let default_server_name = address
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(address);
        let server_name = tls_server_name.unwrap_or(default_server_name).to_owned();
        for _ in 0..40 {
            match TcpStream::connect(address).await {
                Ok(stream) => {
                    let name = ServerName::try_from(server_name.clone())
                        .map_err(|_| anyhow::anyhow!("invalid TLS server name: {server_name}"))?;
                    match connector.connect(name, stream).await {
                        Ok(stream) => return Ok(Box::new(stream)),
                        Err(_) => sleep(StdDuration::from_millis(100)).await,
                    }
                }
                Err(_) => sleep(StdDuration::from_millis(100)).await,
            }
        }
        bail!("remote Agent did not become available: {agent_url}")
    }
    for _ in 0..40 {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(Box::new(stream)),
            Err(_) => sleep(StdDuration::from_millis(100)).await,
        }
    }
    bail!(
        "Agent socket did not become available: {}",
        socket.display()
    )
}

fn load_tls_connector(ca_path: &Path) -> Result<TlsConnector> {
    let mut reader = StdBufReader::new(File::open(ca_path)?);
    let certificates =
        rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

struct AgentClient<S: AsyncRead + AsyncWrite + Unpin> {
    reader: tokio::io::Lines<BufReader<ReadHalf<S>>>,
    writer: WriteHalf<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AgentClient<S> {
    fn new(stream: S) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    async fn request(&mut self, method: RequestMethod, token: &str) -> Result<ResponsePayload> {
        self.request_with_auth(method, Some(token), None).await
    }

    async fn request_with_auth(
        &mut self,
        method: RequestMethod,
        token: Option<&str>,
        pairing_code: Option<&str>,
    ) -> Result<ResponsePayload> {
        let request = RequestEnvelope::new(method, token.map(str::to_owned));
        let request = if let Some(code) = pairing_code {
            request.with_pairing_code(code)
        } else {
            request
        };
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

async fn register_and_refresh<S>(
    client: &mut AgentClient<S>,
    token: &str,
) -> Result<(HostIdentity, String, Vec<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = match client
        .request(
            RequestMethod::Register {
                controller_id: "amcp-controller-local".into(),
            },
            token,
        )
        .await?
    {
        ResponsePayload::Registered { host, .. } => host,
        other => bail!("Agent returned unexpected register response: {other:?}"),
    };
    let (agent_version, capabilities) =
        match client.request(RequestMethod::Capabilities, token).await? {
            ResponsePayload::Capabilities {
                agent_version,
                capabilities,
                ..
            } => (agent_version, capabilities),
            other => bail!("Agent returned unexpected capabilities response: {other:?}"),
        };
    match client.request(RequestMethod::Heartbeat, token).await? {
        ResponsePayload::Heartbeat { healthy: true, .. } => {}
        ResponsePayload::Heartbeat { healthy: false, .. } => {
            bail!("Agent heartbeat reported an unhealthy host")
        }
        other => bail!("Agent returned unexpected heartbeat response: {other:?}"),
    }
    Ok((host, agent_version, capabilities))
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

const DEVELOPMENT_TOKEN: &str = "amcp-development-token";

fn resolve_agent_token(token: &str) -> String {
    if token != DEVELOPMENT_TOKEN {
        return token.to_owned();
    }
    let account = env::var("AMCP_AGENT_KEYCHAIN_ACCOUNT")
        .unwrap_or_else(|_| keychain_account_for_host(&host_id_from_env()));
    MacOsKeychain::new(account)
        .get()
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| token.to_owned())
}
