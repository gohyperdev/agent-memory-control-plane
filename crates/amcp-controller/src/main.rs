#![allow(clippy::too_many_arguments)]

use amcp_core::CatalogService;
use amcp_domain::{
    ApprovalEnvelope, ArtifactRef, AuditEvent, ChangeRequest, ChangeStatus, HostIdentity,
    ProviderDescriptor, Scope, change_set_operations_hash, new_id,
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
    collections::VecDeque,
    env,
    fs::File,
    io::BufReader as StdBufReader,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
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
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
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
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,
        #[arg(long)]
        iterations: Option<usize>,
    },
    RuntimeList {
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
        agent_bin: Option<PathBuf>,
        #[arg(long)]
        no_start_agent: bool,
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    RuntimeRead {
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
        agent_bin: Option<PathBuf>,
        #[arg(long)]
        no_start_agent: bool,
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
        thread_id: String,
        #[arg(long)]
        json: bool,
    },
    RuntimePropose {
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
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
        #[arg(long, conflicts_with = "unarchive")]
        archive: bool,
        #[arg(long, conflicts_with = "archive")]
        unarchive: bool,
        thread_id: String,
        #[arg(long, default_value = "runtime thread lifecycle change")]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    StreamEvents {
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
        #[arg(long, default_value_t = 16)]
        max_in_flight: usize,
        #[arg(long, default_value_t = 1_000)]
        heartbeat_ms: u64,
        #[arg(long, default_value_t = 10)]
        duration_seconds: u64,
        #[arg(long)]
        provider_id: Option<String>,
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
    RebuildIndex {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 256)]
        batch_size: usize,
        #[arg(long)]
        json: bool,
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
            provider_id,
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
                provider_id,
                query,
                json,
                0,
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
            provider_id,
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
                provider_id,
                interval_seconds,
                iterations,
            )
            .await
        }
        CommandKind::RuntimeList {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            agent_bin,
            no_start_agent,
            provider_id,
            limit,
            json,
        } => {
            runtime_list(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                agent_bin,
                no_start_agent,
                provider_id,
                limit,
                json,
            )
            .await
        }
        CommandKind::RuntimeRead {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            agent_bin,
            no_start_agent,
            provider_id,
            thread_id,
            json,
        } => {
            runtime_read(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                agent_bin,
                no_start_agent,
                provider_id,
                thread_id,
                json,
            )
            .await
        }
        CommandKind::RuntimePropose {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            provider_id,
            archive,
            unarchive,
            thread_id,
            reason,
            json,
        } => {
            runtime_propose(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                provider_id,
                archive,
                unarchive,
                thread_id,
                reason,
                json,
            )
            .await
        }
        CommandKind::StreamEvents {
            socket,
            agent_url,
            tls_ca,
            tls_server_name,
            token,
            codex_home,
            db,
            agent_bin,
            no_start_agent,
            max_in_flight,
            heartbeat_ms,
            duration_seconds,
            provider_id,
            json,
        } => {
            stream_events(
                socket,
                agent_url,
                tls_ca,
                tls_server_name,
                token,
                codex_home,
                db.unwrap_or_else(default_db_path),
                agent_bin,
                no_start_agent,
                max_in_flight,
                heartbeat_ms,
                duration_seconds,
                provider_id,
                json,
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
        CommandKind::RebuildIndex {
            db,
            batch_size,
            json,
        } => rebuild_index(db.unwrap_or_else(default_db_path), batch_size, json),
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
    provider_id: String,
    query: Option<String>,
    json: bool,
    event_wait_ms: u64,
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
    let (registered_host, agent_version, capabilities, provider_descriptors) =
        register_and_refresh(&mut client, &token).await?;
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
    catalog.register_provider_descriptors(&registered_host, &provider_descriptors)?;
    let (replayed_events, persisted_events, replayed_event_ids) = match client
        .request(
            RequestMethod::SubscribeEvents {
                after_event_id: None,
                limit: 256,
                wait_ms: event_wait_ms,
            },
            &token,
        )
        .await
    {
        Ok(ResponsePayload::RuntimeEventPage { events, .. })
        | Ok(ResponsePayload::RuntimeEvents(events)) => {
            let events = events
                .into_iter()
                .filter(|event| event.host_id == registered_host.host_id)
                .collect::<Vec<_>>();
            let received = events.len();
            let persisted = catalog.ingest_runtime_events(&events)?;
            let event_ids = events
                .into_iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>();
            (received, persisted, event_ids)
        }
        Ok(_) => (0, 0, Vec::new()),
        Err(error) => {
            eprintln!("AMCP event replay unavailable; continuing: {error:#}");
            (0, 0, Vec::new())
        }
    };
    if !replayed_event_ids.is_empty() {
        match client
            .request(
                RequestMethod::AckEvents {
                    event_ids: replayed_event_ids,
                },
                &token,
            )
            .await
        {
            Ok(ResponsePayload::RuntimeEventsAcked(_)) => {}
            Ok(_) => eprintln!("AMCP Agent returned an unexpected event ack response"),
            Err(error) => {
                eprintln!("AMCP event acknowledgement unavailable; will replay safely: {error:#}")
            }
        }
    }
    let replayed = match client
        .request(
            RequestMethod::ReplayCollection {
                provider_id: provider_id.clone(),
                limit: 8,
            },
            &token,
        )
        .await
    {
        Ok(ResponsePayload::CollectionReplay { batches, .. }) => {
            let mut count = 0usize;
            for replay in batches {
                if replay.host.host_id != registered_host.host_id {
                    continue;
                }
                catalog.ingest(&replay)?;
                catalog.save_cursor(
                    &replay.host.host_id,
                    &provider_id,
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
    let cursor = catalog.latest_cursor(&registered_host.host_id, &provider_id)?;
    let batch = match client
        .request(
            RequestMethod::Collect {
                scope: if agent_url.is_some() {
                    Some(Scope {
                        host_id: None,
                        provider_id: Some(provider_id.clone()),
                        project_id: None,
                    })
                } else {
                    Some(Scope {
                        host_id: Some(host_id_from_env()),
                        provider_id: Some(provider_id.clone()),
                        project_id: None,
                    })
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

    let inserted = catalog.ingest(&batch)?;
    catalog.save_cursor(
        &batch.host.host_id,
        &provider_id,
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
                "provider_id": provider_id,
                "collection_run_id": batch.collection_run_id,
                "discovered": batch.artifacts.len(),
                "inserted": inserted,
                "replayed": replayed,
                "replayed_events": replayed_events,
                "persisted_events": persisted_events,
                "search": search_results.as_ref().map(|hits| hits.iter().map(|hit| serde_json::json!({"title": hit.title, "source": hit.source_reference, "preview": hit.preview})).collect::<Vec<_>>())
            })
        );
    } else {
        println!(
            "Collected {} {} artifacts ({} new) into {}",
            batch.artifacts.len(),
            provider_id,
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
    provider_id: String,
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
                provider_id.clone(),
                None,
                true,
                interval_seconds.saturating_mul(1_000).min(30_000),
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

async fn stream_events(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    max_in_flight: usize,
    heartbeat_ms: u64,
    duration_seconds: u64,
    provider_id: Option<String>,
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
    let result = async {
        let stream = connect_with_retry(
            &socket,
            agent_url.as_deref(),
            tls_ca.as_deref(),
            tls_server_name.as_deref(),
        )
        .await
        .context("connect to AMCP Agent event stream")?;
        let mut client = AgentClient::new(stream);
        let (host, agent_version, capabilities, provider_descriptors) =
            register_and_refresh(&mut client, &token).await?;
        let mut catalog = CatalogService::open(&db)?;
        let endpoint = agent_url
            .clone()
            .unwrap_or_else(|| format!("unix://{}", socket.display()));
        catalog.register_connection(&host, Some(&endpoint), Some(&agent_version), &capabilities)?;
        catalog.register_provider_descriptors(&host, &provider_descriptors)?;
        let stream_scope = Scope {
            host_id: Some(host.host_id.clone()),
            provider_id: provider_id.clone(),
            project_id: None,
        };
        let opened = client
            .request(
                RequestMethod::OpenEventStream {
                    after_event_id: None,
                    scope: Some(stream_scope),
                    max_in_flight: max_in_flight.clamp(1, 64),
                    heartbeat_ms: heartbeat_ms.clamp(250, 30_000),
                },
                &token,
            )
            .await?;
        let (stream_id, negotiated_max_in_flight, negotiated_heartbeat_ms) = match opened {
            ResponsePayload::EventStreamOpened {
                stream_id,
                max_in_flight,
                heartbeat_ms,
            } => (stream_id, max_in_flight, heartbeat_ms),
            other => bail!("Agent returned unexpected event stream response: {other:?}"),
        };
        let deadline = Instant::now() + StdDuration::from_secs(duration_seconds);
        let mut pages = 0usize;
        let mut heartbeats = 0usize;
        let mut received = 0usize;
        let mut persisted = 0usize;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            let response = match tokio::time::timeout(remaining, client.next_response()).await {
                Ok(response) => response?,
                Err(_) => break,
            };
            let payload = response
                .result
                .map_err(|error| anyhow::anyhow!("Agent {}: {}", error.code, error.message))?;
            match payload {
                ResponsePayload::EventStreamPage {
                    stream_id: page_stream_id,
                    events,
                    heartbeat,
                    ..
                } if page_stream_id == stream_id => {
                    pages += 1;
                    if heartbeat {
                        heartbeats += 1;
                        continue;
                    }
                    let events = events
                        .into_iter()
                        .filter(|event| event.host_id == host.host_id)
                        .collect::<Vec<_>>();
                    received += events.len();
                    let event_ids = events
                        .iter()
                        .map(|event| event.event_id.clone())
                        .collect::<Vec<_>>();
                    persisted += catalog.ingest_runtime_events(&events)?;
                    if !event_ids.is_empty() {
                        match client
                            .request(RequestMethod::AckEvents { event_ids }, &token)
                            .await?
                        {
                            ResponsePayload::RuntimeEventsAcked(_) => {}
                            other => {
                                bail!("Agent returned unexpected event ACK response: {other:?}")
                            }
                        }
                    }
                }
                ResponsePayload::EventStreamClosed { .. } => break,
                other => bail!("Agent returned unexpected event stream frame: {other:?}"),
            }
        }
        let _ = client
            .request(RequestMethod::CloseEventStream { stream_id }, &token)
            .await;
        Ok::<_, anyhow::Error>(serde_json::json!({
            "host_id": host.host_id,
            "max_in_flight": negotiated_max_in_flight,
            "heartbeat_ms": negotiated_heartbeat_ms,
            "pages": pages,
            "heartbeats": heartbeats,
            "received": received,
            "persisted": persisted,
        }))
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let summary = result?;
    if json {
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        println!(
            "AMCP event stream received {} event(s), persisted {}",
            summary["received"], summary["persisted"]
        );
    }
    Ok(())
}

async fn runtime_list(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    provider_id: String,
    limit: usize,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
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
        .await
        .context("connect to AMCP Agent")?;
        let mut client = AgentClient::new(stream);
        let (host, _, _, _) = register_and_refresh(&mut client, &token).await?;
        let response = client
            .request(
                RequestMethod::RuntimeListThreads {
                    provider_id,
                    scope: Some(Scope::host(host.host_id.clone())),
                    cursor: None,
                    limit: limit.clamp(1, 64),
                },
                &token,
            )
            .await?;
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        Ok::<_, anyhow::Error>((host, response))
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let (host, response) = result?;
    let threads = match response {
        ResponsePayload::RuntimeThreadPage { threads, .. } => threads,
        other => bail!("Agent returned unexpected runtime response: {other:?}"),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({"host_id": host.host_id, "threads": threads})
        );
    } else {
        println!("Live Codex threads on {}:", host.host_id);
        for thread in threads {
            println!(
                "- {} — {} [{}]",
                thread.thread_id,
                thread.title.unwrap_or_else(|| "untitled".into()),
                thread.status.unwrap_or_else(|| "unknown".into())
            );
        }
    }
    Ok(())
}

async fn runtime_read(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    provider_id: String,
    thread_id: String,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
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
        .await
        .context("connect to AMCP Agent")?;
        let mut client = AgentClient::new(stream);
        let (host, _, _, _) = register_and_refresh(&mut client, &token).await?;
        let response = client
            .request(
                RequestMethod::RuntimeReadThread {
                    provider_id,
                    scope: Some(Scope::host(host.host_id.clone())),
                    thread_id,
                },
                &token,
            )
            .await?;
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        Ok::<_, anyhow::Error>((host, response))
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let (host, response) = result?;
    let snapshot = match response {
        ResponsePayload::RuntimeThreadSnapshot(snapshot) => snapshot,
        other => bail!("Agent returned unexpected runtime read response: {other:?}"),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({"host_id": host.host_id, "snapshot": snapshot})
        );
    } else {
        println!(
            "Live {} thread {}: {} item(s), kinds={:?}, roles={:?}",
            snapshot.thread.provider_id,
            snapshot.thread.thread_id,
            snapshot.item_count,
            snapshot.item_kinds,
            snapshot.item_roles
        );
    }
    Ok(())
}

async fn runtime_propose(
    socket: PathBuf,
    agent_url: Option<String>,
    tls_ca: Option<PathBuf>,
    tls_server_name: Option<String>,
    token: String,
    codex_home: Option<PathBuf>,
    db: PathBuf,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    provider_id: String,
    archive: bool,
    unarchive: bool,
    thread_id: String,
    reason: String,
    json: bool,
) -> Result<()> {
    if archive == unarchive {
        bail!("exactly one of --archive or --unarchive is required");
    }
    let token = resolve_agent_token(&token);
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
        .await
        .context("connect to AMCP Agent")?;
        let mut client = AgentClient::new(stream);
        let (host, agent_version, capabilities, _) =
            register_and_refresh(&mut client, &token).await?;
        let operation = if archive {
            amcp_domain::ChangeOperationKind::RuntimeArchive
        } else {
            amcp_domain::ChangeOperationKind::RuntimeUnarchive
        };
        let request = ChangeRequest {
            actor: "human-or-controller".into(),
            scope: Scope {
                host_id: Some(host.host_id.clone()),
                provider_id: Some(provider_id.clone()),
                project_id: None,
            },
            target: ArtifactRef {
                host_id: host.host_id.clone(),
                provider_id: provider_id.clone(),
                native_id: thread_id.clone(),
                source_reference: format!("codex://thread/{thread_id}"),
            },
            expected_source_hash: None,
            operation,
            replacement_content: None,
            reason,
            evidence_ids: Vec::new(),
        };
        let change_set = match client
            .request(
                RequestMethod::RuntimeProposeThreadChange { request },
                &token,
            )
            .await?
        {
            ResponsePayload::ChangeSet(change_set) => change_set,
            other => bail!("Agent returned unexpected runtime proposal response: {other:?}"),
        };
        let mut catalog = CatalogService::open(&db)?;
        let endpoint = agent_url
            .clone()
            .unwrap_or_else(|| format!("unix://{}", socket.display()));
        catalog.register_connection(&host, Some(&endpoint), Some(&agent_version), &capabilities)?;
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
            "Proposed runtime {} with {} operation(s): {}",
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
        let (agent_version, capabilities, provider_descriptors) = match client
            .request(RequestMethod::Capabilities, &credential)
            .await?
        {
            ResponsePayload::Capabilities {
                agent_version,
                capabilities,
                provider_descriptors,
                ..
            } => (agent_version, capabilities, provider_descriptors),
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
        catalog.register_provider_descriptors(&host, &provider_descriptors)?;
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

fn rebuild_index(db: PathBuf, batch_size: usize, json: bool) -> Result<()> {
    let mut catalog = CatalogService::open(&db)?;
    let run = catalog.rebuild_search_projection(batch_size)?;
    if json {
        println!("{}", serde_json::to_string(&run)?);
    } else {
        println!(
            "Rebuilt search projection: {} artifact(s), run {}",
            run.indexed_count, run.run_id
        );
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
        let (registered_host, agent_version, capabilities, _provider_descriptors) =
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
        let runtime_change = change_set.operations.iter().any(|operation| {
            matches!(
                operation.operation,
                amcp_domain::ChangeOperationKind::RuntimeArchive
                    | amcp_domain::ChangeOperationKind::RuntimeUnarchive
            )
        });
        let receipt = match client
            .request(
                if runtime_change {
                    RequestMethod::RuntimeApplyThreadChange {
                        change_set: change_set.clone(),
                        approval,
                    }
                } else {
                    RequestMethod::ApplyChange {
                        change_set: change_set.clone(),
                        approval,
                    }
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
    command.spawn().context("start AMCP Agent")
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
    command.spawn().context("start AMCP Agent for enrollment")
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
    pending: VecDeque<ResponseEnvelope>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AgentClient<S> {
    fn new(stream: S) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(reader).lines(),
            writer,
            pending: VecDeque::new(),
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
        let request_id = self.send_request(request).await?;
        let mut unrelated = VecDeque::new();
        loop {
            let response = self.next_response().await?;
            if response.request_id == request_id {
                while let Some(response) = unrelated.pop_front() {
                    self.pending.push_back(response);
                }
                return response
                    .result
                    .map_err(|error| anyhow::anyhow!("Agent {}: {}", error.code, error.message));
            }
            unrelated.push_back(response);
        }
    }

    async fn send_request(&mut self, request: RequestEnvelope) -> Result<String> {
        let request_id = request.request_id.clone();
        let encoded = serde_json::to_string(&request)?;
        self.writer.write_all(encoded.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(request_id)
    }

    async fn next_response(&mut self) -> Result<ResponseEnvelope> {
        if let Some(response) = self.pending.pop_front() {
            return Ok(response);
        }
        let line = self
            .reader
            .next_line()
            .await?
            .context("Agent closed connection")?;
        let response: ResponseEnvelope = serde_json::from_str(&line)?;
        Ok(response)
    }
}

async fn register_and_refresh<S>(
    client: &mut AgentClient<S>,
    token: &str,
) -> Result<(HostIdentity, String, Vec<String>, Vec<ProviderDescriptor>)>
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
    let (agent_version, capabilities, provider_descriptors) =
        match client.request(RequestMethod::Capabilities, token).await? {
            ResponsePayload::Capabilities {
                agent_version,
                capabilities,
                provider_descriptors,
                ..
            } => (agent_version, capabilities, provider_descriptors),
            other => bail!("Agent returned unexpected capabilities response: {other:?}"),
        };
    match client.request(RequestMethod::Heartbeat, token).await? {
        ResponsePayload::Heartbeat { healthy: true, .. } => {}
        ResponsePayload::Heartbeat { healthy: false, .. } => {
            bail!("Agent heartbeat reported an unhealthy host")
        }
        other => bail!("Agent returned unexpected heartbeat response: {other:?}"),
    }
    Ok((host, agent_version, capabilities, provider_descriptors))
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
