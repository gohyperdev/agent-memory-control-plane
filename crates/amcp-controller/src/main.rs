#![allow(clippy::too_many_arguments)]

use amcp_core::CatalogService;
use amcp_domain::{
    ApprovalEnvelope, ArtifactRef, AuditEvent, ChangeRequest, ChangeStatus, HostIdentity,
    ProviderCompatibility, ProviderDescriptor, ProviderHealth, Scope, SensitivityClass,
    change_set_operations_hash, new_id,
};
use amcp_platform::{
    SecretStore, credential_store_for_account, default_agent_socket_path,
    default_controller_db_path, keychain_account_for_host,
};
use amcp_protocol::{
    PROTOCOL_VERSION, RequestEnvelope, RequestMethod, ResponseEnvelope, ResponsePayload,
};
use amcp_rag::{
    LexicalRagManager, PersistentRagIndex, RagConfig, RagDocument, RagEvaluationCase, RagManager,
};
use amcp_storage::CollectionRunRecord;
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
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
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::TcpStream,
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
        #[arg(long, default_value = "all", env = "AMCP_PROVIDER_ID")]
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
        #[arg(long, default_value = "all", env = "AMCP_PROVIDER_ID")]
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
    /// Measure the central FTS search path against an existing AMCP catalog.
    /// The result contains aggregate timing/count metadata only; the query,
    /// previews and artifact identifiers are never printed.
    BenchmarkSearch {
        query: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 25)]
        iterations: usize,
        #[arg(long, default_value_t = 3)]
        warmup: usize,
        /// Fail after emitting the receipt when p95 exceeds this value.
        #[arg(long)]
        assert_p95_ms: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Search the local Agent's already-redacted cache without requiring the
    /// Controller catalog. This is intended for local/offline operation only.
    LocalSearch {
        #[arg(
            long,
            default_value_os_t = default_agent_socket_path(),
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
        agent_bin: Option<PathBuf>,
        #[arg(long)]
        no_start_agent: bool,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        provider_id: Option<String>,
        #[arg(long)]
        project_id: Option<String>,
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    RebuildIndex {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 256)]
        batch_size: usize,
        #[arg(long)]
        json: bool,
    },
    /// Create a private, consistent snapshot of the central AMCP catalog.
    Backup {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value = "user-request")]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    RagStatus {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    RagClear {
        #[arg(long)]
        db: Option<PathBuf>,
        /// Required acknowledgement because this removes the complete
        /// derived RAG projection and retrieval audit history.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Evaluate a redacted RAG corpus through the production lexical retrieval
    /// path. It neither enables RAG for normal requests nor opens provider
    /// files, sends network traffic, or persists retrieval history.
    RagEvaluate {
        #[arg(long, default_value = "fixtures/rag/retrieval-evaluation.json")]
        fixture: PathBuf,
        #[arg(long, default_value_t = 3)]
        limit: usize,
        #[arg(long, default_value_t = 10_000)]
        min_citation_coverage_bps: u16,
        #[arg(long, default_value_t = 10_000)]
        min_expected_recall_bps: u16,
        #[arg(long, default_value_t = 0)]
        max_forbidden_record_hits: usize,
        /// Exit unsuccessfully if the supplied targets are not met.
        #[arg(long)]
        assert_targets: bool,
        #[arg(long)]
        json: bool,
    },
    ReadArtifact {
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
        host_id: Option<String>,
        #[arg(long)]
        source: String,
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
        #[arg(long, default_value = "codex", env = "AMCP_PROVIDER_ID")]
        provider_id: String,
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
    Diagnostics {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Report only the locally observable Codex catalog readiness checks.
    /// It never certifies external host, signing, or native-platform evidence.
    Readiness {
        #[arg(long)]
        db: Option<PathBuf>,
        /// Exit unsuccessfully unless all local Codex catalog checks pass.
        #[arg(long)]
        assert_local_codex: bool,
        #[arg(long)]
        json: bool,
    },
    AuditList {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        provider_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
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
        CommandKind::BenchmarkSearch {
            query,
            db,
            limit,
            iterations,
            warmup,
            assert_p95_ms,
            json,
        } => benchmark_search(
            db.unwrap_or_else(default_db_path),
            query,
            limit,
            iterations,
            warmup,
            assert_p95_ms,
            json,
        ),
        CommandKind::LocalSearch {
            socket,
            token,
            codex_home,
            agent_bin,
            no_start_agent,
            host_id,
            provider_id,
            project_id,
            query,
            limit,
            json,
        } => {
            local_search(
                socket,
                token,
                codex_home,
                agent_bin,
                no_start_agent,
                host_id,
                provider_id,
                project_id,
                query,
                limit,
                json,
            )
            .await
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
            provider_id,
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
                provider_id,
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
        CommandKind::Diagnostics { db, json } => {
            diagnostics(db.unwrap_or_else(default_db_path), json)
        }
        CommandKind::Readiness {
            db,
            assert_local_codex,
            json,
        } => readiness(db.unwrap_or_else(default_db_path), assert_local_codex, json),
        CommandKind::AuditList {
            db,
            host_id,
            provider_id,
            limit,
            json,
        } => list_audit_events(
            db.unwrap_or_else(default_db_path),
            host_id.as_deref(),
            provider_id.as_deref(),
            limit,
            json,
        ),
        CommandKind::RebuildIndex {
            db,
            batch_size,
            json,
        } => rebuild_index(db.unwrap_or_else(default_db_path), batch_size, json),
        CommandKind::Backup { db, reason, json } => {
            backup_catalog(db.unwrap_or_else(default_db_path), reason, json)
        }
        CommandKind::RagStatus { db, json } => rag_status(db.unwrap_or_else(default_db_path), json),
        CommandKind::RagClear { db, yes, json } => {
            rag_clear(db.unwrap_or_else(default_db_path), yes, json)
        }
        CommandKind::RagEvaluate {
            fixture,
            limit,
            min_citation_coverage_bps,
            min_expected_recall_bps,
            max_forbidden_record_hits,
            assert_targets,
            json,
        } => rag_evaluate(
            fixture,
            limit,
            min_citation_coverage_bps,
            min_expected_recall_bps,
            max_forbidden_record_hits,
            assert_targets,
            json,
        ),
        CommandKind::ReadArtifact {
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
            host_id,
            source,
            json,
        } => {
            read_artifact(
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
                host_id,
                source,
                json,
            )
            .await
        }
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
        .unwrap_or_else(|| local_agent_endpoint(&socket));
    catalog.register_connection(
        &registered_host,
        Some(&endpoint),
        Some(&agent_version),
        &capabilities,
    )?;
    catalog.register_provider_descriptors(&registered_host, &provider_descriptors)?;
    let collection_provider_ids = collection_provider_ids(&provider_id, &provider_descriptors)?;
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
    let mut collections = Vec::new();
    let mut failed_providers = Vec::new();
    for collected_provider_id in &collection_provider_ids {
        let collection_started_at = Utc::now();
        let collection_started = Instant::now();
        let correlation_id = new_id("collection");
        let (replayed, replayed_discovered, replayed_inserted) = match client
            .request(
                RequestMethod::ReplayCollection {
                    provider_id: collected_provider_id.clone(),
                    limit: 8,
                },
                &token,
            )
            .await
        {
            Ok(ResponsePayload::CollectionReplay { batches, .. }) => {
                let mut replayed_batches = 0usize;
                let mut discovered = 0usize;
                let mut inserted = 0usize;
                for replay in batches {
                    if replay.host.host_id != registered_host.host_id {
                        continue;
                    }
                    discovered += replay.artifacts.len();
                    inserted += catalog.ingest(&replay)?;
                    catalog.save_cursor(
                        &replay.host.host_id,
                        collected_provider_id,
                        replay
                            .next_cursor
                            .as_deref()
                            .or(Some(replay.collection_run_id.as_str())),
                        &replay.collection_run_id,
                    )?;
                    replayed_batches += 1;
                }
                (replayed_batches, discovered, inserted)
            }
            Ok(_) => (0, 0, 0),
            Err(_) => {
                eprintln!(
                    "AMCP replay unavailable for {collected_provider_id}; continuing with live collection"
                );
                (0, 0, 0)
            }
        };
        if replayed > 0 {
            catalog.record_collection_run(&CollectionRunRecord {
                collection_run_id: new_id("collection-replay"),
                host_id: registered_host.host_id.clone(),
                provider_id: collected_provider_id.clone(),
                request_id: None,
                correlation_id: correlation_id.clone(),
                status: "replayed".to_owned(),
                failure_kind: None,
                started_at: collection_started_at,
                completed_at: Utc::now(),
                duration_ms: collection_started
                    .elapsed()
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                discovered_count: replayed_discovered,
                inserted_count: replayed_inserted,
                replayed_batch_count: replayed,
            })?;
        }
        let cursor = catalog.latest_cursor(&registered_host.host_id, collected_provider_id)?;
        let collection_result = client
            .request_traced(
                RequestMethod::Collect {
                    scope: Some(Scope {
                        host_id: Some(registered_host.host_id.clone()),
                        provider_id: Some(collected_provider_id.clone()),
                        project_id: None,
                    }),
                    cursor,
                },
                &token,
            )
            .await;
        let (request_id, batch) = match collection_result {
            Ok((request_id, ResponsePayload::Collection(batch)))
                if batch.host.host_id == registered_host.host_id =>
            {
                (Some(request_id), batch)
            }
            Ok((request_id, ResponsePayload::Collection(_))) => {
                catalog.set_provider_health(
                    &registered_host.host_id,
                    collected_provider_id,
                    ProviderHealth::Degraded,
                )?;
                record_collection_attempt(
                    &mut catalog,
                    &registered_host.host_id,
                    collected_provider_id,
                    new_id("collection-attempt"),
                    Some(request_id),
                    correlation_id,
                    "invalid_host_scope",
                    collection_started_at,
                    collection_started.elapsed(),
                    replayed,
                )?;
                failed_providers.push(provider_collection_failure(
                    collected_provider_id,
                    "invalid_host_scope",
                ));
                continue;
            }
            Ok((request_id, _)) => {
                catalog.set_provider_health(
                    &registered_host.host_id,
                    collected_provider_id,
                    ProviderHealth::Degraded,
                )?;
                record_collection_attempt(
                    &mut catalog,
                    &registered_host.host_id,
                    collected_provider_id,
                    new_id("collection-attempt"),
                    Some(request_id),
                    correlation_id,
                    "unexpected_collection_response",
                    collection_started_at,
                    collection_started.elapsed(),
                    replayed,
                )?;
                failed_providers.push(provider_collection_failure(
                    collected_provider_id,
                    "unexpected_collection_response",
                ));
                continue;
            }
            Err(_) => {
                catalog.set_provider_health(
                    &registered_host.host_id,
                    collected_provider_id,
                    ProviderHealth::Degraded,
                )?;
                record_collection_attempt(
                    &mut catalog,
                    &registered_host.host_id,
                    collected_provider_id,
                    new_id("collection-attempt"),
                    None,
                    correlation_id,
                    "collection_failed",
                    collection_started_at,
                    collection_started.elapsed(),
                    replayed,
                )?;
                failed_providers.push(provider_collection_failure(
                    collected_provider_id,
                    "collection_failed",
                ));
                continue;
            }
        };

        let live_inserted = catalog.ingest(&batch)?;
        let discovered = replayed_discovered + batch.artifacts.len();
        let inserted = replayed_inserted + live_inserted;
        catalog.save_cursor(
            &batch.host.host_id,
            collected_provider_id,
            batch
                .next_cursor
                .as_deref()
                .or(Some(batch.collection_run_id.as_str())),
            &batch.collection_run_id,
        )?;
        let duration_ms = collection_started
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        catalog.record_collection_run(&CollectionRunRecord {
            collection_run_id: new_id("collection-attempt"),
            host_id: batch.host.host_id.clone(),
            provider_id: collected_provider_id.clone(),
            request_id,
            correlation_id,
            status: "completed".to_owned(),
            failure_kind: None,
            started_at: collection_started_at,
            completed_at: Utc::now(),
            duration_ms,
            discovered_count: batch.artifacts.len(),
            inserted_count: live_inserted,
            replayed_batch_count: replayed,
        })?;
        collections.push((
            collected_provider_id.clone(),
            batch,
            discovered,
            inserted,
            replayed,
            duration_ms,
        ));
    }
    if collections.is_empty() {
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        if let Some(mut child) = child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        bail!(
            "AMCP could not collect any selected provider: {}",
            failed_providers
                .iter()
                .map(|failure| failure["provider_id"].as_str().unwrap_or("unknown"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let search_results = query
        .as_deref()
        .map(|value| catalog.search(value, 20))
        .transpose()?;
    if let Some(results) = &search_results {
        catalog.audit_sensitive_search_results("controller.run_once", results)?;
    }

    if json {
        let search_payload = search_results.as_ref().map(|hits| {
            hits.iter()
                .map(|hit| {
                    serde_json::json!({"title": hit.title, "source": hit.source_reference, "preview": hit.preview})
                })
                .collect::<Vec<_>>()
        });
        if collections.len() == 1 && failed_providers.is_empty() {
            let (collected_provider_id, batch, discovered, inserted, replayed, duration_ms) =
                &collections[0];
            println!(
                "{}",
                serde_json::json!({
                    "host_id": batch.host.host_id,
                    "provider_id": collected_provider_id,
                    "collection_run_id": batch.collection_run_id,
                    "discovered": discovered,
                    "inserted": inserted,
                    "replayed": replayed,
                    "duration_ms": duration_ms,
                    "replayed_events": replayed_events,
                    "persisted_events": persisted_events,
                    "search": search_payload
                })
            );
        } else {
            println!(
                "{}",
                serde_json::json!({
                    "host_id": registered_host.host_id,
                    "provider_selector": provider_id,
                    "collections": collections.iter().map(|(collected_provider_id, batch, discovered, inserted, replayed, duration_ms)| serde_json::json!({
                        "provider_id": collected_provider_id,
                        "collection_run_id": batch.collection_run_id,
                        "discovered": discovered,
                        "inserted": inserted,
                        "replayed": replayed,
                        "duration_ms": duration_ms,
                    })).collect::<Vec<_>>(),
                    "failed_providers": failed_providers,
                    "replayed_events": replayed_events,
                    "persisted_events": persisted_events,
                    "search": search_payload
                })
            );
        }
    } else {
        for (collected_provider_id, batch, discovered, inserted, _, duration_ms) in &collections {
            println!(
                "Collected {} {} artifacts ({} new) into {} in {} ms",
                discovered,
                collected_provider_id,
                inserted,
                db.display(),
                duration_ms,
            );
            for artifact in batch.artifacts.iter().take(20) {
                println!("- {} [{}]", artifact.source_reference, artifact.title);
            }
        }
        for failure in &failed_providers {
            eprintln!(
                "AMCP collection failed for {}: {}",
                failure["provider_id"].as_str().unwrap_or("unknown"),
                failure["reason"].as_str().unwrap_or("unknown failure")
            );
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
            .unwrap_or_else(|| local_agent_endpoint(&socket));
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
            .unwrap_or_else(|| local_agent_endpoint(&socket));
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
        ensure_agent_binary_compatibility(&agent_version)?;
        match client
            .request(RequestMethod::Heartbeat, &credential)
            .await?
        {
            ResponsePayload::Heartbeat { healthy: true, .. } => {}
            other => bail!("Agent returned unexpected heartbeat response: {other:?}"),
        }
        credential_store_for_account(keychain_account_for_host(&host.host_id))
            .context("resolve credential store for enrollment")?
            .set(&credential)?;
        let endpoint = agent_url
            .clone()
            .unwrap_or_else(|| local_agent_endpoint(&socket));
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
    let mut catalog = CatalogService::open(&db)?;
    let hits = catalog.search(&query, limit)?;
    catalog.audit_sensitive_search_results("controller.cli", &hits)?;
    for hit in hits {
        println!("{}\t{}\t{}", hit.title, hit.source_reference, hit.preview);
    }
    Ok(())
}

fn benchmark_search(
    db: PathBuf,
    query: String,
    limit: usize,
    iterations: usize,
    warmup: usize,
    assert_p95_ms: Option<u64>,
    json: bool,
) -> Result<()> {
    if query.trim().is_empty() {
        bail!("benchmark query must not be empty");
    }
    if !(1..=100).contains(&iterations) {
        bail!("benchmark iterations must be between 1 and 100");
    }
    if warmup > 20 {
        bail!("benchmark warmup must be between 0 and 20");
    }

    let mut catalog = CatalogService::open(&db)?;
    for _ in 0..warmup {
        let _ = catalog.search(&query, limit)?;
    }

    let mut durations_ms = Vec::with_capacity(iterations);
    let mut result_count = 0usize;
    for _ in 0..iterations {
        let started = Instant::now();
        let hits = catalog.search(&query, limit)?;
        durations_ms.push(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
        result_count = hits.len();
    }
    durations_ms.sort_unstable();
    let p50_ms = percentile_ms(&durations_ms, 50).expect("benchmark has at least one sample");
    let p95_ms = percentile_ms(&durations_ms, 95).expect("benchmark has at least one sample");
    let max_ms = *durations_ms
        .last()
        .expect("benchmark has at least one sample");
    let target_p95_ms = assert_p95_ms.unwrap_or(300);
    let meets_target = p95_ms <= target_p95_ms;
    let receipt = serde_json::json!({
        "iterations": iterations,
        "warmup": warmup,
        "limit": limit.clamp(1, 200),
        "result_count": result_count,
        "p50_ms": p50_ms,
        "p95_ms": p95_ms,
        "max_ms": max_ms,
        "target_p95_ms": target_p95_ms,
        "meets_target": meets_target,
        "content_included": false,
        "search_metrics_recorded": true,
    });
    if json {
        println!("{}", serde_json::to_string(&receipt)?);
    } else {
        println!(
            "FTS benchmark: p50={p50_ms}ms p95={p95_ms}ms max={max_ms}ms; {result_count} result(s); target={target_p95_ms}ms"
        );
    }
    if assert_p95_ms.is_some() && !meets_target {
        bail!("FTS benchmark p95 exceeded the asserted target")
    }
    Ok(())
}

fn percentile_ms(sorted_samples: &[u64], percentile: usize) -> Option<u64> {
    if sorted_samples.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let rank = (sorted_samples.len() * percentile)
        .div_ceil(100)
        .saturating_sub(1);
    sorted_samples.get(rank).copied()
}

async fn local_search(
    socket: PathBuf,
    token: String,
    codex_home: Option<PathBuf>,
    agent_bin: Option<PathBuf>,
    no_start_agent: bool,
    requested_host_id: Option<String>,
    provider_id: Option<String>,
    project_id: Option<String>,
    query: String,
    limit: usize,
    json: bool,
) -> Result<()> {
    let token = resolve_agent_token(&token);
    let mut child = if no_start_agent {
        None
    } else {
        Some(start_agent(&socket, &token, codex_home.as_ref(), agent_bin).await?)
    };
    let result = async {
        let stream = connect_with_retry(&socket, None, None, None)
            .await
            .context("connect to local AMCP Agent")?;
        let mut client = AgentClient::new(stream);
        let (host, _, _, _) = register_and_refresh(&mut client, &token).await?;
        let host_id = requested_host_id.unwrap_or_else(|| host.host_id.clone());
        if host_id != host.host_id {
            bail!(
                "requested host scope {host_id} does not match connected Agent host {}",
                host.host_id
            );
        }
        let response = client
            .request(
                RequestMethod::SearchLocal {
                    query,
                    scope: Some(Scope {
                        host_id: Some(host_id),
                        provider_id,
                        project_id,
                    }),
                    limit,
                },
                &token,
            )
            .await?;
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        match response {
            ResponsePayload::LocalSearch {
                results,
                cache_available,
            } => Ok::<_, anyhow::Error>((results, cache_available)),
            other => bail!("Agent returned unexpected local-search response: {other:?}"),
        }
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let (results, cache_available) = result?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "results": results,
                "cache_available": cache_available,
                "redacted": true,
                "native_files_opened": false,
            }))?
        );
    } else if !cache_available {
        println!("No local AMCP cache is available for this scope.");
    } else if results.is_empty() {
        println!("No matching artifacts in the local AMCP cache.");
    } else {
        for result in results {
            println!(
                "{}\t{}\t{}\n{}",
                result.title, result.provider_id, result.source_reference, result.preview
            );
        }
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

fn backup_catalog(db: PathBuf, reason: String, json: bool) -> Result<()> {
    let receipt = CatalogService::open(&db)?.create_backup(&reason)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!(
            "Created AMCP catalog backup ({} bytes): {}",
            receipt.size_bytes,
            receipt.backup_path.display()
        );
    }
    Ok(())
}

fn diagnostics_snapshot(db: &Path) -> Result<serde_json::Value> {
    let catalog = CatalogService::open(db)?;
    let pending_change_count = catalog
        .list_change_sets(Some(ChangeStatus::Proposed))?
        .len();
    let recent_event_count = catalog.list_runtime_events(None, None, 20)?.len();
    Ok(serde_json::json!({
        "generated_at": Utc::now(),
        "hosts": catalog.list_hosts()?,
        "providers": catalog.list_providers(None)?,
        "latest_index_run": catalog.latest_index_run()?,
        "recent_collection_runs": catalog.list_collection_runs(None, None, 20)?,
        "recent_search_runs": catalog.list_search_runs(None, None, 20)?,
        "pending_change_count": pending_change_count,
        "recent_event_count": recent_event_count,
        "catalog_diagnostics": catalog.diagnostics()?,
        "rag": PersistentRagIndex::open(db)?.stats()?,
        "content_included": false
    }))
}

fn readiness(db: PathBuf, assert_local_codex: bool, json: bool) -> Result<()> {
    let snapshot = readiness_snapshot(&db)?;
    let local_codex_ready = snapshot["local_codex_ready"].as_bool().unwrap_or(false);
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        let checks = snapshot["checks"].as_array().map_or(&[][..], Vec::as_slice);
        let passed = checks
            .iter()
            .filter(|check| check["passed"].as_bool() == Some(true))
            .count();
        println!(
            "Local Codex catalog readiness: {passed}/{} checks passed; ready={local_codex_ready}. External release/host/platform acceptance is not included.",
            checks.len()
        );
    }
    if assert_local_codex && !local_codex_ready {
        bail!("local Codex catalog does not meet the asserted readiness checks")
    }
    Ok(())
}

fn readiness_snapshot(db: &Path) -> Result<serde_json::Value> {
    let catalog = CatalogService::open(db)?;
    let hosts = catalog.list_hosts()?;
    let providers = catalog.list_providers(None)?;
    let projects = catalog.list_projects(None)?;
    let diagnostics = catalog.diagnostics()?;
    let healthy_codex_provider_count = providers
        .iter()
        .filter(|provider| {
            provider.provider_id == "codex"
                && provider.health == ProviderHealth::Healthy
                && provider.compatibility == ProviderCompatibility::Compatible
        })
        .count();
    let codex_project_count = projects
        .iter()
        .filter(|project| project.provider_id == "codex")
        .map(|project| (&project.host_id, &project.project_id))
        .collect::<std::collections::HashSet<_>>()
        .len();
    let checks = vec![
        serde_json::json!({
            "id": "registered-host",
            "passed": !hosts.is_empty(),
            "observed_count": hosts.len(),
        }),
        serde_json::json!({
            "id": "healthy-compatible-codex-provider",
            "passed": healthy_codex_provider_count > 0,
            "observed_count": healthy_codex_provider_count,
        }),
        serde_json::json!({
            "id": "five-codex-project-roots",
            "passed": codex_project_count >= 5,
            "observed_count": codex_project_count,
            "required_count": 5,
        }),
        serde_json::json!({
            "id": "indexed-artifacts",
            "passed": diagnostics.total_artifact_count > 0,
            "observed_count": diagnostics.total_artifact_count,
        }),
        serde_json::json!({
            "id": "complete-fts-projection",
            "passed": diagnostics.total_artifact_count > 0 && diagnostics.search_index_coverage_ratio >= 1.0,
            "coverage_basis_points": (diagnostics.search_index_coverage_ratio * 10_000.0).round() as u16,
        }),
        serde_json::json!({
            "id": "no-stale-artifacts",
            "passed": diagnostics.stale_artifact_count == 0,
            "observed_count": diagnostics.stale_artifact_count,
        }),
    ];
    let local_codex_ready = checks
        .iter()
        .all(|check| check["passed"].as_bool() == Some(true));
    Ok(serde_json::json!({
        "local_codex_ready": local_codex_ready,
        "checks": checks,
        "external_verification_remaining": [
            "second physical host enrollment and reconnect",
            "human-reviewed non-fixture safe change",
            "Developer ID signing, notarization and Gatekeeper smoke",
            "native Linux and Windows lifecycle acceptance",
            "representative search and RAG quality corpora",
        ],
        "content_included": false,
        "native_provider_files_opened": false,
    }))
}

fn diagnostics(db: PathBuf, json: bool) -> Result<()> {
    let snapshot = diagnostics_snapshot(&db)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        let hosts = snapshot["hosts"].as_array().map_or(0, Vec::len);
        let providers = snapshot["providers"].as_array().map_or(0, Vec::len);
        let stale = snapshot["catalog_diagnostics"]["stale_artifact_count"]
            .as_u64()
            .unwrap_or(0);
        println!(
            "AMCP diagnostics: {hosts} host(s), {providers} provider(s), {stale} stale artifact(s). Use --json for bounded metadata."
        );
    }
    Ok(())
}

fn rag_status(db: PathBuf, json: bool) -> Result<()> {
    let index = PersistentRagIndex::open(&db)?;
    let stats = index.stats()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!(
            "RAG derived index: {} chunk(s), {} source(s), {} retrieval run(s)",
            stats.chunk_count, stats.source_count, stats.retrieval_run_count
        );
    }
    Ok(())
}

fn rag_clear(db: PathBuf, yes: bool, json: bool) -> Result<()> {
    if !yes {
        bail!("refusing to clear RAG derived data without --yes")
    }
    let mut index = PersistentRagIndex::open(&db)?;
    let receipt = index.clear_derived_data()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!(
            "Cleared RAG derived data: {} chunk(s), {} retrieval run(s)",
            receipt.deleted_chunks, receipt.deleted_retrieval_runs
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RagEvaluationFixture {
    documents: Vec<RagDocument>,
    cases: Vec<RagEvaluationCase>,
}

fn rag_evaluate(
    fixture_path: PathBuf,
    limit: usize,
    min_citation_coverage_bps: u16,
    min_expected_recall_bps: u16,
    max_forbidden_record_hits: usize,
    assert_targets: bool,
    json: bool,
) -> Result<()> {
    if !(1..=20).contains(&limit) {
        bail!("RAG evaluation limit must be between 1 and 20");
    }
    let fixture: RagEvaluationFixture = serde_json::from_slice(
        &std::fs::read(&fixture_path).context("read redacted RAG evaluation fixture")?,
    )
    .context("parse redacted RAG evaluation fixture")?;
    if fixture.cases.is_empty() {
        bail!("RAG evaluation fixture must contain at least one case");
    }
    let mut manager = LexicalRagManager::new(RagConfig {
        enabled: true,
        ..RagConfig::default()
    });
    let indexed_document_count = manager.index(&fixture.documents)?;
    let report = manager.evaluate(&fixture.cases, limit)?;
    let citation_coverage_bps =
        ratio_basis_points(report.citation_count, report.context_item_count);
    let expected_recall_bps =
        ratio_basis_points(report.expected_record_hits, report.expected_record_count);
    let meets_targets = citation_coverage_bps >= min_citation_coverage_bps
        && expected_recall_bps >= min_expected_recall_bps
        && report.forbidden_record_hits <= max_forbidden_record_hits;
    let receipt = serde_json::json!({
        "fixture_case_count": fixture.cases.len(),
        "indexed_document_count": indexed_document_count,
        "limit": limit,
        "citation_coverage_bps": citation_coverage_bps,
        "expected_recall_bps": expected_recall_bps,
        "forbidden_record_hits": report.forbidden_record_hits,
        "targets": {
            "min_citation_coverage_bps": min_citation_coverage_bps,
            "min_expected_recall_bps": min_expected_recall_bps,
            "max_forbidden_record_hits": max_forbidden_record_hits,
        },
        "meets_targets": meets_targets,
        "content_included": false,
        "native_provider_files_opened": false,
        "network_egress": false,
        "retrieval_history_persisted": false,
    });
    if json {
        println!("{}", serde_json::to_string(&receipt)?);
    } else {
        println!(
            "RAG evaluation: citation coverage={citation_coverage_bps}bps; expected recall={expected_recall_bps}bps; forbidden hits={}; targets met={meets_targets}",
            report.forbidden_record_hits
        );
    }
    if assert_targets && !meets_targets {
        bail!("RAG evaluation did not meet the asserted quality targets")
    }
    Ok(())
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 10_000;
    }
    ((numerator.saturating_mul(10_000) / denominator).min(10_000)) as u16
}

async fn read_artifact(
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
    requested_host_id: Option<String>,
    source: String,
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
        let host_id = requested_host_id.unwrap_or_else(|| host.host_id.clone());
        if host_id != host.host_id {
            bail!(
                "requested host scope {host_id} does not match connected Agent host {}",
                host.host_id
            );
        }
        let response = client
            .request(
                RequestMethod::ReadArtifact {
                    target: ArtifactRef {
                        host_id: host_id.clone(),
                        provider_id: provider_id.clone(),
                        native_id: source.clone(),
                        source_reference: source.clone(),
                    },
                    redacted: true,
                },
                &token,
            )
            .await?;
        let _ = client.request(RequestMethod::Shutdown, &token).await;
        match response {
            ResponsePayload::Artifact(artifact) => Ok::<_, anyhow::Error>(artifact),
            other => bail!("Agent returned unexpected artifact response: {other:?}"),
        }
    }
    .await;
    if let Some(mut child) = child.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let artifact = result?;
    record_sensitive_read_audit(
        &db,
        &artifact.sensitivity,
        &artifact.source_reference,
        &artifact.host_id,
        &artifact.provider_id,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&artifact)?);
    } else {
        println!(
            "{} [{}] {}",
            artifact.title, artifact.provider_id, artifact.source_reference
        );
        println!("{}", artifact.content);
    }
    Ok(())
}

fn record_sensitive_read_audit(
    database: &Path,
    sensitivity: &SensitivityClass,
    source_reference: &str,
    host_id: &str,
    provider_id: &str,
) -> Result<()> {
    if !matches!(
        sensitivity,
        SensitivityClass::Sensitive | SensitivityClass::SecretLike
    ) {
        return Ok(());
    }
    let mut catalog = CatalogService::open(database)?;
    catalog.record_audit(&AuditEvent {
        audit_event_id: new_id("audit"),
        actor: "controller".to_owned(),
        operation: "artifact.read_sensitive".to_owned(),
        target: source_reference.to_owned(),
        host_id: Some(host_id.to_owned()),
        provider_id: Some(provider_id.to_owned()),
        before_hash: None,
        after_hash: None,
        result: "redacted artifact returned".to_owned(),
        correlation_id: new_id("correlation"),
        timestamp: Utc::now(),
    })?;
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
    provider_id: String,
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
                provider_id,
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
            .unwrap_or_else(|| local_agent_endpoint(&socket));
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

fn list_audit_events(
    db: PathBuf,
    host_id: Option<&str>,
    provider_id: Option<&str>,
    limit: usize,
    json: bool,
) -> Result<()> {
    let events = CatalogService::open(&db)?.list_audit_events(host_id, provider_id, limit)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&events)?);
    } else {
        for event in events {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                event.timestamp.to_rfc3339(),
                event.operation,
                event.host_id.as_deref().unwrap_or("controller"),
                event.provider_id.as_deref().unwrap_or("—"),
                event.result,
            );
        }
    }
    Ok(())
}

fn store_keychain_credential(host_id: &str, token: &str) -> Result<()> {
    credential_store_for_account(keychain_account_for_host(host_id))
        .context("resolve credential store")?
        .set(token)?;
    println!(
        "Stored AMCP Agent credential for {host_id} in the configured platform credential store"
    );
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

#[cfg(unix)]
fn local_agent_endpoint(socket: &Path) -> String {
    format!("unix://{}", socket.display())
}

#[cfg(target_os = "windows")]
fn local_agent_endpoint(socket: &Path) -> String {
    format!("npipe://{}", socket.display())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn local_agent_endpoint(socket: &Path) -> String {
    format!("local://{}", socket.display())
}

#[cfg(unix)]
async fn connect_local_agent(socket: &Path) -> Result<DynAgentStream> {
    UnixStream::connect(socket)
        .await
        .map(|stream| Box::new(stream) as DynAgentStream)
        .context("connect to AMCP Unix socket")
}

#[cfg(target_os = "windows")]
async fn connect_local_agent(socket: &Path) -> Result<DynAgentStream> {
    let pipe_name = socket
        .to_str()
        .context("AMCP Windows named-pipe name must be valid Unicode")?;
    if !pipe_name.starts_with(r"\\.\pipe\") {
        bail!("AMCP Windows local IPC requires a \\\\.\\pipe\\ name");
    }
    ClientOptions::new()
        .open(pipe_name)
        .map(|stream| Box::new(stream) as DynAgentStream)
        .with_context(|| format!("connect to AMCP Windows named pipe {pipe_name}"))
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn connect_local_agent(_socket: &Path) -> Result<DynAgentStream> {
    bail!("AMCP local IPC is not implemented for this platform")
}

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
        match connect_local_agent(socket).await {
            Ok(stream) => return Ok(stream),
            Err(_) => sleep(StdDuration::from_millis(100)).await,
        }
    }
    bail!(
        "Agent socket did not become available: {}",
        socket.display()
    )
}

fn load_tls_connector(ca_path: &Path) -> Result<TlsConnector> {
    ensure_rustls_crypto_provider();
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

/// The workspace can enable both ring and aws-lc through independent
/// dependencies, so Controller TLS must choose the same explicit provider
/// before building a client configuration.
fn ensure_rustls_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

    async fn request_traced(
        &mut self,
        method: RequestMethod,
        token: &str,
    ) -> Result<(String, ResponsePayload)> {
        self.request_with_auth_traced(method, Some(token), None)
            .await
    }

    async fn request_with_auth(
        &mut self,
        method: RequestMethod,
        token: Option<&str>,
        pairing_code: Option<&str>,
    ) -> Result<ResponsePayload> {
        self.request_with_auth_traced(method, token, pairing_code)
            .await
            .map(|(_, response)| response)
    }

    async fn request_with_auth_traced(
        &mut self,
        method: RequestMethod,
        token: Option<&str>,
        pairing_code: Option<&str>,
    ) -> Result<(String, ResponsePayload)> {
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
                    .map(|result| (request_id, result))
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
        ensure_agent_protocol_compatibility(response.protocol_version)?;
        Ok(response)
    }
}

fn ensure_agent_protocol_compatibility(agent_protocol_version: u32) -> Result<()> {
    if agent_protocol_version != PROTOCOL_VERSION {
        bail!(
            "incompatible AMCP Agent protocol version {agent_protocol_version}; Controller requires {PROTOCOL_VERSION}"
        );
    }
    Ok(())
}

/// The wire protocol is checked per response; this guards the separately
/// versioned Agent binary before Controller starts using its capabilities. A
/// patch-level difference is safe within one release line, whereas a minor or
/// major difference can change provider contracts and lifecycle semantics.
fn ensure_agent_binary_compatibility(agent_version: &str) -> Result<()> {
    let controller_version = env!("CARGO_PKG_VERSION");
    let controller_release = release_line(controller_version).ok_or_else(|| {
        anyhow::anyhow!("Controller has an invalid package version {controller_version}")
    })?;
    let agent_release = release_line(agent_version).ok_or_else(|| {
        anyhow::anyhow!("Agent reported an invalid binary version {agent_version:?}")
    })?;
    if controller_release != agent_release {
        bail!(
            "incompatible AMCP Agent binary version {agent_version}; Controller {controller_version} requires release line {}.{}",
            controller_release.0,
            controller_release.1,
        );
    }
    Ok(())
}

fn release_line(version: &str) -> Option<(u64, u64)> {
    let core = version
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    (parts.next().is_none()).then_some((major, minor))
}

fn collection_provider_ids(
    requested_provider_id: &str,
    descriptors: &[ProviderDescriptor],
) -> Result<Vec<String>> {
    let mut available = descriptors
        .iter()
        .map(|descriptor| descriptor.id.clone())
        .filter(|provider_id| !provider_id.trim().is_empty())
        .collect::<Vec<_>>();
    available.sort();
    available.dedup();
    if requested_provider_id == "all" {
        if available.is_empty() {
            bail!("Agent did not report any providers for collection");
        }
        return Ok(available);
    }
    if available
        .iter()
        .any(|provider_id| provider_id == requested_provider_id)
    {
        return Ok(vec![requested_provider_id.to_owned()]);
    }
    bail!(
        "requested provider {requested_provider_id:?} is not registered by this Agent; available: {}",
        available.join(", ")
    )
}

fn provider_collection_failure(provider_id: &str, classification: &str) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "reason": classification,
        "content_included": false,
    })
}

fn record_collection_attempt(
    catalog: &mut CatalogService,
    host_id: &str,
    provider_id: &str,
    collection_run_id: String,
    request_id: Option<String>,
    correlation_id: String,
    failure_kind: &str,
    started_at: chrono::DateTime<Utc>,
    elapsed: StdDuration,
    replayed_batch_count: usize,
) -> Result<()> {
    catalog.record_collection_run(&CollectionRunRecord {
        collection_run_id,
        host_id: host_id.to_owned(),
        provider_id: provider_id.to_owned(),
        request_id,
        correlation_id,
        status: "failed".to_owned(),
        failure_kind: Some(failure_kind.to_owned()),
        started_at,
        completed_at: Utc::now(),
        duration_ms: elapsed.as_millis().min(u64::MAX as u128) as u64,
        discovered_count: 0,
        inserted_count: 0,
        replayed_batch_count,
    })
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
    ensure_agent_binary_compatibility(&agent_version)?;
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
        .unwrap_or_else(default_controller_db_path)
}

fn agent_executable_name() -> &'static str {
    if cfg!(windows) {
        "amcp-agent.exe"
    } else {
        "amcp-agent"
    }
}

fn bundled_agent_binary(controller_executable: &Path) -> Option<PathBuf> {
    controller_executable
        .parent()
        .map(|parent| parent.join(agent_executable_name()))
}

fn default_agent_binary() -> PathBuf {
    env::var_os("AMCP_AGENT_BIN")
        .map(PathBuf::from)
        .or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| bundled_agent_binary(&path))
        })
        .unwrap_or_else(|| PathBuf::from(agent_executable_name()))
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
    credential_store_for_account(account)
        .ok()
        .and_then(|store| store.get().ok().flatten())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcp_domain::{ArtifactKind, LifecycleState};
    use amcp_storage::SearchHit;

    #[test]
    fn sensitive_artifact_reads_are_audited_without_auditing_internal_reads() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join("catalog.sqlite");

        record_sensitive_read_audit(
            &database,
            &SensitivityClass::Sensitive,
            "/safe/source",
            "host-test",
            "codex",
        )?;
        let catalog = CatalogService::open(&database)?;
        assert_eq!(catalog.audit_event_count()?, 1);

        record_sensitive_read_audit(
            &database,
            &SensitivityClass::Internal,
            "/safe/source",
            "host-test",
            "codex",
        )?;
        assert_eq!(catalog.audit_event_count()?, 1);
        Ok(())
    }

    #[test]
    fn sensitive_catalog_search_results_are_audited_without_query_or_preview() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join("catalog.sqlite");
        let sensitive_hit = SearchHit {
            artifact_id: "artifact-sensitive".into(),
            project_id: None,
            project_trust_level: None,
            kind: ArtifactKind::Configuration,
            lifecycle: LifecycleState::Active,
            title: "config.toml".into(),
            source_reference: "/safe/config.toml".into(),
            preview: "api_key=[REDACTED]".into(),
            host_id: "host-test".into(),
            provider_id: "codex".into(),
            source_hash: "hash".into(),
            sensitivity: SensitivityClass::Sensitive,
            observed_at: Utc::now(),
        };
        let internal_hit = SearchHit {
            artifact_id: "artifact-internal".into(),
            sensitivity: SensitivityClass::Internal,
            ..sensitive_hit.clone()
        };
        let mut catalog = CatalogService::open(&database)?;
        assert_eq!(
            catalog
                .audit_sensitive_search_results("test.search", &[sensitive_hit, internal_hit])?,
            1
        );
        let events = catalog.list_audit_events(Some("host-test"), Some("codex"), 10)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "catalog.search_sensitive");
        assert_eq!(events[0].target, "/safe/config.toml");
        assert_eq!(events[0].result, "redacted catalog search result");
        assert!(!events[0].target.contains("REDACTED"));
        Ok(())
    }

    #[test]
    fn bundled_agent_binary_uses_platform_executable_name() {
        let controller = Path::new("/Applications/AMCP.app/Contents/MacOS/amcp-controller");
        let expected =
            Path::new("/Applications/AMCP.app/Contents/MacOS").join(agent_executable_name());
        assert_eq!(bundled_agent_binary(controller), Some(expected));
    }

    #[test]
    fn agent_protocol_compatibility_requires_an_exact_version_match() {
        assert!(ensure_agent_protocol_compatibility(PROTOCOL_VERSION).is_ok());
        assert!(ensure_agent_protocol_compatibility(PROTOCOL_VERSION.saturating_add(1)).is_err());
    }

    #[test]
    fn agent_binary_compatibility_requires_the_controller_release_line() {
        let (major, minor) = release_line(env!("CARGO_PKG_VERSION")).expect("controller version");
        assert!(ensure_agent_binary_compatibility(&format!("{major}.{minor}.99")).is_ok());
        assert!(ensure_agent_binary_compatibility(&format!("v{major}.{minor}.0+build.7")).is_ok());
        assert!(ensure_agent_binary_compatibility(&format!("{major}.{}.0", minor + 1)).is_err());
        assert!(ensure_agent_binary_compatibility("1.0.0").is_err());
        assert!(ensure_agent_binary_compatibility("not-a-version").is_err());
    }

    #[test]
    fn controller_diagnostics_snapshot_is_content_free_and_shared() {
        let directory = tempfile::tempdir().expect("diagnostics database directory");
        let snapshot = diagnostics_snapshot(&directory.path().join("controller.sqlite"))
            .expect("diagnostics snapshot");
        assert_eq!(snapshot["content_included"], false);
        assert!(snapshot["hosts"].is_array());
        assert!(snapshot["providers"].is_array());
        assert!(snapshot["recent_collection_runs"].is_array());
        assert!(snapshot["recent_search_runs"].is_array());
        assert!(snapshot["catalog_diagnostics"]["stale_source_ratio"].is_number());
        assert!(snapshot["rag"]["retrieval_citation_coverage_basis_points"].is_number());
        assert!(snapshot.get("query").is_none());
    }

    #[test]
    fn readiness_snapshot_is_content_free_and_does_not_certify_an_empty_catalog() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let snapshot = readiness_snapshot(&temporary.path().join("controller.sqlite"))?;
        assert_eq!(snapshot["content_included"], false);
        assert_eq!(snapshot["native_provider_files_opened"], false);
        assert_eq!(snapshot["local_codex_ready"], false);
        assert!(snapshot["checks"].is_array());
        assert!(snapshot["external_verification_remaining"].is_array());
        assert!(snapshot.get("query").is_none());
        assert!(snapshot.get("source_reference").is_none());
        Ok(())
    }

    fn provider_descriptor(id: &str) -> ProviderDescriptor {
        ProviderDescriptor {
            id: id.into(),
            display_name: id.into(),
            version: None,
            adapter_version: "test".into(),
            schema_fingerprint: "test-v1".into(),
            support_level: amcp_domain::ProviderSupportLevel::InventoryOnly,
            health: ProviderHealth::Healthy,
            compatibility: amcp_domain::ProviderCompatibility::Compatible,
            native_roots: Vec::new(),
            capabilities: vec!["inventory".into()],
        }
    }

    #[test]
    fn collection_selector_collects_all_registered_providers_or_one_explicit_provider() {
        let descriptors = vec![
            provider_descriptor("codex"),
            provider_descriptor("claude-code"),
        ];
        assert_eq!(
            collection_provider_ids("all", &descriptors).expect("all providers"),
            vec!["claude-code", "codex"]
        );
        assert_eq!(
            collection_provider_ids("codex", &descriptors).expect("explicit provider"),
            vec!["codex"]
        );
        assert!(collection_provider_ids("unknown", &descriptors).is_err());
    }

    #[test]
    fn provider_collection_failure_report_is_content_free() {
        let report = provider_collection_failure("codex", "collection_failed");
        assert_eq!(report["provider_id"], "codex");
        assert_eq!(report["reason"], "collection_failed");
        assert_eq!(report["content_included"], false);
        assert!(!report.to_string().contains("provider-secret"));
    }

    #[test]
    fn benchmark_percentiles_use_the_nearest_rank_and_reject_invalid_inputs() {
        let samples = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile_ms(&samples, 50), Some(5));
        assert_eq!(percentile_ms(&samples, 95), Some(10));
        assert_eq!(percentile_ms(&samples, 0), None);
        assert_eq!(percentile_ms(&[], 95), None);
    }

    #[test]
    fn quality_ratio_uses_full_credit_for_an_empty_denominator_and_caps_overflow() {
        assert_eq!(ratio_basis_points(0, 0), 10_000);
        assert_eq!(ratio_basis_points(3, 4), 7_500);
        assert_eq!(ratio_basis_points(9, 3), 10_000);
    }

    #[test]
    fn redacted_rag_fixture_meets_the_controller_quality_gate() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let fixture = temporary.path().join("rag-evaluation.json");
        std::fs::write(
            &fixture,
            include_str!("../../../fixtures/rag/retrieval-evaluation.json"),
        )?;
        rag_evaluate(fixture, 3, 10_000, 10_000, 0, true, true)
    }
}
