use amcp_domain::{
    ArtifactKind, AuditEvent, ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord,
    GuidanceRecord, HostIdentity, HostRecord, HostStatus, LifecycleState, MemoryRecord,
    ProjectRecord, ProviderCompatibility, ProviderHealth, ProviderRecord, ProviderSupportLevel,
    RuntimeEvent, SensitivityClass, SessionItem, SessionRecord, new_id,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub artifact_id: String,
    pub project_id: Option<String>,
    pub project_trust_level: Option<String>,
    pub kind: ArtifactKind,
    pub lifecycle: LifecycleState,
    pub title: String,
    pub source_reference: String,
    pub preview: String,
    pub host_id: String,
    pub provider_id: String,
    pub source_hash: String,
    pub sensitivity: SensitivityClass,
    pub observed_at: DateTime<Utc>,
}

/// Controller-wide, provider-neutral constraints for lexical catalog search.
/// Empty collections and `None` fields intentionally mean "no constraint".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchFilters {
    pub host_id: Option<String>,
    pub provider_id: Option<String>,
    pub project_id: Option<String>,
    pub project_trust_levels: Vec<String>,
    pub artifact_kinds: Vec<ArtifactKind>,
    pub lifecycle_states: Vec<LifecycleState>,
    pub sensitivity_max: Option<SensitivityClass>,
    pub observed_after: Option<DateTime<Utc>>,
    pub observed_before: Option<DateTime<Utc>>,
}

/// A user-owned, private Controller shortcut for a query and its shared
/// catalog constraints. Unlike search telemetry, its query is deliberately
/// persisted because the user explicitly asked to save it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedSearch {
    pub saved_search_id: String,
    pub name: String,
    pub query: String,
    pub filters: SearchFilters,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A Controller-local label for a registered Agent host. It deliberately does
/// not alter the Agent-owned `host_id` or its native display name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostAlias {
    pub host_id: String,
    pub alias: String,
    pub updated_at: DateTime<Utc>,
}

/// A Controller-owned label attached to a normalized AMCP artifact. Tags are
/// catalog metadata only and never write to the provider-native source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerTag {
    pub tag_id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A Controller-owned, symmetric link between two normalized artifacts from
/// different hosts. It is metadata about AMCP's catalog, not a request to
/// merge, copy, or alter either provider-native source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossHostRelationship {
    pub relationship_id: String,
    pub relationship_kind: String,
    pub left_artifact_id: String,
    pub left_host_id: String,
    pub left_title: String,
    pub right_artifact_id: String,
    pub right_host_id: String,
    pub right_title: String,
    pub created_at: DateTime<Utc>,
}

/// Metadata constraints for the session explorer. Session bodies remain outside
/// this query path; callers receive only normalized session records.
#[derive(Debug, Clone, Default)]
pub struct SessionFilters {
    pub host_id: Option<String>,
    pub provider_id: Option<String>,
    pub project_id: Option<String>,
    pub branch: Option<String>,
    pub model: Option<String>,
    pub archived: Option<bool>,
    pub started_after: Option<DateTime<Utc>>,
    pub started_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexRunRecord {
    pub run_id: String,
    pub mode: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub indexed_count: usize,
    pub last_artifact_id: Option<String>,
    pub error: Option<String>,
}

/// Content-free Controller measurement of one provider collection attempt.
/// It intentionally stores counters and correlation metadata only: never a
/// query, native path, excerpt, or provider error message.
#[derive(Debug, Clone, Serialize)]
pub struct CollectionRunRecord {
    pub collection_run_id: String,
    pub host_id: String,
    pub provider_id: String,
    pub request_id: Option<String>,
    pub correlation_id: String,
    pub status: String,
    pub failure_kind: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub discovered_count: usize,
    pub inserted_count: usize,
    pub replayed_batch_count: usize,
}

/// Content-free measurement of a catalog search. Query text, snippets and
/// result identifiers are intentionally excluded from persistent telemetry.
#[derive(Debug, Clone, Serialize)]
pub struct SearchRunRecord {
    pub search_run_id: String,
    pub host_id: Option<String>,
    pub provider_id: Option<String>,
    pub correlation_id: String,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub result_count: usize,
    pub limit: usize,
}

/// Receipt for a human-requested removal of one central memory record. This
/// never changes the native provider file; it removes AMCP's own catalog and
/// derived projections for the observed source version.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryForgetReceipt {
    pub memory_record_id: String,
    pub host_id: String,
    pub provider_id: String,
    pub tombstone_id: String,
    pub deleted_artifacts: usize,
    pub deleted_rag_chunks: usize,
    pub cleared_retrieval_runs: usize,
    pub deleted_at: DateTime<Utc>,
}

/// Content-free diagnostics shared by the desktop and MCP surfaces. Paths,
/// identifiers and lifecycle state are safe operational metadata; excerpts,
/// diffs and provider payloads are deliberately excluded.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogDiagnostics {
    pub total_artifact_count: usize,
    pub stale_artifact_count: usize,
    pub stale_source_ratio: f64,
    pub search_indexed_artifact_count: usize,
    pub search_index_coverage_ratio: f64,
    pub database_size_bytes: u64,
    pub applied_change_count: usize,
    pub conflicted_change_count: usize,
    pub rolled_back_change_count: usize,
    pub stale_artifacts: Vec<ArtifactDiagnostic>,
    pub projects_requiring_attention: Vec<ProjectRecord>,
    pub conflicted_changes: Vec<ChangeConflictDiagnostic>,
    pub recent_provider_diagnostic_event_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDiagnostic {
    pub artifact_id: String,
    pub host_id: String,
    pub provider_id: String,
    pub project_id: Option<String>,
    pub kind: ArtifactKind,
    pub title: String,
    pub source_reference: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeConflictDiagnostic {
    pub change_set_id: String,
    pub host_id: String,
    pub provider_id: String,
    pub updated_at: DateTime<Utc>,
}

/// A consistent SQLite snapshot owned by the Controller. The backup contains
/// only AMCP's central catalog; it never reads or copies provider-native files.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogBackupReceipt {
    pub backup_path: PathBuf,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
}

pub struct Catalog {
    connection: Connection,
    database_path: Option<std::path::PathBuf>,
}

pub const HEARTBEAT_STALE_AFTER_SECONDS: i64 = 90;
pub const CURRENT_SCHEMA_VERSION: i64 = 10;

impl Catalog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let existing_catalog = fs::symlink_metadata(&path)
            .map(|metadata| metadata.is_file() && metadata.len() > 0)
            .unwrap_or(false);
        prepare_private_database_path(&path)?;
        let connection = Connection::open(&path).context("open AMCP catalog")?;
        let catalog = Self {
            connection,
            database_path: Some(path),
        };
        if existing_catalog && catalog.requires_migration()? {
            catalog.create_backup("pre-migration")?;
        }
        catalog.migrate()?;
        catalog.restrict_catalog_files()?;
        Ok(catalog)
    }

    fn requires_migration(&self) -> Result<bool> {
        let migration_table_exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
            [],
            |row| row.get(0),
        )?;
        if !migration_table_exists {
            return Ok(true);
        }
        let version: Option<i64> =
            self.connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get(0)
                })?;
        Ok(version.unwrap_or_default() < CURRENT_SCHEMA_VERSION)
    }

    pub fn create_backup(&self, reason: &str) -> Result<CatalogBackupReceipt> {
        let database_path = self
            .database_path
            .as_deref()
            .context("cannot create a persistent backup of an in-memory catalog")?;
        let reason = backup_reason_slug(reason)?;
        let directory = database_path
            .parent()
            .context("AMCP catalog path has no parent directory")?
            .join("backups");
        prepare_private_backup_directory(&directory)?;
        let created_at = Utc::now();
        let destination = directory.join(format!(
            "controller-{reason}-{}-{}.sqlite",
            created_at.timestamp_nanos_opt().unwrap_or_default(),
            std::process::id(),
        ));
        let destination_sql = destination
            .to_str()
            .context("AMCP backup path must be valid Unicode")?
            .replace('\'', "''");
        self.connection
            .execute_batch(&format!("VACUUM INTO '{destination_sql}'"))
            .context("create consistent AMCP catalog backup")?;
        restrict_file_to_current_user(&destination)?;
        let size_bytes = fs::metadata(&destination)
            .context("inspect AMCP catalog backup")?
            .len();
        Ok(CatalogBackupReceipt {
            backup_path: destination,
            reason,
            created_at,
            size_bytes,
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().context("open in-memory catalog")?;
        let catalog = Self {
            connection,
            database_path: None,
        };
        catalog.migrate()?;
        Ok(catalog)
    }

    /// Catalogs retain redacted but potentially sensitive local state. On Unix
    /// keep the SQLite database and its WAL sidecars readable only by the
    /// current user; other platforms rely on their user-profile ACL defaults.
    fn restrict_catalog_files(&self) -> Result<()> {
        let Some(database_path) = &self.database_path else {
            return Ok(());
        };
        harden_private_database_path(database_path)
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                platform TEXT NOT NULL,
                hostname TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS providers (
                provider_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                version TEXT,
                adapter_version TEXT NOT NULL,
                schema_fingerprint TEXT NOT NULL DEFAULT '',
                support_level TEXT NOT NULL DEFAULT 'inventory-only',
                health TEXT NOT NULL DEFAULT 'unknown',
                compatibility TEXT NOT NULL DEFAULT 'unknown',
                native_roots_json TEXT NOT NULL DEFAULT '[]',
                capabilities_json TEXT NOT NULL,
                PRIMARY KEY (provider_id, host_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                root_path TEXT NOT NULL,
                display_name TEXT NOT NULL,
                trust_level TEXT,
                discovered_from TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (project_id, host_id, provider_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                project_id TEXT,
                title TEXT,
                cwd TEXT,
                model TEXT,
                branch TEXT,
                started_at TEXT,
                ended_at TEXT,
                archived INTEGER NOT NULL,
                source_reference TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (session_id, host_id, provider_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS session_items (
                session_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                role TEXT,
                item_kind TEXT NOT NULL,
                content TEXT,
                source_reference TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (session_id, host_id, provider_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS memory_records (
                memory_record_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                project_id TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                confidence REAL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (memory_record_id, host_id, provider_id)
            );
            CREATE TABLE IF NOT EXISTS config_layers (
                config_layer_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                project_id TEXT,
                source_reference TEXT NOT NULL,
                scope TEXT NOT NULL,
                profile TEXT,
                precedence_rank INTEGER NOT NULL,
                source_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (config_layer_id, host_id, provider_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS guidance_records (
                guidance_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                project_id TEXT,
                source_reference TEXT NOT NULL,
                relative_scope TEXT NOT NULL,
                kind TEXT NOT NULL,
                precedence_rank INTEGER NOT NULL,
                source_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (guidance_id, host_id, provider_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS guidance_edges (
                lower_guidance_id TEXT NOT NULL,
                higher_guidance_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                PRIMARY KEY (lower_guidance_id, higher_guidance_id, host_id, provider_id)
            );
            CREATE TABLE IF NOT EXISTS runtime_events (
                event_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                project_id TEXT,
                native_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                content TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                UNIQUE(host_id, provider_id, native_id, source_hash)
            );
            CREATE TABLE IF NOT EXISTS source_observations (
                observation_id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                native_id TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                parser_version TEXT NOT NULL,
                schema_fingerprint TEXT NOT NULL,
                redaction_policy_version TEXT NOT NULL,
                collection_run_id TEXT NOT NULL,
                state TEXT NOT NULL,
                FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
            );
            CREATE TABLE IF NOT EXISTS evidence_snapshots (
                evidence_id TEXT PRIMARY KEY,
                observation_id TEXT NOT NULL,
                excerpt TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                retention_until TEXT,
                FOREIGN KEY (observation_id) REFERENCES source_observations(observation_id)
            );
            CREATE TABLE IF NOT EXISTS collection_cursors (
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                cursor TEXT,
                collection_run_id TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (host_id, provider_id)
            );
            CREATE TABLE IF NOT EXISTS collection_runs (
                collection_run_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                request_id TEXT,
                correlation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                failure_kind TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                discovered_count INTEGER NOT NULL,
                inserted_count INTEGER NOT NULL,
                replayed_batch_count INTEGER NOT NULL,
                PRIMARY KEY (collection_run_id, host_id, provider_id),
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE INDEX IF NOT EXISTS collection_runs_recent_idx
                ON collection_runs(completed_at DESC);
            CREATE TABLE IF NOT EXISTS search_runs (
                search_run_id TEXT PRIMARY KEY,
                host_id TEXT,
                provider_id TEXT,
                correlation_id TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                result_count INTEGER NOT NULL,
                result_limit INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS search_runs_recent_idx
                ON search_runs(completed_at DESC);
            CREATE TABLE IF NOT EXISTS saved_searches (
                saved_search_id TEXT PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                query TEXT NOT NULL,
                filters_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS host_aliases (
                host_id TEXT PRIMARY KEY,
                alias TEXT NOT NULL COLLATE NOCASE UNIQUE,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(host_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS controller_tags (
                tag_id TEXT PRIMARY KEY,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_tags (
                artifact_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (artifact_id, tag_id),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES controller_tags(tag_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS cross_host_relationships (
                relationship_id TEXT PRIMARY KEY,
                left_artifact_id TEXT NOT NULL,
                right_artifact_id TEXT NOT NULL,
                relationship_kind TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(left_artifact_id, right_artifact_id, relationship_kind),
                FOREIGN KEY (left_artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
                FOREIGN KEY (right_artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
                CHECK(left_artifact_id < right_artifact_id)
            );
            CREATE TABLE IF NOT EXISTS change_sets (
                change_set_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                status TEXT NOT NULL,
                change_set_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                audit_event_id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                host_id TEXT,
                provider_id TEXT,
                before_hash TEXT,
                after_hash TEXT,
                result TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy_tombstones (
                tombstone_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                native_id TEXT NOT NULL,
                source_hash TEXT,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(host_id, provider_id, native_id, source_hash)
            );
            CREATE TABLE IF NOT EXISTS agent_connections (
                host_id TEXT PRIMARY KEY,
                endpoint TEXT,
                status TEXT NOT NULL,
                agent_version TEXT,
                capabilities_json TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(host_id)
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS search_content USING fts5(
                artifact_id UNINDEXED,
                title,
                content,
                source_reference UNINDEXED,
                host_id UNINDEXED,
                provider_id UNINDEXED
            );
            CREATE TABLE IF NOT EXISTS index_runs (
                run_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                indexed_count INTEGER NOT NULL,
                last_artifact_id TEXT,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS index_runs_started_at_idx
                ON index_runs(started_at DESC);
            INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (1, datetime('now'));
            "#,
        )?;
        let provider_columns = self
            .connection
            .prepare("PRAGMA table_info(providers)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !provider_columns
            .iter()
            .any(|column| column == "schema_fingerprint")
        {
            self.connection.execute_batch(
                "ALTER TABLE providers ADD COLUMN schema_fingerprint TEXT NOT NULL DEFAULT '';",
            )?;
        }
        if !provider_columns
            .iter()
            .any(|column| column == "support_level")
        {
            self.connection.execute_batch(
                "ALTER TABLE providers ADD COLUMN support_level TEXT NOT NULL DEFAULT 'inventory-only';",
            )?;
        }
        if !provider_columns.iter().any(|column| column == "health") {
            self.connection.execute_batch(
                "ALTER TABLE providers ADD COLUMN health TEXT NOT NULL DEFAULT 'unknown';",
            )?;
        }
        if !provider_columns
            .iter()
            .any(|column| column == "compatibility")
        {
            self.connection.execute_batch(
                "ALTER TABLE providers ADD COLUMN compatibility TEXT NOT NULL DEFAULT 'unknown';",
            )?;
        }
        if !provider_columns
            .iter()
            .any(|column| column == "native_roots_json")
        {
            self.connection.execute_batch(
                "ALTER TABLE providers ADD COLUMN native_roots_json TEXT NOT NULL DEFAULT '[]';",
            )?;
        }
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (2, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (3, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (4, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (5, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (6, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (7, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (8, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (9, datetime('now'))",
            [],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (10, datetime('now'))",
            [],
        )?;
        Ok(())
    }

    pub fn ingest(&mut self, batch: &CollectionBatch) -> Result<usize> {
        let index_run_id = new_id("index-run");
        let index_started_at = Utc::now();
        let transaction = self
            .connection
            .transaction()
            .context("start collection transaction")?;
        let host = &batch.host;
        transaction.execute(
            "INSERT INTO hosts(host_id, display_name, platform, hostname, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id) DO UPDATE SET display_name=excluded.display_name, platform=excluded.platform, hostname=excluded.hostname, last_seen=excluded.last_seen",
            params![host.host_id, host.display_name, host.platform, host.hostname, Utc::now().to_rfc3339()],
        )?;

        for provider in &batch.providers {
            transaction.execute(
                "INSERT INTO providers(provider_id, host_id, display_name, version, adapter_version, schema_fingerprint, support_level, health, compatibility, native_roots_json, capabilities_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(provider_id, host_id) DO UPDATE SET display_name=excluded.display_name, version=excluded.version, adapter_version=excluded.adapter_version, schema_fingerprint=excluded.schema_fingerprint, support_level=excluded.support_level, health=excluded.health, compatibility=excluded.compatibility, native_roots_json=excluded.native_roots_json, capabilities_json=excluded.capabilities_json",
                params![
                    provider.id,
                    host.host_id,
                    provider.display_name,
                    provider.version,
                    provider.adapter_version,
                    provider.schema_fingerprint,
                    serde_json::to_string(&provider.support_level)?,
                    serde_json::to_string(&provider.health)?,
                    serde_json::to_string(&provider.compatibility)?,
                    serde_json::to_string(&provider.native_roots)?,
                    serde_json::to_string(&provider.capabilities)?,
                ],
            )?;
        }

        for project in &batch.projects {
            transaction.execute(
                "INSERT INTO projects(project_id, host_id, provider_id, root_path, display_name, trust_level, discovered_from, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(project_id, host_id, provider_id) DO UPDATE SET root_path=excluded.root_path, display_name=excluded.display_name, trust_level=excluded.trust_level, discovered_from=excluded.discovered_from, observed_at=excluded.observed_at",
                params![
                    project.project_id,
                    project.host_id,
                    project.provider_id,
                    project.root_path,
                    project.display_name,
                    project.trust_level,
                    project.discovered_from,
                    project.observed_at.to_rfc3339(),
                ],
            )?;
        }

        for session in &batch.sessions {
            transaction.execute(
                "INSERT INTO sessions(session_id, host_id, provider_id, project_id, title, cwd, model, branch, started_at, ended_at, archived, source_reference, source_hash, metadata_json, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                 ON CONFLICT(session_id, host_id, provider_id) DO UPDATE SET project_id=excluded.project_id, title=excluded.title, cwd=excluded.cwd, model=excluded.model, branch=excluded.branch, started_at=excluded.started_at, ended_at=excluded.ended_at, archived=excluded.archived, source_reference=excluded.source_reference, source_hash=excluded.source_hash, metadata_json=excluded.metadata_json, observed_at=excluded.observed_at",
                params![
                    session.session_id,
                    session.host_id,
                    session.provider_id,
                    session.project_id,
                    session.title,
                    session.cwd,
                    session.model,
                    session.branch,
                    session.started_at.map(|value| value.to_rfc3339()),
                    session.ended_at.map(|value| value.to_rfc3339()),
                    i64::from(session.archived),
                    session.source_reference,
                    session.source_hash,
                    session.metadata_json,
                    session.observed_at.to_rfc3339(),
                ],
            )?;
        }

        for item in &batch.session_items {
            transaction.execute(
                "INSERT INTO session_items(session_id, host_id, provider_id, sequence, role, item_kind, content, source_reference, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(session_id, host_id, provider_id, sequence) DO UPDATE SET role=excluded.role, item_kind=excluded.item_kind, content=excluded.content, source_reference=excluded.source_reference, observed_at=excluded.observed_at",
                params![
                    item.session_id,
                    item.host_id,
                    item.provider_id,
                    item.sequence,
                    item.role,
                    item.item_kind,
                    item.content,
                    item.source_reference,
                    item.observed_at.to_rfc3339(),
                ],
            )?;
        }

        for memory in &batch.memory_records {
            if is_policy_tombstoned(
                &transaction,
                &memory.host_id,
                &memory.provider_id,
                &memory.source_reference,
                &memory.source_hash,
            )? {
                continue;
            }
            transaction.execute(
                "INSERT INTO memory_records(memory_record_id, host_id, provider_id, project_id, title, content, source_reference, source_hash, lifecycle, confidence, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(memory_record_id, host_id, provider_id) DO UPDATE SET project_id=excluded.project_id, title=excluded.title, content=excluded.content, source_reference=excluded.source_reference, source_hash=excluded.source_hash, lifecycle=excluded.lifecycle, confidence=excluded.confidence, observed_at=excluded.observed_at",
                params![
                    memory.memory_record_id,
                    memory.host_id,
                    memory.provider_id,
                    memory.project_id,
                    memory.title,
                    memory.content,
                    memory.source_reference,
                    memory.source_hash,
                    serde_json::to_string(&memory.lifecycle)?,
                    memory.confidence,
                    memory.observed_at.to_rfc3339(),
                ],
            )?;
        }

        for layer in &batch.config_layers {
            transaction.execute(
                "INSERT INTO config_layers(config_layer_id, host_id, provider_id, project_id, source_reference, scope, profile, precedence_rank, source_hash, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(config_layer_id, host_id, provider_id) DO UPDATE SET project_id=excluded.project_id, source_reference=excluded.source_reference, scope=excluded.scope, profile=excluded.profile, precedence_rank=excluded.precedence_rank, source_hash=excluded.source_hash, observed_at=excluded.observed_at",
                params![
                    layer.config_layer_id,
                    layer.host_id,
                    layer.provider_id,
                    layer.project_id,
                    layer.source_reference,
                    layer.scope,
                    layer.profile,
                    layer.precedence_rank,
                    layer.source_hash,
                    layer.observed_at.to_rfc3339(),
                ],
            )?;
        }

        for guidance in &batch.guidance_records {
            transaction.execute(
                "INSERT INTO guidance_records(guidance_id, host_id, provider_id, project_id, source_reference, relative_scope, kind, precedence_rank, source_hash, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(guidance_id, host_id, provider_id) DO UPDATE SET project_id=excluded.project_id, source_reference=excluded.source_reference, relative_scope=excluded.relative_scope, kind=excluded.kind, precedence_rank=excluded.precedence_rank, source_hash=excluded.source_hash, observed_at=excluded.observed_at",
                params![
                    guidance.guidance_id,
                    guidance.host_id,
                    guidance.provider_id,
                    guidance.project_id,
                    guidance.source_reference,
                    guidance.relative_scope,
                    guidance.kind,
                    guidance.precedence_rank,
                    guidance.source_hash,
                    guidance.observed_at.to_rfc3339(),
                ],
            )?;
        }
        for edge in &batch.guidance_edges {
            transaction.execute(
                "INSERT INTO guidance_edges(lower_guidance_id, higher_guidance_id, relation, host_id, provider_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(lower_guidance_id, higher_guidance_id, host_id, provider_id) DO UPDATE SET relation=excluded.relation",
                params![
                    edge.lower_guidance_id,
                    edge.higher_guidance_id,
                    edge.relation,
                    edge.host_id,
                    edge.provider_id,
                ],
            )?;
        }
        for event in &batch.runtime_events {
            transaction.execute(
                "INSERT OR IGNORE INTO runtime_events(event_id, host_id, provider_id, event_type, sequence, payload_json, occurred_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.event_id,
                    event.host_id,
                    event.provider_id,
                    event.event_type,
                    event.sequence,
                    event.payload_json,
                    event.occurred_at.to_rfc3339(),
                ],
            )?;
        }

        let mut inserted = 0;
        for artifact in &batch.artifacts {
            if is_policy_tombstoned(
                &transaction,
                &artifact.host_id,
                &artifact.provider_id,
                &artifact.native_id,
                &artifact.observation.source_hash,
            )? {
                continue;
            }
            let existing_artifact_id: Option<String> = transaction
                .query_row(
                    "SELECT artifact_id FROM artifacts WHERE host_id = ?1 AND provider_id = ?2 AND native_id = ?3 AND source_hash = ?4",
                    params![
                        artifact.host_id,
                        artifact.provider_id,
                        artifact.native_id,
                        artifact.observation.source_hash,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let effective_artifact_id = if let Some(existing) = existing_artifact_id {
                transaction.execute(
                    "UPDATE artifacts SET project_id = ?2, kind = ?3, title = ?4, source_reference = ?5, content = ?6, sensitivity = ?7, lifecycle = ?8, observed_at = ?9
                     WHERE artifact_id = ?1",
                    params![
                        existing,
                        artifact.project_id,
                        serde_json::to_string(&artifact.kind)?,
                        artifact.title,
                        artifact.source_reference,
                        artifact.content,
                        serde_json::to_string(&artifact.sensitivity)?,
                        serde_json::to_string(&artifact.lifecycle)?,
                        artifact.observation.observed_at.to_rfc3339(),
                    ],
                )?;
                existing
            } else {
                transaction.execute(
                    "INSERT INTO artifacts(artifact_id, host_id, provider_id, project_id, native_id, kind, title, source_reference, content, sensitivity, lifecycle, observed_at, source_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        artifact.artifact_id,
                        artifact.host_id,
                        artifact.provider_id,
                        artifact.project_id,
                        artifact.native_id,
                        serde_json::to_string(&artifact.kind)?,
                        artifact.title,
                        artifact.source_reference,
                        artifact.content,
                        serde_json::to_string(&artifact.sensitivity)?,
                        serde_json::to_string(&artifact.lifecycle)?,
                        artifact.observation.observed_at.to_rfc3339(),
                        artifact.observation.source_hash,
                    ],
                )?;
                inserted += 1;
                artifact.artifact_id.clone()
            };

            transaction.execute(
                "INSERT OR IGNORE INTO source_observations(observation_id, artifact_id, host_id, provider_id, native_id, source_reference, source_hash, observed_at, parser_version, schema_fingerprint, redaction_policy_version, collection_run_id, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    artifact.observation.observation_id,
                    effective_artifact_id,
                    artifact.observation.host_id,
                    artifact.observation.provider_id,
                    artifact.observation.native_id,
                    artifact.observation.source_reference,
                    artifact.observation.source_hash,
                    artifact.observation.observed_at.to_rfc3339(),
                    artifact.observation.parser_version,
                    artifact.observation.schema_fingerprint,
                    artifact.observation.redaction_policy_version,
                    artifact.observation.collection_run_id,
                    serde_json::to_string(&artifact.observation.state)?,
                ],
            )?;

            if let Some(evidence) = &artifact.evidence {
                transaction.execute(
                    "INSERT OR IGNORE INTO evidence_snapshots(evidence_id, observation_id, excerpt, source_hash, observed_at, sensitivity, retention_until)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        evidence.evidence_id,
                        evidence.observation_id,
                        evidence.excerpt,
                        evidence.source_hash,
                        evidence.observed_at.to_rfc3339(),
                        serde_json::to_string(&evidence.sensitivity)?,
                        evidence.retention_until.map(|value| value.to_rfc3339()),
                    ],
                )?;
            }

            transaction.execute(
                "DELETE FROM search_content WHERE artifact_id = ?1",
                params![effective_artifact_id],
            )?;
            transaction.execute(
                "INSERT INTO search_content(artifact_id, title, content, source_reference, host_id, provider_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![effective_artifact_id, artifact.title, artifact.content, artifact.source_reference, artifact.host_id, artifact.provider_id],
            )?;
        }

        for provider in &batch.providers {
            transaction.execute(
                "INSERT INTO collection_cursors(host_id, provider_id, cursor, collection_run_id, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(host_id, provider_id) DO UPDATE SET cursor=excluded.cursor, collection_run_id=excluded.collection_run_id, updated_at=excluded.updated_at",
                params![host.host_id, provider.id, batch.next_cursor, batch.collection_run_id, Utc::now().to_rfc3339()],
            )?;
        }
        if !batch.artifacts.is_empty() {
            transaction.execute(
                "INSERT INTO index_runs(run_id, mode, status, started_at, completed_at, indexed_count, last_artifact_id, error)
                 VALUES (?1, 'incremental', 'completed', ?2, ?3, ?4, ?5, NULL)",
                params![
                    index_run_id,
                    index_started_at.to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    batch.artifacts.len() as i64,
                    batch.artifacts.last().map(|artifact| artifact.artifact_id.as_str()),
                ],
            )?;
        }
        transaction
            .commit()
            .context("commit collection transaction")?;
        self.restrict_catalog_files()?;
        Ok(inserted)
    }

    pub fn latest_index_run(&self) -> Result<Option<IndexRunRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT run_id, mode, status, started_at, completed_at, indexed_count, last_artifact_id, error
             FROM index_runs ORDER BY started_at DESC LIMIT 1",
        )?;
        Ok(statement.query_row([], index_run_from_row).optional()?)
    }

    pub fn record_collection_run(&mut self, run: &CollectionRunRecord) -> Result<()> {
        self.connection.execute(
            "INSERT INTO collection_runs(collection_run_id, host_id, provider_id, request_id, correlation_id, status, failure_kind, started_at, completed_at, duration_ms, discovered_count, inserted_count, replayed_batch_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(collection_run_id, host_id, provider_id) DO UPDATE SET request_id=excluded.request_id, correlation_id=excluded.correlation_id, status=excluded.status, failure_kind=excluded.failure_kind, started_at=excluded.started_at, completed_at=excluded.completed_at, duration_ms=excluded.duration_ms, discovered_count=excluded.discovered_count, inserted_count=excluded.inserted_count, replayed_batch_count=excluded.replayed_batch_count",
            params![
                run.collection_run_id,
                run.host_id,
                run.provider_id,
                run.request_id,
                run.correlation_id,
                run.status,
                run.failure_kind,
                run.started_at.to_rfc3339(),
                run.completed_at.to_rfc3339(),
                run.duration_ms.min(i64::MAX as u64) as i64,
                run.discovered_count.min(i64::MAX as usize) as i64,
                run.inserted_count.min(i64::MAX as usize) as i64,
                run.replayed_batch_count.min(i64::MAX as usize) as i64,
            ],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    fn record_search_run(&mut self, run: &SearchRunRecord) -> Result<()> {
        self.connection.execute(
            "INSERT INTO search_runs(search_run_id, host_id, provider_id, correlation_id, completed_at, duration_ms, result_count, result_limit)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run.search_run_id,
                run.host_id,
                run.provider_id,
                run.correlation_id,
                run.completed_at.to_rfc3339(),
                run.duration_ms.min(i64::MAX as u64) as i64,
                run.result_count.min(i64::MAX as usize) as i64,
                run.limit.min(i64::MAX as usize) as i64,
            ],
        )?;
        self.connection.execute(
            "DELETE FROM search_runs WHERE search_run_id IN (
                 SELECT search_run_id FROM search_runs
                 ORDER BY completed_at DESC, search_run_id DESC
                 LIMIT -1 OFFSET 1000
             )",
            [],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn list_search_runs(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchRunRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT search_run_id, host_id, provider_id, correlation_id, completed_at, duration_ms, result_count, result_limit
             FROM search_runs
             WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2)
             ORDER BY completed_at DESC, search_run_id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![host_id, provider_id, limit.clamp(1, 100) as i64],
            search_run_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_collection_runs(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CollectionRunRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT collection_run_id, host_id, provider_id, request_id, correlation_id, status, failure_kind, started_at, completed_at, duration_ms, discovered_count, inserted_count, replayed_batch_count
             FROM collection_runs
             WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2)
             ORDER BY completed_at DESC, collection_run_id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![host_id, provider_id, limit.clamp(1, 100) as i64],
            collection_run_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn rebuild_search_projection(&mut self, batch_size: usize) -> Result<IndexRunRecord> {
        let run_id = new_id("index-run");
        let started_at = Utc::now();
        self.connection.execute(
            "INSERT INTO index_runs(run_id, mode, status, started_at, completed_at, indexed_count, last_artifact_id, error)
             VALUES (?1, 'rebuild', 'running', ?2, NULL, 0, NULL, NULL)",
            params![run_id, started_at.to_rfc3339()],
        )?;
        let operation = (|| -> Result<()> {
            self.connection
                .execute("DELETE FROM search_content", [])
                .context("clear search projection")?;
            let batch_size = batch_size.clamp(1, 1_000);
            let mut last_artifact_id: Option<String> = None;
            let mut indexed_count = 0usize;
            loop {
                let rows = {
                    let mut statement = self.connection.prepare(
                        "SELECT artifact_id, title, content, source_reference, host_id, provider_id
                         FROM artifacts WHERE artifact_id > ?1 ORDER BY artifact_id LIMIT ?2",
                    )?;
                    let rows = statement.query_map(
                        params![last_artifact_id.as_deref().unwrap_or(""), batch_size as i64],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                            ))
                        },
                    )?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()?
                };
                if rows.is_empty() {
                    break;
                }
                let transaction = self
                    .connection
                    .transaction()
                    .context("start search projection chunk")?;
                for (artifact_id, title, content, source_reference, host_id, provider_id) in &rows {
                    transaction.execute(
                        "INSERT INTO search_content(artifact_id, title, content, source_reference, host_id, provider_id)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            artifact_id,
                            title,
                            content,
                            source_reference,
                            host_id,
                            provider_id,
                        ],
                    )?;
                }
                transaction
                    .commit()
                    .context("commit search projection chunk")?;
                indexed_count += rows.len();
                last_artifact_id = rows.last().map(|row| row.0.clone());
                self.connection.execute(
                    "UPDATE index_runs SET indexed_count = ?2, last_artifact_id = ?3 WHERE run_id = ?1",
                    params![run_id, indexed_count as i64, last_artifact_id],
                )?;
            }
            self.connection.execute(
                "UPDATE index_runs SET status = 'completed', completed_at = ?2 WHERE run_id = ?1",
                params![run_id, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })();
        if let Err(error) = operation {
            let _ = self.connection.execute(
                "UPDATE index_runs SET status = 'failed', completed_at = ?2, error = ?3 WHERE run_id = ?1",
                params![run_id, Utc::now().to_rfc3339(), error.to_string()],
            );
            return Err(error);
        }
        self.restrict_catalog_files()?;
        self.latest_index_run()?
            .context("completed index run disappeared")
    }

    pub fn ingest_runtime_events(&mut self, events: &[RuntimeEvent]) -> Result<usize> {
        let transaction = self
            .connection
            .transaction()
            .context("start runtime event transaction")?;
        let mut inserted = 0;
        for event in events {
            let event_inserted = transaction.execute(
                "INSERT OR IGNORE INTO runtime_events(event_id, host_id, provider_id, event_type, sequence, payload_json, occurred_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event.event_id,
                    event.host_id,
                    event.provider_id,
                    event.event_type,
                    event.sequence,
                    event.payload_json,
                    event.occurred_at.to_rfc3339(),
                ],
            )?;
            inserted += event_inserted;
            if event_inserted > 0 && event.event_type == "source.changed" {
                Self::mark_source_paths_stale(&transaction, event)?;
            }
            if event.event_type == "session.updated" {
                Self::project_runtime_session(&transaction, event)?;
            }
        }
        transaction
            .commit()
            .context("commit runtime event transaction")?;
        self.restrict_catalog_files()?;
        Ok(inserted)
    }

    fn mark_source_paths_stale(
        transaction: &rusqlite::Transaction<'_>,
        event: &RuntimeEvent,
    ) -> Result<()> {
        let payload: serde_json::Value = match serde_json::from_str(&event.payload_json) {
            Ok(payload) => payload,
            Err(_) => return Ok(()),
        };
        let Some(root) = payload.get("root").and_then(serde_json::Value::as_str) else {
            return Ok(());
        };
        if !is_absolute_source_root(root) {
            return Ok(());
        }
        let Some(paths) = payload.get("paths").and_then(serde_json::Value::as_array) else {
            return Ok(());
        };
        let stale = serde_json::to_string(&LifecycleState::Stale)?;
        for relative_path in paths.iter().filter_map(serde_json::Value::as_str) {
            if !is_safe_relative_source_path(relative_path) {
                continue;
            }
            let source_reference = join_source_reference(root, relative_path);
            transaction.execute(
                "UPDATE artifacts SET lifecycle = ?1
                 WHERE host_id = ?2 AND provider_id = ?3 AND source_reference = ?4",
                params![stale, event.host_id, event.provider_id, source_reference],
            )?;
        }
        Ok(())
    }

    fn project_runtime_session(
        transaction: &rusqlite::Transaction<'_>,
        event: &RuntimeEvent,
    ) -> Result<()> {
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).context("decode runtime session metadata")?;
        let Some(thread_id) = payload.get("thread_id").and_then(serde_json::Value::as_str) else {
            return Ok(());
        };
        let title = payload
            .get("title")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let cwd = payload
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let model = payload
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let project_id = payload
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let archived = payload
            .get("archived")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let started_at = payload
            .get("created_at")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_utc)
            .map(|value| value.to_rfc3339());
        let source_reference = format!(
            "{}://thread/{}",
            event.provider_id,
            thread_id.replace('/', "%2F")
        );
        transaction.execute(
        "INSERT INTO sessions(session_id, host_id, provider_id, project_id, title, cwd, model, branch, started_at, ended_at, archived, source_reference, source_hash, metadata_json, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(session_id, host_id, provider_id) DO UPDATE SET
           project_id=COALESCE(excluded.project_id, sessions.project_id),
           title=COALESCE(excluded.title, sessions.title),
           cwd=COALESCE(excluded.cwd, sessions.cwd),
           model=COALESCE(excluded.model, sessions.model),
           started_at=COALESCE(excluded.started_at, sessions.started_at),
           archived=excluded.archived,
           source_reference=excluded.source_reference,
           source_hash=excluded.source_hash,
           metadata_json=excluded.metadata_json,
           observed_at=excluded.observed_at",
        params![
            thread_id,
            event.host_id,
            event.provider_id,
            project_id,
            title,
            cwd,
            model,
            started_at,
            i64::from(archived),
            source_reference,
            event.event_id,
            event.payload_json,
            event.occurred_at.to_rfc3339(),
        ],
    )?;
        Ok(())
    }

    pub fn search(&mut self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        self.search_filtered(query, limit, &SearchFilters::default())
    }

    pub fn save_search(
        &mut self,
        name: &str,
        query: &str,
        filters: &SearchFilters,
    ) -> Result<SavedSearch> {
        let name = name.trim();
        let query = query.trim();
        if name.is_empty() || name.chars().count() > 120 {
            anyhow::bail!("saved-search name must contain 1 to 120 characters");
        }
        if query.is_empty() || query.chars().count() > 512 {
            anyhow::bail!("saved-search query must contain 1 to 512 characters");
        }
        let existing = self
            .connection
            .query_row(
                "SELECT saved_search_id, created_at FROM saved_searches WHERE name = ?1 COLLATE NOCASE",
                params![name],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let now = Utc::now();
        let (saved_search_id, created_at) = existing
            .map(|(id, created_at)| (id, parse_utc(&created_at).unwrap_or(now)))
            .unwrap_or_else(|| (new_id("saved-search"), now));
        self.connection.execute(
            "INSERT INTO saved_searches(saved_search_id, name, query, filters_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
                 query=excluded.query,
                 filters_json=excluded.filters_json,
                 updated_at=excluded.updated_at",
            params![
                saved_search_id,
                name,
                query,
                serde_json::to_string(filters)?,
                created_at.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;
        Ok(SavedSearch {
            saved_search_id,
            name: name.to_owned(),
            query: query.to_owned(),
            filters: filters.clone(),
            created_at,
            updated_at: now,
        })
    }

    pub fn list_saved_searches(&self) -> Result<Vec<SavedSearch>> {
        let mut statement = self.connection.prepare(
            "SELECT saved_search_id, name, query, filters_json, created_at, updated_at
             FROM saved_searches ORDER BY lower(name), created_at",
        )?;
        let rows = statement.query_map([], |row| {
            let filters_json: String = row.get(3)?;
            let created_at: String = row.get(4)?;
            let updated_at: String = row.get(5)?;
            Ok(SavedSearch {
                saved_search_id: row.get(0)?,
                name: row.get(1)?,
                query: row.get(2)?,
                filters: serde_json::from_str(&filters_json).unwrap_or_default(),
                created_at: parse_utc(&created_at).unwrap_or_else(Utc::now),
                updated_at: parse_utc(&updated_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_saved_search(&mut self, saved_search_id: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM saved_searches WHERE saved_search_id = ?1",
            params![saved_search_id],
        )? > 0)
    }

    pub fn set_host_alias(&mut self, host_id: &str, alias: &str) -> Result<HostAlias> {
        let alias = alias.trim();
        if alias.is_empty() || alias.chars().count() > 80 || alias.chars().any(char::is_control) {
            anyhow::bail!("host alias must contain 1 to 80 printable characters");
        }
        let host_exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosts WHERE host_id = ?1)",
            params![host_id],
            |row| row.get(0),
        )?;
        if !host_exists {
            anyhow::bail!("cannot assign an alias to an unknown host");
        }
        let updated_at = Utc::now();
        self.connection.execute(
            "INSERT INTO host_aliases(host_id, alias, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(host_id) DO UPDATE SET alias=excluded.alias, updated_at=excluded.updated_at",
            params![host_id, alias, updated_at.to_rfc3339()],
        )?;
        Ok(HostAlias {
            host_id: host_id.to_owned(),
            alias: alias.to_owned(),
            updated_at,
        })
    }

    pub fn list_host_aliases(&self) -> Result<Vec<HostAlias>> {
        let mut statement = self.connection.prepare(
            "SELECT host_id, alias, updated_at FROM host_aliases ORDER BY lower(alias), host_id",
        )?;
        let rows = statement.query_map([], |row| {
            let updated_at: String = row.get(2)?;
            Ok(HostAlias {
                host_id: row.get(0)?,
                alias: row.get(1)?,
                updated_at: parse_utc(&updated_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_host_alias(&mut self, host_id: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM host_aliases WHERE host_id = ?1",
            params![host_id],
        )? > 0)
    }

    pub fn tag_artifact(&mut self, artifact_id: &str, name: &str) -> Result<ControllerTag> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 48 || name.chars().any(char::is_control) {
            anyhow::bail!("tag name must contain 1 to 48 printable characters");
        }
        let artifact_exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE artifact_id = ?1)",
            params![artifact_id],
            |row| row.get(0),
        )?;
        if !artifact_exists {
            anyhow::bail!("cannot tag an unknown artifact");
        }
        let existing = self
            .connection
            .query_row(
                "SELECT tag_id, created_at FROM controller_tags WHERE name = ?1 COLLATE NOCASE",
                params![name],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let now = Utc::now();
        let (tag_id, created_at) = existing
            .map(|(id, created_at)| (id, parse_utc(&created_at).unwrap_or(now)))
            .unwrap_or_else(|| (new_id("tag"), now));
        self.connection.execute(
            "INSERT OR IGNORE INTO controller_tags(tag_id, name, created_at) VALUES (?1, ?2, ?3)",
            params![tag_id, name, created_at.to_rfc3339()],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO artifact_tags(artifact_id, tag_id, created_at) VALUES (?1, ?2, ?3)",
            params![artifact_id, tag_id, now.to_rfc3339()],
        )?;
        Ok(ControllerTag {
            tag_id,
            name: name.to_owned(),
            created_at,
        })
    }

    pub fn list_artifact_tags(&self, artifact_id: &str) -> Result<Vec<ControllerTag>> {
        let mut statement = self.connection.prepare(
            "SELECT t.tag_id, t.name, t.created_at
             FROM controller_tags t JOIN artifact_tags a ON a.tag_id = t.tag_id
             WHERE a.artifact_id = ?1 ORDER BY lower(t.name), t.tag_id",
        )?;
        let rows = statement.query_map(params![artifact_id], |row| {
            let created_at: String = row.get(2)?;
            Ok(ControllerTag {
                tag_id: row.get(0)?,
                name: row.get(1)?,
                created_at: parse_utc(&created_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn untag_artifact(&mut self, artifact_id: &str, tag_id: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM artifact_tags WHERE artifact_id = ?1 AND tag_id = ?2",
            params![artifact_id, tag_id],
        )? > 0)
    }

    pub fn link_cross_host_artifacts(
        &mut self,
        first_artifact_id: &str,
        second_artifact_id: &str,
        relationship_kind: &str,
    ) -> Result<CrossHostRelationship> {
        if first_artifact_id == second_artifact_id {
            anyhow::bail!("a cross-host relationship requires two different artifacts");
        }
        if !matches!(
            relationship_kind,
            "related" | "duplicate" | "same-policy" | "follow-up"
        ) {
            anyhow::bail!("unsupported cross-host relationship kind");
        }
        let first = self.artifact_relationship_summary(first_artifact_id)?;
        let second = self.artifact_relationship_summary(second_artifact_id)?;
        if first.0 == second.0 {
            anyhow::bail!("a cross-host relationship requires artifacts from different hosts");
        }
        let (left_artifact_id, right_artifact_id, left, right) =
            if first_artifact_id < second_artifact_id {
                (first_artifact_id, second_artifact_id, first, second)
            } else {
                (second_artifact_id, first_artifact_id, second, first)
            };
        let existing = self
            .connection
            .query_row(
                "SELECT relationship_id, created_at FROM cross_host_relationships
                 WHERE left_artifact_id = ?1 AND right_artifact_id = ?2 AND relationship_kind = ?3",
                params![left_artifact_id, right_artifact_id, relationship_kind],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let now = Utc::now();
        let (relationship_id, created_at) = existing
            .map(|(id, created_at)| (id, parse_utc(&created_at).unwrap_or(now)))
            .unwrap_or_else(|| (new_id("relationship"), now));
        self.connection.execute(
            "INSERT OR IGNORE INTO cross_host_relationships(relationship_id, left_artifact_id, right_artifact_id, relationship_kind, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![relationship_id, left_artifact_id, right_artifact_id, relationship_kind, created_at.to_rfc3339()],
        )?;
        Ok(CrossHostRelationship {
            relationship_id,
            relationship_kind: relationship_kind.to_owned(),
            left_artifact_id: left_artifact_id.to_owned(),
            left_host_id: left.0,
            left_title: left.1,
            right_artifact_id: right_artifact_id.to_owned(),
            right_host_id: right.0,
            right_title: right.1,
            created_at,
        })
    }

    pub fn list_cross_host_relationships(
        &self,
        artifact_id: &str,
    ) -> Result<Vec<CrossHostRelationship>> {
        let mut statement = self.connection.prepare(
            "SELECT r.relationship_id, r.relationship_kind,
                    left_artifact.artifact_id, left_artifact.host_id, left_artifact.title,
                    right_artifact.artifact_id, right_artifact.host_id, right_artifact.title,
                    r.created_at
             FROM cross_host_relationships r
             JOIN artifacts left_artifact ON left_artifact.artifact_id = r.left_artifact_id
             JOIN artifacts right_artifact ON right_artifact.artifact_id = r.right_artifact_id
             WHERE r.left_artifact_id = ?1 OR r.right_artifact_id = ?1
             ORDER BY r.created_at DESC, r.relationship_id",
        )?;
        let rows = statement.query_map(params![artifact_id], |row| {
            let created_at: String = row.get(8)?;
            Ok(CrossHostRelationship {
                relationship_id: row.get(0)?,
                relationship_kind: row.get(1)?,
                left_artifact_id: row.get(2)?,
                left_host_id: row.get(3)?,
                left_title: row.get(4)?,
                right_artifact_id: row.get(5)?,
                right_host_id: row.get(6)?,
                right_title: row.get(7)?,
                created_at: parse_utc(&created_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn unlink_cross_host_relationship(&mut self, relationship_id: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "DELETE FROM cross_host_relationships WHERE relationship_id = ?1",
            params![relationship_id],
        )? > 0)
    }

    fn artifact_relationship_summary(&self, artifact_id: &str) -> Result<(String, String)> {
        self.connection
            .query_row(
                "SELECT host_id, title FROM artifacts WHERE artifact_id = ?1",
                params![artifact_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("cannot relate an unknown artifact"))
    }

    pub fn artifact_source_hashes(&self) -> Result<HashMap<String, String>> {
        let mut statement = self
            .connection
            .prepare("SELECT artifact_id, source_hash FROM artifacts")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<HashMap<_, _>>>()?)
    }

    pub fn search_scoped(
        &mut self,
        query: &str,
        limit: usize,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SearchHit>> {
        self.search_filtered(
            query,
            limit,
            &SearchFilters {
                host_id: host_id.map(str::to_owned),
                provider_id: provider_id.map(str::to_owned),
                project_id: project_id.map(str::to_owned),
                ..SearchFilters::default()
            },
        )
    }

    pub fn search_filtered(
        &mut self,
        query: &str,
        limit: usize,
        filters: &SearchFilters,
    ) -> Result<Vec<SearchHit>> {
        let started = Instant::now();
        let mut sql = String::from(
            "SELECT a.artifact_id, a.project_id, p.trust_level, a.kind, a.lifecycle, a.title, a.source_reference,
                    snippet(search_content, 2, '[', ']', '…', 24), a.host_id, a.provider_id,
                    a.sensitivity, a.observed_at, a.source_hash
             FROM search_content JOIN artifacts a ON a.artifact_id = search_content.artifact_id
             LEFT JOIN projects p ON p.project_id = a.project_id AND p.host_id = a.host_id AND p.provider_id = a.provider_id
             WHERE search_content MATCH ?",
        );
        let mut values = vec![Value::Text(query.to_owned())];
        append_optional_constraint(
            &mut sql,
            &mut values,
            "a.host_id",
            filters.host_id.as_deref(),
        );
        append_optional_constraint(
            &mut sql,
            &mut values,
            "a.provider_id",
            filters.provider_id.as_deref(),
        );
        append_optional_constraint(
            &mut sql,
            &mut values,
            "a.project_id",
            filters.project_id.as_deref(),
        );
        append_text_list_constraint(
            &mut sql,
            &mut values,
            "p.trust_level",
            &filters.project_trust_levels,
        );
        append_json_enum_constraint(&mut sql, &mut values, "a.kind", &filters.artifact_kinds)?;
        append_json_enum_constraint(
            &mut sql,
            &mut values,
            "a.lifecycle",
            &filters.lifecycle_states,
        )?;
        if let Some(sensitivity_max) = &filters.sensitivity_max {
            sql.push_str(
                " AND CASE a.sensitivity
                    WHEN '\"Public\"' THEN 0
                    WHEN '\"Internal\"' THEN 1
                    WHEN '\"Sensitive\"' THEN 2
                    WHEN '\"SecretLike\"' THEN 3
                    ELSE 3 END <= ?",
            );
            values.push(Value::Integer(sensitivity_rank(sensitivity_max)));
        }
        if let Some(observed_after) = filters.observed_after {
            sql.push_str(" AND a.observed_at >= ?");
            values.push(Value::Text(observed_after.to_rfc3339()));
        }
        if let Some(observed_before) = filters.observed_before {
            sql.push_str(" AND a.observed_at <= ?");
            values.push(Value::Text(observed_before.to_rfc3339()));
        }
        sql.push_str(" ORDER BY rank LIMIT ?");
        values.push(Value::Integer(limit.clamp(1, 200) as i64));

        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
            let kind: String = row.get(3)?;
            let lifecycle: String = row.get(4)?;
            let sensitivity: String = row.get(10)?;
            let observed_at: String = row.get(11)?;
            Ok(SearchHit {
                artifact_id: row.get(0)?,
                project_id: row.get(1)?,
                project_trust_level: row.get(2)?,
                kind: serde_json::from_str(&kind).unwrap_or(ArtifactKind::ProjectContext),
                lifecycle: serde_json::from_str(&lifecycle).unwrap_or(LifecycleState::Stale),
                title: row.get(5)?,
                source_reference: row.get(6)?,
                preview: row.get(7)?,
                host_id: row.get(8)?,
                provider_id: row.get(9)?,
                source_hash: row.get(12)?,
                sensitivity: serde_json::from_str(&sensitivity)
                    .unwrap_or(SensitivityClass::Sensitive),
                observed_at: DateTime::parse_from_rfc3339(&observed_at)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;
        let hits = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.record_search_run(&SearchRunRecord {
            search_run_id: new_id("search"),
            host_id: filters.host_id.clone(),
            provider_id: filters.provider_id.clone(),
            correlation_id: new_id("search-correlation"),
            completed_at: Utc::now(),
            duration_ms,
            result_count: hits.len(),
            limit: limit.clamp(1, 200),
        })?;
        Ok(hits)
    }

    pub fn artifact_count(&self) -> Result<i64> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))?)
    }

    pub fn list_projects(&self, host_id: Option<&str>) -> Result<Vec<ProjectRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT project_id, host_id, provider_id, root_path, display_name, trust_level, discovered_from, observed_at
             FROM projects WHERE (?1 IS NULL OR host_id = ?1) ORDER BY display_name, root_path",
        )?;
        let rows = statement.query_map(params![host_id], |row| {
            let observed_at: String = row.get(7)?;
            Ok(ProjectRecord {
                project_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                root_path: row.get(3)?,
                display_name: row.get(4)?,
                trust_level: row.get(5)?,
                discovered_from: row.get(6)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_sessions(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SessionRecord>> {
        self.list_sessions_filtered(&SessionFilters {
            host_id: host_id.map(str::to_owned),
            project_id: project_id.map(str::to_owned),
            ..SessionFilters::default()
        })
    }

    pub fn list_sessions_filtered(&self, filters: &SessionFilters) -> Result<Vec<SessionRecord>> {
        let mut sql = String::from(
            "SELECT session_id, host_id, provider_id, project_id, title, cwd, model, branch, started_at, ended_at, archived, source_reference, source_hash, metadata_json, observed_at
             FROM sessions WHERE 1 = 1",
        );
        let mut values = Vec::new();
        append_optional_constraint(&mut sql, &mut values, "host_id", filters.host_id.as_deref());
        append_optional_constraint(
            &mut sql,
            &mut values,
            "provider_id",
            filters.provider_id.as_deref(),
        );
        append_optional_constraint(
            &mut sql,
            &mut values,
            "project_id",
            filters.project_id.as_deref(),
        );
        append_optional_constraint(&mut sql, &mut values, "branch", filters.branch.as_deref());
        append_optional_constraint(&mut sql, &mut values, "model", filters.model.as_deref());
        if let Some(archived) = filters.archived {
            sql.push_str(" AND archived = ?");
            values.push(Value::Integer(i64::from(archived)));
        }
        if let Some(started_after) = filters.started_after {
            sql.push_str(" AND COALESCE(started_at, observed_at) >= ?");
            values.push(Value::Text(started_after.to_rfc3339()));
        }
        if let Some(started_before) = filters.started_before {
            sql.push_str(" AND COALESCE(started_at, observed_at) <= ?");
            values.push(Value::Text(started_before.to_rfc3339()));
        }
        sql.push_str(" ORDER BY COALESCE(started_at, observed_at) DESC");
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
            let started_at: Option<String> = row.get(8)?;
            let ended_at: Option<String> = row.get(9)?;
            let observed_at: String = row.get(14)?;
            Ok(SessionRecord {
                session_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                project_id: row.get(3)?,
                title: row.get(4)?,
                cwd: row.get(5)?,
                model: row.get(6)?,
                branch: row.get(7)?,
                started_at: started_at.as_deref().and_then(parse_utc),
                ended_at: ended_at.as_deref().and_then(parse_utc),
                archived: row.get::<_, i64>(10)? != 0,
                source_reference: row.get(11)?,
                source_hash: row.get(12)?,
                metadata_json: row.get(13)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_memory_records(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<MemoryRecord>> {
        self.list_memory_records_scoped(host_id, None, project_id)
    }

    pub fn list_memory_records_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<MemoryRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT memory_record_id, host_id, provider_id, project_id, title, content, source_reference, source_hash, lifecycle, confidence, observed_at
             FROM memory_records WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2) AND (?3 IS NULL OR project_id = ?3)
             ORDER BY observed_at DESC",
        )?;
        let rows = statement.query_map(params![host_id, provider_id, project_id], |row| {
            let lifecycle: String = row.get(8)?;
            let observed_at: String = row.get(10)?;
            Ok(MemoryRecord {
                memory_record_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                project_id: row.get(3)?,
                title: row.get(4)?,
                content: row.get(5)?,
                source_reference: row.get(6)?,
                source_hash: row.get(7)?,
                lifecycle: serde_json::from_str(&lifecycle)
                    .unwrap_or(amcp_domain::LifecycleState::Stale),
                confidence: row.get(9)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Delete one AMCP-collected memory version and every local projection that
    /// can contain it. A source-hash tombstone preserves the user's deletion
    /// choice during a replay, while a changed native source is eligible for a
    /// fresh collection.
    pub fn forget_memory_record(
        &mut self,
        memory_record_id: &str,
        host_id: &str,
        provider_id: &str,
        reason: &str,
    ) -> Result<MemoryForgetReceipt> {
        if reason.trim().is_empty() {
            anyhow::bail!("central memory deletion requires a reason");
        }
        let transaction = self
            .connection
            .transaction()
            .context("start central memory deletion transaction")?;
        let memory: Option<(String, String)> = transaction
            .query_row(
                "SELECT source_reference, source_hash FROM memory_records
                 WHERE memory_record_id = ?1 AND host_id = ?2 AND provider_id = ?3",
                params![memory_record_id, host_id, provider_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((source_reference, source_hash)) = memory else {
            anyhow::bail!("memory record is not indexed in the requested host/provider scope");
        };
        let artifact_ids = {
            let mut statement = transaction.prepare(
                "SELECT artifact_id FROM artifacts
                 WHERE host_id = ?1 AND provider_id = ?2 AND native_id = ?3",
            )?;
            statement
                .query_map(params![host_id, provider_id, source_reference], |row| {
                    row.get(0)
                })?
                .collect::<rusqlite::Result<Vec<String>>>()?
        };
        let has_rag_chunks = sqlite_table_exists(&transaction, "rag_chunks")?;
        let has_retrieval_runs = sqlite_table_exists(&transaction, "rag_retrieval_runs")?;
        let mut deleted_rag_chunks = 0;
        if has_rag_chunks {
            for artifact_id in &artifact_ids {
                deleted_rag_chunks += transaction.execute(
                    "DELETE FROM rag_chunks WHERE record_id = ?1",
                    params![artifact_id],
                )?;
            }
        }
        let cleared_retrieval_runs = if has_retrieval_runs && !artifact_ids.is_empty() {
            transaction.execute("DELETE FROM rag_retrieval_runs", [])?
        } else {
            0
        };
        for artifact_id in &artifact_ids {
            transaction.execute(
                "DELETE FROM evidence_snapshots WHERE observation_id IN
                 (SELECT observation_id FROM source_observations WHERE artifact_id = ?1)",
                params![artifact_id],
            )?;
            transaction.execute(
                "DELETE FROM source_observations WHERE artifact_id = ?1",
                params![artifact_id],
            )?;
            transaction.execute(
                "DELETE FROM search_content WHERE artifact_id = ?1",
                params![artifact_id],
            )?;
            transaction.execute(
                "DELETE FROM artifacts WHERE artifact_id = ?1",
                params![artifact_id],
            )?;
        }
        transaction.execute(
            "DELETE FROM memory_records
             WHERE memory_record_id = ?1 AND host_id = ?2 AND provider_id = ?3",
            params![memory_record_id, host_id, provider_id],
        )?;
        let tombstone_id = new_id("tombstone");
        transaction.execute(
            "INSERT INTO policy_tombstones(tombstone_id, host_id, provider_id, native_id, source_hash, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(host_id, provider_id, native_id, source_hash) DO UPDATE SET
                 tombstone_id = excluded.tombstone_id,
                 reason = excluded.reason,
                 created_at = excluded.created_at",
            params![
                tombstone_id,
                host_id,
                provider_id,
                source_reference,
                source_hash,
                reason,
                Utc::now().to_rfc3339(),
            ],
        )?;
        transaction
            .commit()
            .context("commit central memory deletion transaction")?;
        self.restrict_catalog_files()?;
        Ok(MemoryForgetReceipt {
            memory_record_id: memory_record_id.to_owned(),
            host_id: host_id.to_owned(),
            provider_id: provider_id.to_owned(),
            tombstone_id,
            deleted_artifacts: artifact_ids.len(),
            deleted_rag_chunks,
            cleared_retrieval_runs,
            deleted_at: Utc::now(),
        })
    }

    pub fn list_session_items(
        &self,
        session_id: &str,
        host_id: Option<&str>,
    ) -> Result<Vec<SessionItem>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, host_id, provider_id, sequence, role, item_kind, content, source_reference, observed_at
             FROM session_items WHERE session_id = ?1 AND (?2 IS NULL OR host_id = ?2)
             ORDER BY sequence",
        )?;
        let rows = statement.query_map(params![session_id, host_id], |row| {
            let observed_at: String = row.get(8)?;
            Ok(SessionItem {
                session_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                sequence: row.get(3)?,
                role: row.get(4)?,
                item_kind: row.get(5)?,
                content: row.get(6)?,
                source_reference: row.get(7)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_runtime_events(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RuntimeEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT event_id, host_id, provider_id, event_type, sequence, payload_json, occurred_at
             FROM runtime_events WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2)
             ORDER BY occurred_at DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![host_id, provider_id, limit as i64], |row| {
            let occurred_at: String = row.get(6)?;
            Ok(RuntimeEvent {
                event_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                event_type: row.get(3)?,
                sequence: row.get(4)?,
                payload_json: row.get(5)?,
                occurred_at: parse_utc(&occurred_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_config_layers(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ConfigLayerRecord>> {
        self.list_config_layers_scoped(host_id, None, project_id)
    }

    pub fn list_config_layers_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ConfigLayerRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT config_layer_id, host_id, provider_id, project_id, source_reference, scope, profile, precedence_rank, source_hash, observed_at
             FROM config_layers WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2) AND (?3 IS NULL OR project_id = ?3)
             ORDER BY precedence_rank, source_reference",
        )?;
        let rows = statement.query_map(params![host_id, provider_id, project_id], |row| {
            let observed_at: String = row.get(9)?;
            Ok(ConfigLayerRecord {
                config_layer_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                project_id: row.get(3)?,
                source_reference: row.get(4)?,
                scope: row.get(5)?,
                profile: row.get(6)?,
                precedence_rank: row.get(7)?,
                source_hash: row.get(8)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_guidance(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<GuidanceRecord>> {
        self.list_guidance_scoped(host_id, None, project_id)
    }

    pub fn list_guidance_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<GuidanceRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT guidance_id, host_id, provider_id, project_id, source_reference, relative_scope, kind, precedence_rank, source_hash, observed_at
             FROM guidance_records WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2) AND (?3 IS NULL OR project_id = ?3 OR project_id IS NULL)
             ORDER BY precedence_rank, source_reference",
        )?;
        let rows = statement.query_map(params![host_id, provider_id, project_id], |row| {
            let observed_at: String = row.get(9)?;
            Ok(GuidanceRecord {
                guidance_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_id: row.get(2)?,
                project_id: row.get(3)?,
                source_reference: row.get(4)?,
                relative_scope: row.get(5)?,
                kind: row.get(6)?,
                precedence_rank: row.get(7)?,
                source_hash: row.get(8)?,
                observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn latest_cursor(&self, host_id: &str, provider_id: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT cursor FROM collection_cursors WHERE host_id = ?1 AND provider_id = ?2",
                params![host_id, provider_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn save_cursor(
        &mut self,
        host_id: &str,
        provider_id: &str,
        cursor: Option<&str>,
        collection_run_id: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO collection_cursors(host_id, provider_id, cursor, collection_run_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id, provider_id) DO UPDATE SET cursor=excluded.cursor, collection_run_id=excluded.collection_run_id, updated_at=excluded.updated_at",
            params![host_id, provider_id, cursor, collection_run_id, Utc::now().to_rfc3339()],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn save_change_set(&mut self, change_set: &ChangeSet) -> Result<()> {
        self.connection.execute(
            "INSERT INTO change_sets(change_set_id, host_id, provider_id, actor, scope_json, reason, evidence_ids_json, status, change_set_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(change_set_id) DO UPDATE SET status=excluded.status, change_set_json=excluded.change_set_json, updated_at=excluded.updated_at",
            params![
                change_set.change_set_id,
                change_set.scope.host_id,
                change_set.provider_id,
                change_set.actor,
                serde_json::to_string(&change_set.scope)?,
                change_set.reason,
                serde_json::to_string(&change_set.evidence_ids)?,
                serde_json::to_string(&change_set.status)?,
                serde_json::to_string(change_set)?,
                change_set.created_at.to_rfc3339(),
                change_set.updated_at.to_rfc3339(),
            ],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn register_host(&mut self, host: &HostIdentity) -> Result<()> {
        self.connection.execute(
            "INSERT INTO hosts(host_id, display_name, platform, hostname, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id) DO UPDATE SET display_name=excluded.display_name, platform=excluded.platform, hostname=excluded.hostname, last_seen=excluded.last_seen",
            params![
                host.host_id,
                host.display_name,
                host.platform,
                host.hostname,
                Utc::now().to_rfc3339(),
            ],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn register_connection(
        &mut self,
        host: &HostIdentity,
        endpoint: Option<&str>,
        agent_version: Option<&str>,
        capabilities: &[String],
    ) -> Result<()> {
        self.register_host(host)?;
        self.connection.execute(
            "INSERT INTO agent_connections(host_id, endpoint, status, agent_version, capabilities_json, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(host_id) DO UPDATE SET endpoint=excluded.endpoint, status=excluded.status, agent_version=excluded.agent_version, capabilities_json=excluded.capabilities_json, last_seen=excluded.last_seen",
            params![
                host.host_id,
                endpoint,
                serde_json::to_string(&HostStatus::Connected)?,
                agent_version,
                serde_json::to_string(capabilities)?,
                Utc::now().to_rfc3339(),
            ],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn register_provider_descriptors(
        &mut self,
        host: &HostIdentity,
        descriptors: &[amcp_domain::ProviderDescriptor],
    ) -> Result<()> {
        self.register_host(host)?;
        for provider in descriptors {
            self.connection.execute(
                "INSERT INTO providers(provider_id, host_id, display_name, version, adapter_version, schema_fingerprint, support_level, health, compatibility, native_roots_json, capabilities_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(provider_id, host_id) DO UPDATE SET display_name=excluded.display_name, version=excluded.version, adapter_version=excluded.adapter_version, schema_fingerprint=excluded.schema_fingerprint, support_level=excluded.support_level, health=excluded.health, compatibility=excluded.compatibility, native_roots_json=excluded.native_roots_json, capabilities_json=excluded.capabilities_json",
                params![
                    provider.id,
                    host.host_id,
                    provider.display_name,
                    provider.version,
                    provider.adapter_version,
                    provider.schema_fingerprint,
                    serde_json::to_string(&provider.support_level)?,
                    serde_json::to_string(&provider.health)?,
                    serde_json::to_string(&provider.compatibility)?,
                    serde_json::to_string(&provider.native_roots)?,
                    serde_json::to_string(&provider.capabilities)?,
                ],
            )?;
        }
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn load_change_set(&self, change_set_id: &str) -> Result<Option<ChangeSet>> {
        let encoded: Option<String> = self
            .connection
            .query_row(
                "SELECT change_set_json FROM change_sets WHERE change_set_id = ?1",
                params![change_set_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| serde_json::from_str(&value).context("decode stored change set"))
            .transpose()
    }

    pub fn list_change_sets(&self, status: Option<ChangeStatus>) -> Result<Vec<ChangeSet>> {
        let mut statement = if let Some(status) = status {
            let encoded = serde_json::to_string(&status)?;
            let mut statement = self.connection.prepare(
                "SELECT change_set_json FROM change_sets WHERE status = ?1 ORDER BY updated_at DESC",
            )?;
            let rows = statement.query_map(params![encoded], |row| row.get::<_, String>(0))?;
            return rows
                .map(|row| {
                    let encoded = row?;
                    serde_json::from_str(&encoded).context("decode stored change set")
                })
                .collect::<Result<Vec<_>>>();
        } else {
            self.connection
                .prepare("SELECT change_set_json FROM change_sets ORDER BY updated_at DESC")?
        };
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let encoded = row?;
            serde_json::from_str(&encoded).context("decode stored change set")
        })
        .collect::<Result<Vec<_>>>()
    }

    pub fn record_audit(&mut self, event: &AuditEvent) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO audit_events(audit_event_id, actor, operation, target, host_id, provider_id, before_hash, after_hash, result, correlation_id, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.audit_event_id,
                event.actor,
                event.operation,
                event.target,
                event.host_id,
                event.provider_id,
                event.before_hash,
                event.after_hash,
                event.result,
                event.correlation_id,
                event.timestamp.to_rfc3339(),
            ],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }

    pub fn audit_event_count(&self) -> Result<usize> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?;
        usize::try_from(count).context("audit event count must be non-negative")
    }

    /// Return a bounded, metadata-only audit view. Audit rows deliberately do
    /// not carry artifact bodies, diffs, or provider payloads.
    pub fn list_audit_events(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 100) as i64;
        let mut statement = self.connection.prepare(
            "SELECT audit_event_id, actor, operation, target, host_id, provider_id, before_hash, after_hash, result, correlation_id, timestamp
             FROM audit_events
             WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR provider_id = ?2)
             ORDER BY timestamp DESC, audit_event_id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![host_id, provider_id, limit], |row| {
            let timestamp: String = row.get(10)?;
            Ok(AuditEvent {
                audit_event_id: row.get(0)?,
                actor: row.get(1)?,
                operation: row.get(2)?,
                target: row.get(3)?,
                host_id: row.get(4)?,
                provider_id: row.get(5)?,
                before_hash: row.get(6)?,
                after_hash: row.get(7)?,
                result: row.get(8)?,
                correlation_id: row.get(9)?,
                timestamp: parse_utc(&timestamp).unwrap_or_else(Utc::now),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn diagnostics(&self) -> Result<CatalogDiagnostics> {
        let stale_lifecycle = serde_json::to_string(&LifecycleState::Stale)?;
        let total_artifact_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        let stale_artifact_count = self.connection.query_row(
            "SELECT COUNT(*) FROM artifacts WHERE lifecycle = ?1",
            params![&stale_lifecycle],
            |row| row.get::<_, i64>(0),
        )?;
        let search_indexed_artifact_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM search_content", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        let mut stale_statement = self.connection.prepare(
            "SELECT artifact_id, host_id, provider_id, project_id, kind, title, source_reference, observed_at
             FROM artifacts WHERE lifecycle = ?1
             ORDER BY observed_at DESC LIMIT 50",
        )?;
        let stale_artifacts = stale_statement
            .query_map(params![&stale_lifecycle], |row| {
                let kind: String = row.get(4)?;
                let observed_at: String = row.get(7)?;
                Ok(ArtifactDiagnostic {
                    artifact_id: row.get(0)?,
                    host_id: row.get(1)?,
                    provider_id: row.get(2)?,
                    project_id: row.get(3)?,
                    kind: serde_json::from_str(&kind).unwrap_or(ArtifactKind::ProjectContext),
                    title: row.get(5)?,
                    source_reference: row.get(6)?,
                    observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut project_statement = self.connection.prepare(
            "SELECT project_id, host_id, provider_id, root_path, display_name, trust_level, discovered_from, observed_at
             FROM projects
             WHERE trust_level IS NULL OR LOWER(trust_level) != 'trusted'
             ORDER BY observed_at DESC LIMIT 50",
        )?;
        let projects_requiring_attention = project_statement
            .query_map([], |row| {
                let observed_at: String = row.get(7)?;
                Ok(ProjectRecord {
                    project_id: row.get(0)?,
                    host_id: row.get(1)?,
                    provider_id: row.get(2)?,
                    root_path: row.get(3)?,
                    display_name: row.get(4)?,
                    trust_level: row.get(5)?,
                    discovered_from: row.get(6)?,
                    observed_at: parse_utc(&observed_at).unwrap_or_else(Utc::now),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let conflict_status = serde_json::to_string(&ChangeStatus::Conflict)?;
        let applied_status = serde_json::to_string(&ChangeStatus::Applied)?;
        let rolled_back_status = serde_json::to_string(&ChangeStatus::RolledBack)?;
        let mut conflict_statement = self.connection.prepare(
            "SELECT change_set_id, host_id, provider_id, updated_at
             FROM change_sets WHERE status = ?1
             ORDER BY updated_at DESC LIMIT 50",
        )?;
        let conflicted_changes = conflict_statement
            .query_map(params![&conflict_status], |row| {
                let updated_at: String = row.get(3)?;
                Ok(ChangeConflictDiagnostic {
                    change_set_id: row.get(0)?,
                    host_id: row.get(1)?,
                    provider_id: row.get(2)?,
                    updated_at: parse_utc(&updated_at).unwrap_or_else(Utc::now),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let diagnostic_event_count = self.connection.query_row(
            "SELECT COUNT(*) FROM runtime_events WHERE event_type = 'diagnostic.updated'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let applied_change_count = self.connection.query_row(
            "SELECT COUNT(*) FROM change_sets WHERE status = ?1",
            params![applied_status],
            |row| row.get::<_, i64>(0),
        )?;
        let conflicted_change_count = self.connection.query_row(
            "SELECT COUNT(*) FROM change_sets WHERE status = ?1",
            params![&conflict_status],
            |row| row.get::<_, i64>(0),
        )?;
        let rolled_back_change_count = self.connection.query_row(
            "SELECT COUNT(*) FROM change_sets WHERE status = ?1",
            params![rolled_back_status],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(CatalogDiagnostics {
            total_artifact_count: usize::try_from(total_artifact_count)?,
            stale_artifact_count: usize::try_from(stale_artifact_count)?,
            stale_source_ratio: ratio(stale_artifact_count, total_artifact_count),
            search_indexed_artifact_count: usize::try_from(search_indexed_artifact_count)?,
            search_index_coverage_ratio: ratio(search_indexed_artifact_count, total_artifact_count),
            database_size_bytes: self.database_size_bytes(),
            applied_change_count: usize::try_from(applied_change_count)?,
            conflicted_change_count: usize::try_from(conflicted_change_count)?,
            rolled_back_change_count: usize::try_from(rolled_back_change_count)?,
            stale_artifacts,
            projects_requiring_attention,
            conflicted_changes,
            recent_provider_diagnostic_event_count: usize::try_from(diagnostic_event_count)?,
        })
    }

    fn database_size_bytes(&self) -> u64 {
        self.database_path
            .iter()
            .flat_map(|database_path| {
                [
                    database_path.clone(),
                    std::path::PathBuf::from(format!("{}-wal", database_path.display())),
                    std::path::PathBuf::from(format!("{}-shm", database_path.display())),
                ]
            })
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT h.host_id, h.display_name, h.platform, h.hostname,
                    COALESCE(c.last_seen, h.last_seen), c.endpoint, c.agent_version, c.status,
                    c.capabilities_json, GROUP_CONCAT(p.provider_id)
             FROM hosts h LEFT JOIN providers p ON p.host_id = h.host_id
                    LEFT JOIN agent_connections c ON c.host_id = h.host_id
             GROUP BY h.host_id ORDER BY h.display_name",
        )?;
        let rows = statement.query_map([], |row| {
            let last_seen: Option<String> = row.get(4)?;
            let provider_ids: Option<String> = row.get(9)?;
            let status: Option<String> = row.get(7)?;
            let capabilities_json: Option<String> = row.get(8)?;
            let parsed_last_seen = last_seen.as_deref().and_then(parse_utc);
            let stored_status = status
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok());
            let effective_status = match stored_status.unwrap_or_else(|| {
                if parsed_last_seen.is_some() {
                    HostStatus::Connected
                } else {
                    HostStatus::Disconnected
                }
            }) {
                HostStatus::Connected
                    if parsed_last_seen.is_some_and(|value| {
                        (Utc::now() - value).num_seconds() > HEARTBEAT_STALE_AFTER_SECONDS
                    }) =>
                {
                    HostStatus::Disconnected
                }
                value => value,
            };
            Ok(HostRecord {
                identity: amcp_domain::HostIdentity {
                    host_id: row.get(0)?,
                    display_name: row.get(1)?,
                    platform: row.get(2)?,
                    hostname: row.get(3)?,
                },
                endpoint: row.get(5)?,
                agent_version: row
                    .get::<_, Option<String>>(6)?
                    .and_then(|value| value.split(',').next().map(str::to_owned)),
                status: effective_status,
                capabilities: capabilities_json
                    .and_then(|value| serde_json::from_str(&value).ok())
                    .or_else(|| {
                        provider_ids.map(|value| value.split(',').map(str::to_owned).collect())
                    })
                    .unwrap_or_default(),
                enrolled_at: Utc::now(),
                last_seen: parsed_last_seen,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_providers(&self, host_id: Option<&str>) -> Result<Vec<ProviderRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT host_id, provider_id, display_name, version, adapter_version, schema_fingerprint, support_level, health, compatibility, native_roots_json, capabilities_json
             FROM providers
             WHERE (?1 IS NULL OR host_id = ?1)
             ORDER BY host_id, display_name, provider_id",
        )?;
        let rows = statement.query_map(params![host_id], |row| {
            let support_level: String = row.get(6)?;
            let health: String = row.get(7)?;
            let compatibility: String = row.get(8)?;
            let native_roots_json: String = row.get(9)?;
            let capabilities_json: String = row.get(10)?;
            Ok(ProviderRecord {
                host_id: row.get(0)?,
                provider_id: row.get(1)?,
                display_name: row.get(2)?,
                version: row.get(3)?,
                adapter_version: row.get(4)?,
                schema_fingerprint: row.get(5)?,
                support_level: parse_provider_support_level(&support_level),
                health: parse_provider_health(&health),
                compatibility: parse_provider_compatibility(&compatibility),
                native_roots: serde_json::from_str(&native_roots_json).unwrap_or_default(),
                capabilities: serde_json::from_str(&capabilities_json).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Records Controller-observed health without retaining provider errors or
    /// native payloads. Provider descriptors are registered before collection,
    /// so this targets one known host/provider pair.
    pub fn set_provider_health(
        &mut self,
        host_id: &str,
        provider_id: &str,
        health: ProviderHealth,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE providers SET health = ?1 WHERE host_id = ?2 AND provider_id = ?3",
            params![serde_json::to_string(&health)?, host_id, provider_id],
        )?;
        self.restrict_catalog_files()?;
        Ok(())
    }
}

fn index_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IndexRunRecord> {
    let started_at: String = row.get(3)?;
    let completed_at: Option<String> = row.get(4)?;
    Ok(IndexRunRecord {
        run_id: row.get(0)?,
        mode: row.get(1)?,
        status: row.get(2)?,
        started_at: parse_utc(&started_at).unwrap_or_else(Utc::now),
        completed_at: completed_at.as_deref().and_then(parse_utc),
        indexed_count: row.get::<_, i64>(5)?.max(0) as usize,
        last_artifact_id: row.get(6)?,
        error: row.get(7)?,
    })
}

fn collection_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CollectionRunRecord> {
    let started_at: String = row.get(7)?;
    let completed_at: String = row.get(8)?;
    Ok(CollectionRunRecord {
        collection_run_id: row.get(0)?,
        host_id: row.get(1)?,
        provider_id: row.get(2)?,
        request_id: row.get(3)?,
        correlation_id: row.get(4)?,
        status: row.get(5)?,
        failure_kind: row.get(6)?,
        started_at: parse_utc(&started_at).unwrap_or_else(Utc::now),
        completed_at: parse_utc(&completed_at).unwrap_or_else(Utc::now),
        duration_ms: row.get::<_, i64>(9)?.max(0) as u64,
        discovered_count: row.get::<_, i64>(10)?.max(0) as usize,
        inserted_count: row.get::<_, i64>(11)?.max(0) as usize,
        replayed_batch_count: row.get::<_, i64>(12)?.max(0) as usize,
    })
}

fn search_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SearchRunRecord> {
    let completed_at: String = row.get(4)?;
    Ok(SearchRunRecord {
        search_run_id: row.get(0)?,
        host_id: row.get(1)?,
        provider_id: row.get(2)?,
        correlation_id: row.get(3)?,
        completed_at: parse_utc(&completed_at).unwrap_or_else(Utc::now),
        duration_ms: row.get::<_, i64>(5)?.max(0) as u64,
        result_count: row.get::<_, i64>(6)?.max(0) as usize,
        limit: row.get::<_, i64>(7)?.max(0) as usize,
    })
}

fn parse_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        0.0
    } else {
        numerator.max(0) as f64 / denominator as f64
    }
}

fn parse_provider_support_level(value: &str) -> ProviderSupportLevel {
    serde_json::from_str(value).unwrap_or(match value {
        "full" => ProviderSupportLevel::Full,
        "read-only" => ProviderSupportLevel::ReadOnly,
        "unsupported" => ProviderSupportLevel::Unsupported,
        _ => ProviderSupportLevel::InventoryOnly,
    })
}

fn parse_provider_health(value: &str) -> ProviderHealth {
    serde_json::from_str(value).unwrap_or(match value {
        "healthy" => ProviderHealth::Healthy,
        "degraded" => ProviderHealth::Degraded,
        "unavailable" => ProviderHealth::Unavailable,
        _ => ProviderHealth::Unknown,
    })
}

fn parse_provider_compatibility(value: &str) -> ProviderCompatibility {
    serde_json::from_str(value).unwrap_or(match value {
        "compatible" => ProviderCompatibility::Compatible,
        "unsupported" => ProviderCompatibility::Unsupported,
        _ => ProviderCompatibility::Unknown,
    })
}

fn append_optional_constraint(
    sql: &mut String,
    values: &mut Vec<Value>,
    column: &str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        sql.push_str(" AND ");
        sql.push_str(column);
        sql.push_str(" = ?");
        values.push(Value::Text(value.to_owned()));
    }
}

fn append_json_enum_constraint<T: Serialize>(
    sql: &mut String,
    values: &mut Vec<Value>,
    column: &str,
    requested: &[T],
) -> Result<()> {
    if requested.is_empty() {
        return Ok(());
    }
    sql.push_str(" AND ");
    sql.push_str(column);
    sql.push_str(" IN (");
    for (index, value) in requested.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push('?');
        values.push(Value::Text(serde_json::to_string(value)?));
    }
    sql.push(')');
    Ok(())
}

fn append_text_list_constraint(
    sql: &mut String,
    values: &mut Vec<Value>,
    column: &str,
    requested: &[String],
) {
    if requested.is_empty() {
        return;
    }
    sql.push_str(" AND ");
    sql.push_str(column);
    sql.push_str(" IN (");
    for (index, value) in requested.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push('?');
        values.push(Value::Text(value.to_owned()));
    }
    sql.push(')');
}

fn sensitivity_rank(value: &SensitivityClass) -> i64 {
    match value {
        SensitivityClass::Public => 0,
        SensitivityClass::Internal => 1,
        SensitivityClass::Sensitive => 2,
        SensitivityClass::SecretLike => 3,
    }
}

fn is_policy_tombstoned(
    transaction: &rusqlite::Transaction<'_>,
    host_id: &str,
    provider_id: &str,
    native_id: &str,
    source_hash: &str,
) -> Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM policy_tombstones
            WHERE host_id = ?1 AND provider_id = ?2 AND native_id = ?3
              AND (source_hash IS NULL OR source_hash = ?4)
        )",
        params![host_id, provider_id, native_id, source_hash],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn sqlite_table_exists(transaction: &rusqlite::Transaction<'_>, table: &str) -> Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn backup_reason_slug(reason: &str) -> Result<String> {
    let slug = reason
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if slug.is_empty() || slug.chars().count() > 48 {
        anyhow::bail!("backup reason must contain 1 to 48 characters")
    }
    Ok(slug)
}

fn prepare_private_backup_directory(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory).context("create AMCP backup directory")?;
    let metadata = fs::symlink_metadata(directory).context("inspect AMCP backup directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("AMCP backup directory must be a non-symlink directory");
    }
    #[cfg(unix)]
    fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .context("restrict AMCP backup directory permissions")?;
    Ok(())
}

/// Create a local SQLite database path without following symlinks and make the
/// database file private on Unix. Both the central catalog and its derived RAG
/// projection use this because they share a physical database.
pub fn prepare_private_database_path(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        #[cfg(unix)]
        let parent_was_missing = !parent.exists();
        fs::create_dir_all(parent).context("create AMCP catalog directory")?;
        #[cfg(unix)]
        if parent_was_missing {
            fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .context("restrict newly created AMCP catalog directory")?;
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("AMCP catalog path must not be a symlink");
            }
            if !metadata.is_file() {
                anyhow::bail!("AMCP catalog path must be a regular file");
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => {}
                // Another Controller or MCP request created the catalog after
                // the metadata check. Validate and harden the resulting path
                // below instead of failing a safe concurrent open.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("create private AMCP catalog"),
            }
            #[cfg(not(unix))]
            match fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("create AMCP catalog"),
            }
        }
        Err(error) => return Err(error).context("inspect AMCP catalog path"),
    }
    let metadata = fs::symlink_metadata(path).context("reinspect AMCP catalog path")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("AMCP catalog path must be a regular non-symlink file");
    }
    restrict_file_to_current_user(path)
}

/// Re-apply private permissions after a SQLite write, including WAL/SHM files
/// that may have been created by the current connection.
pub fn harden_private_database_path(path: &Path) -> Result<()> {
    restrict_file_to_current_user(path)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            restrict_file_to_current_user(&sidecar)?;
        }
    }
    Ok(())
}

fn restrict_file_to_current_user(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect AMCP catalog file")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("AMCP catalog file must be a regular non-symlink file");
    }
    #[cfg(unix)]
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("restrict AMCP catalog file permissions")?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn is_absolute_source_root(value: &str) -> bool {
    let bytes = value.as_bytes();
    Path::new(value).is_absolute()
        || value.starts_with('/')
        || value.starts_with('\\')
        || (bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'/' | b'\\'))
}

fn is_safe_relative_source_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    !(normalized.is_empty()
        || is_absolute_source_root(value)
        || normalized
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        || (normalized.len() >= 2 && normalized.as_bytes()[1] == b':'))
}

fn join_source_reference(root: &str, relative: &str) -> String {
    let separator = if root.contains('\\') { '\\' } else { '/' };
    let root = root.trim_end_matches(['/', '\\']);
    let relative = relative.trim_start_matches(['/', '\\']);
    format!("{root}{separator}{relative}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcp_domain::{
        ArtifactKind, ArtifactRecord, ConfigLayerRecord, EvidenceSnapshot, GuidanceEdge,
        GuidanceRecord, HostIdentity, LifecycleState, MemoryRecord, ObservationState,
        ProjectRecord, ProviderDescriptor, RuntimeEvent, SessionItem, SessionRecord,
        SourceObservation, new_id,
    };

    fn batch() -> CollectionBatch {
        let host = HostIdentity {
            host_id: "host_test".into(),
            display_name: "Test".into(),
            platform: "macos".into(),
            hostname: "test.local".into(),
        };
        let observation_id = new_id("obs");
        let now = Utc::now();
        let source_hash: String = "hash".into();
        let observation = SourceObservation {
            observation_id: observation_id.clone(),
            host_id: host.host_id.clone(),
            provider_id: "codex".into(),
            native_id: "config".into(),
            source_reference: "/tmp/config.toml".into(),
            source_hash: source_hash.clone(),
            observed_at: now,
            parser_version: "test".into(),
            schema_fingerprint: "toml".into(),
            redaction_policy_version: "test".into(),
            collection_run_id: "run".into(),
            state: ObservationState::Present,
        };
        CollectionBatch {
            collection_run_id: "run".into(),
            host,
            providers: vec![ProviderDescriptor {
                id: "codex".into(),
                display_name: "Codex".into(),
                version: None,
                adapter_version: "test".into(),
                schema_fingerprint: "codex-test-v1".into(),
                support_level: ProviderSupportLevel::Full,
                health: ProviderHealth::Healthy,
                compatibility: ProviderCompatibility::Compatible,
                native_roots: vec!["/tmp/codex".into()],
                capabilities: vec!["read".into()],
            }],
            projects: vec![ProjectRecord {
                project_id: "/tmp/project".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                root_path: "/tmp/project".into(),
                display_name: "project".into(),
                trust_level: Some("trusted".into()),
                discovered_from: "fixture".into(),
                observed_at: now,
            }],
            sessions: vec![SessionRecord {
                session_id: "session-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                project_id: Some("/tmp/project".into()),
                title: Some("Test session".into()),
                cwd: Some("/tmp/project".into()),
                model: Some("gpt-test".into()),
                branch: Some("main".into()),
                started_at: Some(now),
                ended_at: None,
                archived: false,
                source_reference: "/tmp/session.jsonl".into(),
                source_hash: "session-hash".into(),
                metadata_json: "{}".into(),
                observed_at: now,
            }],
            session_items: vec![SessionItem {
                session_id: "session-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                sequence: 0,
                role: Some("user".into()),
                item_kind: "message".into(),
                content: None,
                source_reference: "/tmp/session.jsonl".into(),
                observed_at: now,
            }],
            memory_records: vec![MemoryRecord {
                memory_record_id: "memory-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                project_id: Some("/tmp/project".into()),
                title: "Memory".into(),
                content: "remember sandbox".into(),
                source_reference: "/tmp/memory.md".into(),
                source_hash: "memory-hash".into(),
                lifecycle: LifecycleState::Active,
                confidence: Some(0.9),
                observed_at: now,
            }],
            config_layers: vec![ConfigLayerRecord {
                config_layer_id: "config-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                project_id: Some("/tmp/project".into()),
                source_reference: "/tmp/config.toml".into(),
                scope: "user".into(),
                profile: None,
                precedence_rank: 20,
                source_hash: "config-hash".into(),
                observed_at: now,
            }],
            guidance_records: vec![GuidanceRecord {
                guidance_id: "guidance-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                project_id: Some("/tmp/project".into()),
                source_reference: "/tmp/project/AGENTS.md".into(),
                relative_scope: "AGENTS.md".into(),
                kind: "agents".into(),
                precedence_rank: 40,
                source_hash: "guidance-hash".into(),
                observed_at: now,
            }],
            guidance_edges: vec![GuidanceEdge {
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                lower_guidance_id: "guidance-test".into(),
                higher_guidance_id: "guidance-test".into(),
                relation: "more_specific".into(),
            }],
            runtime_events: vec![RuntimeEvent {
                event_id: "event-test".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                event_type: "inventory.completed".into(),
                sequence: 0,
                payload_json: "{}".into(),
                occurred_at: now,
            }],
            artifacts: vec![ArtifactRecord {
                artifact_id: new_id("artifact"),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                project_id: Some("/tmp/project".into()),
                native_id: "config".into(),
                kind: ArtifactKind::Configuration,
                title: "config.toml".into(),
                source_reference: "/tmp/config.toml".into(),
                content: "sandbox_mode = \"read-only\"".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
                evidence: Some(EvidenceSnapshot {
                    evidence_id: new_id("evidence"),
                    observation_id: observation_id.clone(),
                    excerpt: "sandbox_mode".into(),
                    source_hash,
                    observed_at: now,
                    sensitivity: SensitivityClass::Internal,
                    retention_until: None,
                }),
                observation,
            }],
            next_cursor: None,
        }
    }

    #[test]
    fn ingest_and_search_work() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let inserted = catalog.ingest(&batch()).expect("ingest");
        assert_eq!(inserted, 1);
        assert_eq!(catalog.artifact_count().expect("count"), 1);
        assert_eq!(
            catalog
                .list_runtime_events(None, None, 10)
                .expect("events")
                .len(),
            1
        );
        assert_eq!(catalog.search("sandbox", 10).expect("search").len(), 1);
        let search_runs = catalog
            .list_search_runs(None, None, 10)
            .expect("search metrics");
        assert_eq!(search_runs.len(), 1);
        assert_eq!(search_runs[0].result_count, 1);
        assert_eq!(search_runs[0].limit, 10);
        assert!(search_runs[0].host_id.is_none());
        assert!(search_runs[0].provider_id.is_none());
        assert_eq!(
            catalog
                .search_scoped("sandbox", 10, None, None, Some("/tmp/project"))
                .expect("project-scoped search")
                .len(),
            1
        );
        assert!(
            catalog
                .search_scoped("sandbox", 10, None, None, Some("/tmp/other-project"))
                .expect("empty project-scoped search")
                .is_empty()
        );
        let filtered = catalog
            .search_filtered(
                "sandbox",
                10,
                &SearchFilters {
                    host_id: Some("host_test".into()),
                    provider_id: Some("codex".into()),
                    project_id: Some("/tmp/project".into()),
                    project_trust_levels: vec!["trusted".into()],
                    artifact_kinds: vec![ArtifactKind::Configuration],
                    lifecycle_states: vec![LifecycleState::Active],
                    sensitivity_max: Some(SensitivityClass::Internal),
                    observed_after: Some(Utc::now() - chrono::Duration::hours(1)),
                    observed_before: Some(Utc::now() + chrono::Duration::hours(1)),
                },
            )
            .expect("fully filtered search");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].project_id.as_deref(), Some("/tmp/project"));
        assert_eq!(filtered[0].project_trust_level.as_deref(), Some("trusted"));
        assert_eq!(filtered[0].kind, ArtifactKind::Configuration);
        assert_eq!(filtered[0].lifecycle, LifecycleState::Active);
        assert!(
            catalog
                .search_filtered(
                    "sandbox",
                    10,
                    &SearchFilters {
                        artifact_kinds: vec![ArtifactKind::Memory],
                        ..SearchFilters::default()
                    },
                )
                .expect("artifact type filtering")
                .is_empty()
        );
        assert!(
            catalog
                .search_filtered(
                    "sandbox",
                    10,
                    &SearchFilters {
                        project_trust_levels: vec!["untrusted".into()],
                        ..SearchFilters::default()
                    },
                )
                .expect("project trust filtering")
                .is_empty()
        );
        assert_eq!(catalog.list_projects(None).expect("projects").len(), 1);
        assert_eq!(catalog.list_providers(None).expect("providers").len(), 1);
        assert_eq!(
            catalog
                .list_config_layers(None, None)
                .expect("config")
                .len(),
            1
        );
        assert_eq!(
            catalog
                .list_config_layers_scoped(Some("host_test"), Some("codex"), Some("/tmp/project"))
                .expect("scoped config")
                .len(),
            1
        );
        assert_eq!(
            catalog.list_guidance(None, None).expect("guidance").len(),
            1
        );
        assert_eq!(
            catalog
                .list_guidance_scoped(Some("host_test"), Some("codex"), Some("/tmp/project"))
                .expect("scoped guidance")
                .len(),
            1
        );
        assert_eq!(
            catalog
                .list_memory_records_scoped(Some("host_test"), Some("codex"), Some("/tmp/project"))
                .expect("scoped memory")
                .len(),
            1
        );
        assert_eq!(
            catalog.list_sessions(None, None).expect("sessions").len(),
            1
        );
        let filtered_sessions = catalog
            .list_sessions_filtered(&SessionFilters {
                host_id: Some("host_test".into()),
                provider_id: Some("codex".into()),
                project_id: Some("/tmp/project".into()),
                branch: Some("main".into()),
                model: Some("gpt-test".into()),
                archived: Some(false),
                started_after: Some(Utc::now() - chrono::Duration::hours(1)),
                started_before: Some(Utc::now() + chrono::Duration::hours(1)),
            })
            .expect("filtered sessions");
        assert_eq!(filtered_sessions.len(), 1);
        assert!(
            catalog
                .list_sessions_filtered(&SessionFilters {
                    archived: Some(true),
                    ..SessionFilters::default()
                })
                .expect("archived filter")
                .is_empty()
        );
        assert_eq!(
            catalog
                .list_session_items("session-test", None)
                .expect("session items")
                .len(),
            1
        );
        assert_eq!(
            catalog
                .list_runtime_events(None, None, 10)
                .expect("events")
                .len(),
            1
        );
        assert_eq!(
            catalog
                .list_memory_records(None, None)
                .expect("memory")
                .len(),
            1
        );
        let incremental = catalog
            .latest_index_run()
            .expect("index run")
            .expect("incremental index run");
        assert_eq!(incremental.mode, "incremental");
        assert_eq!(incremental.status, "completed");
    }

    #[test]
    fn saved_searches_preserve_shared_filters_and_replace_by_name() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let filters = SearchFilters {
            host_id: Some("host_test".into()),
            provider_id: Some("codex".into()),
            project_id: Some("/tmp/project".into()),
            project_trust_levels: vec!["trusted".into()],
            artifact_kinds: vec![ArtifactKind::Configuration],
            lifecycle_states: vec![LifecycleState::Active],
            sensitivity_max: Some(SensitivityClass::Internal),
            observed_after: Some(Utc::now() - chrono::Duration::days(1)),
            observed_before: None,
        };
        let created = catalog
            .save_search("Trusted Codex config", "sandbox", &filters)
            .expect("save search");
        let searches = catalog.list_saved_searches().expect("list searches");
        assert_eq!(searches, vec![created.clone()]);

        let updated = catalog
            .save_search(
                "trusted codex CONFIG",
                "approval",
                &SearchFilters::default(),
            )
            .expect("replace by name");
        assert_eq!(updated.saved_search_id, created.saved_search_id);
        assert_eq!(updated.created_at, created.created_at);
        assert_eq!(updated.query, "approval");
        assert_eq!(updated.filters, SearchFilters::default());
        assert_eq!(
            catalog
                .list_saved_searches()
                .expect("list after update")
                .len(),
            1
        );
        assert!(
            catalog
                .delete_saved_search(&updated.saved_search_id)
                .expect("delete saved search")
        );
        assert!(
            catalog
                .list_saved_searches()
                .expect("list after deletion")
                .is_empty()
        );
    }

    #[test]
    fn host_aliases_are_private_controller_metadata() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        catalog.ingest(&batch()).expect("ingest host");
        let created = catalog
            .set_host_alias("host_test", "Studio Mac")
            .expect("set host alias");
        assert_eq!(
            catalog.list_host_aliases().expect("list aliases"),
            vec![created]
        );
        let updated = catalog
            .set_host_alias("host_test", "Primary Mac")
            .expect("update host alias");
        assert_eq!(updated.alias, "Primary Mac");
        assert_eq!(catalog.list_host_aliases().expect("list aliases").len(), 1);
        assert!(catalog.set_host_alias("unknown", "Elsewhere").is_err());
        assert!(
            catalog
                .delete_host_alias("host_test")
                .expect("delete alias")
        );
        assert!(
            catalog
                .list_host_aliases()
                .expect("list after deletion")
                .is_empty()
        );
    }

    #[test]
    fn artifact_tags_are_private_catalog_relationships() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let batch = batch();
        let artifact_id = batch.artifacts[0].artifact_id.clone();
        catalog.ingest(&batch).expect("ingest artifact");
        let created = catalog
            .tag_artifact(&artifact_id, "needs review")
            .expect("create tag");
        assert_eq!(
            catalog.list_artifact_tags(&artifact_id).expect("list tags"),
            vec![created.clone()]
        );
        let reused = catalog
            .tag_artifact(&artifact_id, "Needs Review")
            .expect("reuse tag");
        assert_eq!(reused.tag_id, created.tag_id);
        assert_eq!(
            catalog
                .list_artifact_tags(&artifact_id)
                .expect("list tags")
                .len(),
            1
        );
        assert!(catalog.tag_artifact("missing-artifact", "other").is_err());
        assert!(
            catalog
                .untag_artifact(&artifact_id, &created.tag_id)
                .expect("remove tag")
        );
        assert!(
            catalog
                .list_artifact_tags(&artifact_id)
                .expect("list after removal")
                .is_empty()
        );
    }

    #[test]
    fn cross_host_relationships_are_symmetric_and_catalog_only() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let first = batch();
        let first_artifact_id = first.artifacts[0].artifact_id.clone();
        catalog.ingest(&first).expect("ingest first host");

        let mut second = batch();
        second.collection_run_id = "run-other-host".into();
        second.host = HostIdentity {
            host_id: "host_other".into(),
            display_name: "Other host".into(),
            platform: "macos".into(),
            hostname: "other.local".into(),
        };
        second.projects.clear();
        second.sessions.clear();
        second.session_items.clear();
        second.memory_records.clear();
        second.config_layers.clear();
        second.guidance_records.clear();
        second.guidance_edges.clear();
        second.runtime_events.clear();
        let second_artifact = &mut second.artifacts[0];
        second_artifact.artifact_id = "artifact-other-host".into();
        second_artifact.host_id = "host_other".into();
        second_artifact.native_id = "config-other-host".into();
        second_artifact.observation.host_id = "host_other".into();
        let second_artifact_id = second_artifact.artifact_id.clone();
        catalog.ingest(&second).expect("ingest second host");

        let linked = catalog
            .link_cross_host_artifacts(&first_artifact_id, &second_artifact_id, "same-policy")
            .expect("link artifacts");
        assert_eq!(linked.relationship_kind, "same-policy");
        assert_ne!(linked.left_host_id, linked.right_host_id);
        let symmetric = catalog
            .link_cross_host_artifacts(&second_artifact_id, &first_artifact_id, "same-policy")
            .expect("reuse symmetric relationship");
        assert_eq!(symmetric.relationship_id, linked.relationship_id);
        assert_eq!(
            catalog
                .list_cross_host_relationships(&first_artifact_id)
                .expect("list relationships"),
            vec![linked.clone()]
        );
        assert!(
            catalog
                .link_cross_host_artifacts(&first_artifact_id, &first_artifact_id, "related")
                .is_err()
        );
        assert!(
            catalog
                .link_cross_host_artifacts(&first_artifact_id, &second_artifact_id, "unsupported")
                .is_err()
        );
        assert!(
            catalog
                .unlink_cross_host_relationship(&linked.relationship_id)
                .expect("unlink relationship")
        );
        assert!(
            catalog
                .list_cross_host_relationships(&first_artifact_id)
                .expect("list after unlink")
                .is_empty()
        );
    }

    #[test]
    fn persistent_catalog_backup_is_consistent_and_private() {
        let directory = tempfile::tempdir().expect("catalog directory");
        let database = directory.path().join("controller.sqlite");
        let mut catalog = Catalog::open(&database).expect("catalog");
        catalog.ingest(&batch()).expect("ingest catalog");
        let receipt = catalog
            .create_backup("user-request")
            .expect("create backup");
        assert_eq!(receipt.reason, "user-request");
        assert!(
            receipt
                .backup_path
                .starts_with(directory.path().join("backups"))
        );
        assert!(receipt.size_bytes > 0);
        let backup = Catalog::open(&receipt.backup_path).expect("open backup");
        assert_eq!(backup.artifact_count().expect("backup artifact count"), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&receipt.backup_path)
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
            assert_eq!(
                fs::metadata(receipt.backup_path.parent().expect("backup parent"))
                    .expect("backup directory metadata")
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
    }

    #[test]
    fn search_projection_rebuilds_in_bounded_chunks() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        catalog.ingest(&batch()).expect("ingest");
        let run = catalog
            .rebuild_search_projection(1)
            .expect("rebuild projection");
        assert_eq!(run.mode, "rebuild");
        assert_eq!(run.status, "completed");
        assert_eq!(run.indexed_count, 1);
        assert_eq!(catalog.search("sandbox", 10).expect("search").len(), 1);
    }

    #[test]
    fn collection_runs_persist_content_free_provider_metrics() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        catalog.ingest(&batch()).expect("ingest host");
        let now = Utc::now();
        catalog
            .record_collection_run(&CollectionRunRecord {
                collection_run_id: "run-metrics".into(),
                host_id: "host_test".into(),
                provider_id: "codex".into(),
                request_id: Some("request-metrics".into()),
                correlation_id: "collection-metrics".into(),
                status: "completed".into(),
                failure_kind: None,
                started_at: now,
                completed_at: now,
                duration_ms: 42,
                discovered_count: 5,
                inserted_count: 3,
                replayed_batch_count: 1,
            })
            .expect("record collection metrics");
        let runs = catalog
            .list_collection_runs(Some("host_test"), Some("codex"), 10)
            .expect("list metrics");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].duration_ms, 42);
        assert_eq!(runs[0].discovered_count, 5);
        assert_eq!(runs[0].inserted_count, 3);
        assert_eq!(runs[0].request_id.as_deref(), Some("request-metrics"));
        assert!(runs[0].failure_kind.is_none());
    }

    #[test]
    fn audit_view_is_bounded_scoped_and_metadata_only() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        for (id, host_id, provider_id) in [
            ("audit-older", "host-a", "codex"),
            ("audit-newer", "host-b", "claude-code"),
        ] {
            catalog
                .record_audit(&AuditEvent {
                    audit_event_id: id.into(),
                    actor: "controller".into(),
                    operation: "artifact.read_sensitive".into(),
                    target: format!("/safe/{id}"),
                    host_id: Some(host_id.into()),
                    provider_id: Some(provider_id.into()),
                    before_hash: None,
                    after_hash: None,
                    result: "redacted artifact returned".into(),
                    correlation_id: format!("correlation-{id}"),
                    timestamp: Utc::now(),
                })
                .expect("record audit");
        }

        let scoped = catalog
            .list_audit_events(Some("host-a"), Some("codex"), 1000)
            .expect("scoped audit view");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].audit_event_id, "audit-older");
        assert_eq!(scoped[0].target, "/safe/audit-older");
        assert!(scoped[0].before_hash.is_none());
        assert!(scoped[0].after_hash.is_none());
        assert_eq!(
            catalog
                .list_audit_events(None, None, 0)
                .expect("bounded audit view")
                .len(),
            1
        );
    }

    #[test]
    fn repeated_ingest_is_idempotent_for_same_source_hash() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let first = batch();
        assert_eq!(catalog.ingest(&first).expect("first ingest"), 1);
        assert_eq!(catalog.ingest(&first).expect("second ingest"), 0);
        assert_eq!(catalog.artifact_count().expect("count"), 1);
        assert_eq!(
            catalog.latest_cursor("host_test", "codex").expect("cursor"),
            None
        );
        catalog
            .save_cursor("host_test", "codex", Some("run-cursor"), "run")
            .expect("save cursor");
        assert_eq!(
            catalog.latest_cursor("host_test", "codex").expect("cursor"),
            Some("run-cursor".into())
        );
    }

    #[test]
    fn source_change_marks_matching_artifact_stale_until_recollected() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let collection = batch();
        assert_eq!(catalog.ingest(&collection).expect("initial ingest"), 1);

        let event = RuntimeEvent {
            event_id: "event-source-change-1".into(),
            host_id: "host_test".into(),
            provider_id: "codex".into(),
            event_type: "source.changed".into(),
            sequence: 1,
            payload_json: serde_json::json!({
                "root": "/tmp",
                "paths": ["config.toml"],
            })
            .to_string(),
            occurred_at: Utc::now(),
        };
        assert_eq!(
            catalog
                .ingest_runtime_events(std::slice::from_ref(&event))
                .expect("source change"),
            1
        );
        assert_eq!(
            catalog.search("sandbox", 10).expect("stale search")[0].lifecycle,
            LifecycleState::Stale
        );
        assert_eq!(
            catalog
                .ingest_runtime_events(std::slice::from_ref(&event))
                .expect("deduplicated source change"),
            0
        );

        assert_eq!(catalog.ingest(&collection).expect("recollect"), 0);
        assert_eq!(
            catalog.search("sandbox", 10).expect("recollected search")[0].lifecycle,
            LifecycleState::Active
        );
    }

    #[test]
    fn forgetting_memory_removes_central_projections_and_tombstones_that_source_version() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let mut collection = batch();
        let memory = collection.memory_records[0].clone();
        let mut memory_artifact = collection.artifacts[0].clone();
        memory_artifact.artifact_id = "artifact-memory".into();
        memory_artifact.native_id = memory.source_reference.clone();
        memory_artifact.project_id = memory.project_id.clone();
        memory_artifact.kind = ArtifactKind::Memory;
        memory_artifact.title = memory.title.clone();
        memory_artifact.source_reference = memory.source_reference.clone();
        memory_artifact.content = memory.content.clone();
        memory_artifact.observation.observation_id = "observation-memory".into();
        memory_artifact.observation.native_id = memory.source_reference.clone();
        memory_artifact.observation.source_reference = memory.source_reference.clone();
        memory_artifact.observation.source_hash = memory.source_hash.clone();
        if let Some(evidence) = &mut memory_artifact.evidence {
            evidence.evidence_id = "evidence-memory".into();
            evidence.observation_id = "observation-memory".into();
            evidence.source_hash = memory.source_hash.clone();
        }
        collection.artifacts.push(memory_artifact);
        assert_eq!(catalog.ingest(&collection).expect("initial ingest"), 2);
        catalog
            .connection
            .execute_batch(
                "CREATE TABLE rag_chunks (record_id TEXT NOT NULL);
                 CREATE TABLE rag_retrieval_runs (run_id TEXT NOT NULL);",
            )
            .expect("RAG fixture tables");
        catalog
            .connection
            .execute(
                "INSERT INTO rag_chunks(record_id) VALUES (?1)",
                params!["artifact-memory"],
            )
            .expect("RAG chunk");
        catalog
            .connection
            .execute(
                "INSERT INTO rag_retrieval_runs(run_id) VALUES (?1)",
                params!["retrieval-memory"],
            )
            .expect("retrieval run");

        let receipt = catalog
            .forget_memory_record(
                &memory.memory_record_id,
                &memory.host_id,
                &memory.provider_id,
                "human requested central memory removal",
            )
            .expect("forget memory");
        assert_eq!(receipt.deleted_artifacts, 1);
        assert_eq!(receipt.deleted_rag_chunks, 1);
        assert_eq!(receipt.cleared_retrieval_runs, 1);
        assert!(
            catalog
                .search("remember", 10)
                .expect("search after deletion")
                .is_empty()
        );
        assert!(
            catalog
                .list_memory_records(None, None)
                .expect("memory after deletion")
                .is_empty()
        );
        assert_eq!(catalog.artifact_count().expect("artifact count"), 1);
        assert_eq!(
            catalog
                .connection
                .query_row("SELECT COUNT(*) FROM rag_chunks", [], |row| row
                    .get::<_, i64>(0))
                .expect("chunk count"),
            0
        );
        assert_eq!(
            catalog
                .connection
                .query_row("SELECT COUNT(*) FROM rag_retrieval_runs", [], |row| row
                    .get::<_, i64>(0))
                .expect("retrieval count"),
            0
        );

        assert_eq!(catalog.ingest(&collection).expect("replay collection"), 0);
        assert!(
            catalog
                .list_memory_records(None, None)
                .expect("tombstoned memory")
                .is_empty()
        );

        let mut changed_collection = collection.clone();
        changed_collection.memory_records[0].source_hash = "memory-hash-updated".into();
        let changed_artifact = &mut changed_collection.artifacts[1];
        changed_artifact.artifact_id = "artifact-memory-updated".into();
        changed_artifact.observation.observation_id = "observation-memory-updated".into();
        changed_artifact.observation.source_hash = "memory-hash-updated".into();
        if let Some(evidence) = &mut changed_artifact.evidence {
            evidence.evidence_id = "evidence-memory-updated".into();
            evidence.observation_id = "observation-memory-updated".into();
            evidence.source_hash = "memory-hash-updated".into();
        }
        assert_eq!(
            catalog
                .ingest(&changed_collection)
                .expect("changed source collection"),
            1
        );
        assert_eq!(
            catalog
                .list_memory_records(None, None)
                .expect("new memory version")
                .len(),
            1
        );
    }

    #[test]
    fn diagnostics_are_content_free_and_report_staleness_trust_and_conflicts() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        catalog.ingest(&batch()).expect("ingest");
        catalog
            .ingest_runtime_events(&[
                RuntimeEvent {
                    event_id: "event-diagnostics-source".into(),
                    host_id: "host_test".into(),
                    provider_id: "codex".into(),
                    event_type: "source.changed".into(),
                    sequence: 1,
                    payload_json: serde_json::json!({
                        "root": "/tmp",
                        "paths": ["config.toml"],
                    })
                    .to_string(),
                    occurred_at: Utc::now(),
                },
                RuntimeEvent {
                    event_id: "event-diagnostics-provider".into(),
                    host_id: "host_test".into(),
                    provider_id: "codex".into(),
                    event_type: "diagnostic.updated".into(),
                    sequence: 2,
                    payload_json: "{}".into(),
                    occurred_at: Utc::now(),
                },
            ])
            .expect("diagnostic events");
        catalog
            .connection
            .execute(
                "UPDATE projects SET trust_level = 'untrusted' WHERE project_id = '/tmp/project'",
                [],
            )
            .expect("mark project untrusted");
        let now = Utc::now().to_rfc3339();
        catalog
            .connection
            .execute(
                "INSERT INTO change_sets(change_set_id, host_id, provider_id, actor, scope_json, reason, evidence_ids_json, status, change_set_json, created_at, updated_at)
                 VALUES ('change-conflict', 'host_test', 'codex', 'test', '{}', 'external edit', '[]', ?1, '{}', ?2, ?2)",
                params![serde_json::to_string(&ChangeStatus::Conflict).expect("status"), &now],
            )
            .expect("conflicted change");
        for (change_set_id, status) in [
            ("change-applied", ChangeStatus::Applied),
            ("change-rolled-back", ChangeStatus::RolledBack),
        ] {
            catalog
                .connection
                .execute(
                    "INSERT INTO change_sets(change_set_id, host_id, provider_id, actor, scope_json, reason, evidence_ids_json, status, change_set_json, created_at, updated_at)
                     VALUES (?1, 'host_test', 'codex', 'test', '{}', 'fixture', '[]', ?2, '{}', ?3, ?3)",
                    params![change_set_id, serde_json::to_string(&status).expect("status"), &now],
                )
                .expect("change outcome");
        }

        let diagnostics = catalog.diagnostics().expect("diagnostics");
        assert_eq!(diagnostics.total_artifact_count, 1);
        assert_eq!(diagnostics.stale_artifact_count, 1);
        assert_eq!(diagnostics.stale_source_ratio, 1.0);
        assert_eq!(diagnostics.search_indexed_artifact_count, 1);
        assert_eq!(diagnostics.search_index_coverage_ratio, 1.0);
        assert_eq!(diagnostics.database_size_bytes, 0);
        assert_eq!(diagnostics.stale_artifacts.len(), 1);
        assert_eq!(diagnostics.stale_artifacts[0].title, "config.toml");
        assert_eq!(diagnostics.projects_requiring_attention.len(), 1);
        assert_eq!(
            diagnostics.projects_requiring_attention[0]
                .trust_level
                .as_deref(),
            Some("untrusted")
        );
        assert_eq!(diagnostics.conflicted_changes.len(), 1);
        assert_eq!(diagnostics.conflicted_change_count, 1);
        assert_eq!(diagnostics.applied_change_count, 1);
        assert_eq!(diagnostics.rolled_back_change_count, 1);
        assert_eq!(
            diagnostics.conflicted_changes[0].change_set_id,
            "change-conflict"
        );
        assert_eq!(diagnostics.recent_provider_diagnostic_event_count, 1);
    }

    #[test]
    fn runtime_session_events_are_projected_and_deduplicated() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        catalog
            .register_host(&HostIdentity {
                host_id: "host-runtime".into(),
                display_name: "Runtime host".into(),
                platform: "macos".into(),
                hostname: "runtime.local".into(),
            })
            .expect("runtime host");
        let event = RuntimeEvent {
            event_id: "event-session-1".into(),
            host_id: "host-runtime".into(),
            provider_id: "codex".into(),
            event_type: "session.updated".into(),
            sequence: 1,
            payload_json: serde_json::json!({
                "source": "codex.app-server",
                "metadata_only": true,
                "thread_id": "thread-1",
                "title": "Runtime session",
                "cwd": "/work/project",
                "model": "gpt-test",
                "archived": false
            })
            .to_string(),
            occurred_at: Utc::now(),
        };
        assert_eq!(
            catalog
                .ingest_runtime_events(std::slice::from_ref(&event))
                .expect("event"),
            1
        );
        assert_eq!(
            catalog
                .ingest_runtime_events(std::slice::from_ref(&event))
                .expect("replay"),
            0
        );
        let sessions = catalog
            .list_sessions(Some("host-runtime"), None)
            .expect("projected sessions");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "thread-1");
        assert_eq!(sessions[0].title.as_deref(), Some("Runtime session"));
        assert_eq!(sessions[0].source_reference, "codex://thread/thread-1");
        assert!(sessions[0].metadata_json.contains("metadata_only"));
    }

    #[test]
    fn host_connection_registry_preserves_endpoint_and_capabilities() {
        let mut catalog = Catalog::open_in_memory().expect("catalog");
        let host = batch().host;
        catalog
            .register_connection(
                &host,
                Some("tcp://agent.example:45432"),
                Some("0.1.0"),
                &["inventory".into(), "read".into()],
            )
            .expect("connection");
        catalog
            .register_provider_descriptors(
                &host,
                &[amcp_domain::ProviderDescriptor {
                    id: "claude-code".into(),
                    display_name: "Claude Code".into(),
                    version: None,
                    adapter_version: "inventory-fixture".into(),
                    schema_fingerprint: "claude-fixture-v1".into(),
                    support_level: ProviderSupportLevel::InventoryOnly,
                    health: ProviderHealth::Healthy,
                    compatibility: ProviderCompatibility::Compatible,
                    native_roots: vec!["/fixtures/claude-code".into()],
                    capabilities: vec!["inventory".into()],
                }],
            )
            .expect("provider descriptors");
        let hosts = catalog.list_hosts().expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].endpoint.as_deref(),
            Some("tcp://agent.example:45432")
        );
        assert_eq!(hosts[0].status, HostStatus::Connected);
        assert!(hosts[0].capabilities.contains(&"read".to_owned()));
        let providers = catalog
            .list_providers(Some("host_test"))
            .expect("providers");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider_id, "claude-code");
        assert_eq!(providers[0].schema_fingerprint, "claude-fixture-v1");
        assert_eq!(
            providers[0].support_level,
            ProviderSupportLevel::InventoryOnly
        );
        assert_eq!(providers[0].health, ProviderHealth::Healthy);
        assert_eq!(
            providers[0].compatibility,
            ProviderCompatibility::Compatible
        );
        assert_eq!(providers[0].native_roots, vec!["/fixtures/claude-code"]);
        catalog
            .set_provider_health("host_test", "claude-code", ProviderHealth::Degraded)
            .expect("record collection failure");
        assert_eq!(
            catalog
                .list_providers(Some("host_test"))
                .expect("degraded provider")[0]
                .health,
            ProviderHealth::Degraded
        );
    }

    #[test]
    fn migrates_legacy_provider_registry_with_inventory_only_defaults() {
        let directory = tempfile::tempdir().expect("catalog directory");
        let database = directory.path().join("legacy.sqlite");
        let legacy = Connection::open(&database).expect("legacy database");
        legacy
            .execute_batch(
                "CREATE TABLE providers (
                    provider_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    version TEXT,
                    adapter_version TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    PRIMARY KEY (provider_id, host_id)
                );",
            )
            .expect("legacy providers table");
        legacy
            .execute(
                "INSERT INTO providers(provider_id, host_id, display_name, version, adapter_version, capabilities_json)
                 VALUES ('legacy-provider', 'legacy-host', 'Legacy provider', NULL, 'legacy-adapter', '[]')",
                [],
            )
            .expect("legacy provider row");
        drop(legacy);

        let catalog = Catalog::open(&database).expect("migrate legacy catalog");
        let migration_backups = fs::read_dir(directory.path().join("backups"))
            .expect("migration backup directory")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("migration backups");
        assert_eq!(migration_backups.len(), 1);
        let columns = catalog
            .connection
            .prepare("PRAGMA table_info(providers)")
            .expect("provider columns")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query columns")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect columns");
        assert!(columns.contains(&"schema_fingerprint".to_owned()));
        assert!(columns.contains(&"support_level".to_owned()));
        assert!(columns.contains(&"health".to_owned()));
        assert!(columns.contains(&"compatibility".to_owned()));
        assert!(columns.contains(&"native_roots_json".to_owned()));
        let migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .expect("provider migration marker");
        assert_eq!(migration_count, 1);
        let health_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 3",
                [],
                |row| row.get(0),
            )
            .expect("provider health migration marker");
        assert_eq!(health_migration_count, 1);
        let native_roots_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 4",
                [],
                |row| row.get(0),
            )
            .expect("native roots migration marker");
        assert_eq!(native_roots_migration_count, 1);
        let saved_search_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 7",
                [],
                |row| row.get(0),
            )
            .expect("saved-search migration marker");
        assert_eq!(saved_search_migration_count, 1);
        let saved_search_table_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'saved_searches'",
                [],
                |row| row.get(0),
            )
            .expect("saved-search table");
        assert_eq!(saved_search_table_count, 1);
        let host_alias_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 8",
                [],
                |row| row.get(0),
            )
            .expect("host-alias migration marker");
        assert_eq!(host_alias_migration_count, 1);
        let host_alias_table_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'host_aliases'",
                [],
                |row| row.get(0),
            )
            .expect("host-alias table");
        assert_eq!(host_alias_table_count, 1);
        let artifact_tag_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 9",
                [],
                |row| row.get(0),
            )
            .expect("artifact-tag migration marker");
        assert_eq!(artifact_tag_migration_count, 1);
        let artifact_tag_table_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'artifact_tags'",
                [],
                |row| row.get(0),
            )
            .expect("artifact-tag table");
        assert_eq!(artifact_tag_table_count, 1);
        let cross_host_migration_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 10",
                [],
                |row| row.get(0),
            )
            .expect("cross-host migration marker");
        assert_eq!(cross_host_migration_count, 1);
        let cross_host_table_count: i64 = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'cross_host_relationships'",
                [],
                |row| row.get(0),
            )
            .expect("cross-host relationship table");
        assert_eq!(cross_host_table_count, 1);
        let providers = catalog
            .list_providers(Some("legacy-host"))
            .expect("migrated provider");
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].support_level,
            ProviderSupportLevel::InventoryOnly
        );
        assert_eq!(providers[0].health, ProviderHealth::Unknown);
        assert_eq!(providers[0].compatibility, ProviderCompatibility::Unknown);
        assert!(providers[0].native_roots.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn disk_catalog_files_are_private_and_reject_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("catalog directory");
        let database = directory.path().join("private/catalog.sqlite");
        {
            let mut catalog = Catalog::open(&database).expect("private catalog");
            catalog.ingest(&batch()).expect("write catalog");
        }
        assert_eq!(
            fs::metadata(database.parent().expect("catalog parent"))
                .expect("catalog parent metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(&database)
                .expect("catalog metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{}{}", database.display(), suffix));
            if sidecar.exists() {
                assert_eq!(
                    fs::metadata(sidecar)
                        .expect("catalog sidecar metadata")
                        .permissions()
                        .mode()
                        & 0o077,
                    0
                );
            }
        }

        fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))
            .expect("broaden catalog permissions");
        drop(Catalog::open(&database).expect("repair catalog permissions"));
        assert_eq!(
            fs::metadata(&database)
                .expect("repaired catalog metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );

        let symlink_path = directory.path().join("catalog-link.sqlite");
        symlink(&database, &symlink_path).expect("catalog symlink");
        assert!(Catalog::open(&symlink_path).is_err());
    }
}
