use amcp_domain::{
    AuditEvent, ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord, GuidanceRecord,
    HostIdentity, HostRecord, HostStatus, MemoryRecord, ProjectRecord, RuntimeEvent,
    SensitivityClass, SessionItem, SessionRecord,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub artifact_id: String,
    pub title: String,
    pub source_reference: String,
    pub preview: String,
    pub host_id: String,
    pub provider_id: String,
    pub source_hash: String,
    pub sensitivity: SensitivityClass,
    pub observed_at: DateTime<Utc>,
}

pub struct Catalog {
    connection: Connection,
}

pub const HEARTBEAT_STALE_AFTER_SECONDS: i64 = 90;

impl Catalog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path).context("open AMCP catalog")?;
        let catalog = Self { connection };
        catalog.migrate()?;
        Ok(catalog)
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().context("open in-memory catalog")?;
        let catalog = Self { connection };
        catalog.migrate()?;
        Ok(catalog)
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
            INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (1, datetime('now'));
            "#,
        )?;
        Ok(())
    }

    pub fn ingest(&mut self, batch: &CollectionBatch) -> Result<usize> {
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
                "INSERT INTO providers(provider_id, host_id, display_name, version, adapter_version, capabilities_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(provider_id, host_id) DO UPDATE SET display_name=excluded.display_name, version=excluded.version, adapter_version=excluded.adapter_version, capabilities_json=excluded.capabilities_json",
                params![provider.id, host.host_id, provider.display_name, provider.version, provider.adapter_version, serde_json::to_string(&provider.capabilities)?],
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
        transaction
            .commit()
            .context("commit collection transaction")?;
        Ok(inserted)
    }

    pub fn ingest_runtime_events(&mut self, events: &[RuntimeEvent]) -> Result<usize> {
        let transaction = self
            .connection
            .transaction()
            .context("start runtime event transaction")?;
        let mut inserted = 0;
        for event in events {
            inserted += transaction.execute(
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
        transaction
            .commit()
            .context("commit runtime event transaction")?;
        Ok(inserted)
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        self.search_scoped(query, limit, None, None, None)
    }

    pub fn search_scoped(
        &self,
        query: &str,
        limit: usize,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SearchHit>> {
        let mut statement = self.connection.prepare(
            "SELECT a.artifact_id, a.title, a.source_reference, snippet(search_content, 2, '[', ']', '…', 24), a.host_id, a.provider_id, a.sensitivity, a.observed_at, a.source_hash
             FROM search_content JOIN artifacts a ON a.artifact_id = search_content.artifact_id
             WHERE search_content MATCH ?1
               AND (?3 IS NULL OR a.host_id = ?3)
               AND (?4 IS NULL OR a.provider_id = ?4)
               AND (?5 IS NULL OR a.project_id = ?5)
             ORDER BY rank LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![query, limit as i64, host_id, provider_id, project_id],
            |row| {
                let sensitivity: String = row.get(6)?;
                let observed_at: String = row.get(7)?;
                Ok(SearchHit {
                    artifact_id: row.get(0)?,
                    title: row.get(1)?,
                    source_reference: row.get(2)?,
                    preview: row.get(3)?,
                    host_id: row.get(4)?,
                    provider_id: row.get(5)?,
                    source_hash: row.get(8)?,
                    sensitivity: serde_json::from_str(&sensitivity)
                        .unwrap_or(SensitivityClass::Sensitive),
                    observed_at: DateTime::parse_from_rfc3339(&observed_at)
                        .map(|value| value.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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
        let mut statement = self.connection.prepare(
            "SELECT session_id, host_id, provider_id, project_id, title, cwd, model, branch, started_at, ended_at, archived, source_reference, source_hash, metadata_json, observed_at
             FROM sessions WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR project_id = ?2)
             ORDER BY COALESCE(started_at, observed_at) DESC",
        )?;
        let rows = statement.query_map(params![host_id, project_id], |row| {
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
        let mut statement = self.connection.prepare(
            "SELECT memory_record_id, host_id, provider_id, project_id, title, content, source_reference, source_hash, lifecycle, confidence, observed_at
             FROM memory_records WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR project_id = ?2)
             ORDER BY observed_at DESC",
        )?;
        let rows = statement.query_map(params![host_id, project_id], |row| {
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
        let mut statement = self.connection.prepare(
            "SELECT config_layer_id, host_id, provider_id, project_id, source_reference, scope, profile, precedence_rank, source_hash, observed_at
             FROM config_layers WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR project_id = ?2)
             ORDER BY precedence_rank, source_reference",
        )?;
        let rows = statement.query_map(params![host_id, project_id], |row| {
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
        let mut statement = self.connection.prepare(
            "SELECT guidance_id, host_id, provider_id, project_id, source_reference, relative_scope, kind, precedence_rank, source_hash, observed_at
             FROM guidance_records WHERE (?1 IS NULL OR host_id = ?1) AND (?2 IS NULL OR project_id = ?2 OR project_id IS NULL)
             ORDER BY precedence_rank, source_reference",
        )?;
        let rows = statement.query_map(params![host_id, project_id], |row| {
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
        Ok(())
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
}

fn parse_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
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
                project_id: None,
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
                project_id: None,
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
        assert_eq!(catalog.list_projects(None).expect("projects").len(), 1);
        assert_eq!(
            catalog
                .list_config_layers(None, None)
                .expect("config")
                .len(),
            1
        );
        assert_eq!(
            catalog.list_guidance(None, None).expect("guidance").len(),
            1
        );
        assert_eq!(
            catalog.list_sessions(None, None).expect("sessions").len(),
            1
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
        let hosts = catalog.list_hosts().expect("hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].endpoint.as_deref(),
            Some("tcp://agent.example:45432")
        );
        assert_eq!(hosts[0].status, HostStatus::Connected);
        assert!(hosts[0].capabilities.contains(&"read".to_owned()));
    }
}
