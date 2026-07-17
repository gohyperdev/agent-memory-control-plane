use amcp_domain::{CollectionBatch, SensitivityClass};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub artifact_id: String,
    pub title: String,
    pub source_reference: String,
    pub preview: String,
    pub host_id: String,
    pub provider_id: String,
    pub sensitivity: SensitivityClass,
    pub observed_at: DateTime<Utc>,
}

pub struct Catalog {
    connection: Connection,
}

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

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let mut statement = self.connection.prepare(
            "SELECT a.artifact_id, a.title, a.source_reference, snippet(search_content, 2, '[', ']', '…', 24), a.host_id, a.provider_id, a.sensitivity, a.observed_at
             FROM search_content JOIN artifacts a ON a.artifact_id = search_content.artifact_id
             WHERE search_content MATCH ?1 ORDER BY rank LIMIT ?2",
        )?;
        let rows = statement.query_map(params![query, limit as i64], |row| {
            let sensitivity: String = row.get(6)?;
            let observed_at: String = row.get(7)?;
            Ok(SearchHit {
                artifact_id: row.get(0)?,
                title: row.get(1)?,
                source_reference: row.get(2)?,
                preview: row.get(3)?,
                host_id: row.get(4)?,
                provider_id: row.get(5)?,
                sensitivity: serde_json::from_str(&sensitivity)
                    .unwrap_or(SensitivityClass::Sensitive),
                observed_at: DateTime::parse_from_rfc3339(&observed_at)
                    .map(|value| value.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn artifact_count(&self) -> Result<i64> {
        Ok(self
            .connection
            .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))?)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcp_domain::{
        ArtifactKind, ArtifactRecord, EvidenceSnapshot, HostIdentity, LifecycleState,
        ObservationState, ProviderDescriptor, SourceObservation, new_id,
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
        assert_eq!(catalog.search("sandbox", 10).expect("search").len(), 1);
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
    }
}
