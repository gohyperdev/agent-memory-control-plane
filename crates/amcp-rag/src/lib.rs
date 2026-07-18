use amcp_domain::{LifecycleState, Scope, SensitivityClass};
use amcp_storage::{harden_private_database_path, prepare_private_database_path};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};

pub const RAG_POLICY_VERSION: &str = "amcp-rag-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RagConfig {
    pub enabled: bool,
    pub allowed_scopes: Vec<Scope>,
    pub embedding_provider: Option<String>,
    pub embedding_model: Option<String>,
    pub retention_days: Option<u32>,
    pub chunk_size: usize,
    #[serde(default = "default_retrieval_limit")]
    pub retrieval_limit: usize,
}

const fn default_retrieval_limit() -> usize {
    5
}

impl Default for RagConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_scopes: Vec::new(),
            embedding_provider: None,
            embedding_model: None,
            retention_days: None,
            chunk_size: 800,
            retrieval_limit: default_retrieval_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagDocument {
    pub record_id: String,
    pub scope: Scope,
    pub title: String,
    pub content: String,
    pub source_reference: String,
    pub source_hash: String,
    pub sensitivity: SensitivityClass,
    pub lifecycle: LifecycleState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagCitation {
    pub record_id: String,
    pub source_reference: String,
    pub source_hash: String,
    pub chunk_index: usize,
    #[serde(default)]
    pub embedding_provider: Option<String>,
    #[serde(default)]
    pub embedding_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalContext {
    pub enabled: bool,
    pub query: String,
    pub scope: Scope,
    pub context: Vec<String>,
    pub citations: Vec<RagCitation>,
    pub policy_version: String,
    pub warning: Option<String>,
}

/// One deterministic retrieval expectation used to evaluate citation quality
/// without exposing production records. Callers can keep the corpus in a
/// redacted fixture and measure the same retrieval path used by MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagEvaluationCase {
    pub id: String,
    pub query: String,
    pub scope: Scope,
    #[serde(default)]
    pub expected_record_ids: Vec<String>,
    #[serde(default)]
    pub forbidden_record_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RagEvaluationCaseResult {
    pub id: String,
    pub context_item_count: usize,
    pub citation_count: usize,
    pub expected_record_hits: usize,
    pub forbidden_record_hits: usize,
}

/// Aggregate retrieval-quality evidence. Coverage is defined over context
/// items, so a context item without a citation is always visible in the
/// report. Expected-record recall is measured only for explicitly declared
/// expectations; query-only cases do not dilute it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RagEvaluationReport {
    pub cases: Vec<RagEvaluationCaseResult>,
    pub context_item_count: usize,
    pub citation_count: usize,
    pub expected_record_count: usize,
    pub expected_record_hits: usize,
    pub forbidden_record_hits: usize,
}

impl RagEvaluationReport {
    pub fn citation_coverage(&self) -> f64 {
        ratio(self.citation_count, self.context_item_count)
    }

    pub fn expected_record_recall(&self) -> f64 {
        ratio(self.expected_record_hits, self.expected_record_count)
    }
}

pub trait RagManager {
    fn config(&self) -> &RagConfig;
    fn index(&mut self, documents: &[RagDocument]) -> Result<usize>;
    fn retrieve(&self, query: &str, scope: &Scope, limit: usize) -> Result<RetrievalContext>;
    fn invalidate_source(&mut self, source_hash: &str) -> Result<usize>;
    fn purge_expired(&mut self, _now: DateTime<Utc>) -> Result<usize> {
        Ok(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingProviderDescriptor {
    pub id: String,
    pub model: String,
    pub dimensions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RagIndexStats {
    pub chunk_count: usize,
    pub source_count: usize,
    pub retrieval_run_count: usize,
    pub average_retrieval_latency_ms: Option<u64>,
    pub retrieval_context_item_count: usize,
    pub retrieval_citation_count: usize,
    pub retrieval_citation_coverage_basis_points: u16,
    pub oldest_indexed_at: Option<DateTime<Utc>>,
    pub newest_indexed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RagClearReceipt {
    pub deleted_chunks: usize,
    pub deleted_retrieval_runs: usize,
    pub cleared_at: DateTime<Utc>,
}

/// Embedding providers are deliberately isolated from retrieval policy. A
/// provider can be local or remote, but it must return only bounded vectors;
/// the Controller decides whether the provider is allowed for a scope.
pub trait EmbeddingProvider: Send + Sync {
    fn descriptor(&self) -> EmbeddingProviderDescriptor;
    fn embed(&self, text: &str) -> Result<Vec<f32>>;
}

#[derive(Serialize)]
struct OpenAiEmbeddingRequest<'a> {
    input: &'a str,
    model: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<usize>,
    encoding_format: &'static str,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingResponse {
    data: Vec<OpenAiEmbeddingItem>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingItem {
    index: usize,
    embedding: Vec<f32>,
}

/// OpenAI-compatible remote embeddings with explicit caller-controlled
/// egress. The API key is kept in memory only and is never serialized,
/// included in errors, or written to the RAG index.
pub struct OpenAiEmbeddingProvider {
    descriptor: EmbeddingProviderDescriptor,
    endpoint: String,
    api_key: String,
    dimensions_requested: Option<usize>,
    client: reqwest::blocking::Client,
}

impl OpenAiEmbeddingProvider {
    pub fn new(
        api_key: impl Into<String>,
        model: impl Into<String>,
        dimensions: Option<usize>,
    ) -> Result<Self> {
        Self::with_endpoint(
            api_key,
            model,
            dimensions,
            "https://api.openai.com/v1/embeddings",
        )
    }

    /// Construct an OpenAI-compatible provider for a TLS endpoint. Plain HTTP
    /// is accepted only for loopback test/development endpoints.
    pub fn with_endpoint(
        api_key: impl Into<String>,
        model: impl Into<String>,
        dimensions: Option<usize>,
        endpoint: impl Into<String>,
    ) -> Result<Self> {
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            bail!("OpenAI embedding provider requires a non-empty API key")
        }
        let model = model.into();
        if model.trim().is_empty() {
            bail!("OpenAI embedding provider requires a model")
        }
        let endpoint = endpoint.into();
        let parsed_endpoint =
            reqwest::Url::parse(&endpoint).with_context(|| "parse OpenAI embedding endpoint")?;
        let is_loopback_http = parsed_endpoint.scheme() == "http"
            && parsed_endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]"));
        if parsed_endpoint.scheme() != "https" && !is_loopback_http {
            bail!("OpenAI embedding endpoint must use HTTPS (loopback HTTP is allowed for tests)")
        }
        if !parsed_endpoint.username().is_empty()
            || parsed_endpoint.password().is_some()
            || parsed_endpoint.query().is_some()
            || parsed_endpoint.fragment().is_some()
        {
            bail!("embedding endpoint must not contain credentials, query or fragment")
        }
        let dimensions_requested = dimensions.map(|value| value.clamp(1, 8_192));
        let descriptor_dimensions =
            dimensions_requested.unwrap_or_else(|| default_embedding_dimensions(&model));
        let client = reqwest::blocking::Client::builder()
            .timeout(StdDuration::from_secs(30))
            .build()
            .context("build embedding HTTP client")?;
        Ok(Self {
            descriptor: EmbeddingProviderDescriptor {
                id: "openai".into(),
                model,
                dimensions: descriptor_dimensions,
            },
            endpoint,
            api_key,
            dimensions_requested,
            client,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl EmbeddingProvider for OpenAiEmbeddingProvider {
    fn descriptor(&self) -> EmbeddingProviderDescriptor {
        self.descriptor.clone()
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        if text.trim().is_empty() {
            bail!("embedding input must not be empty")
        }
        if text.len() > 32_000 {
            bail!("embedding input exceeds the 32,000-byte AMCP bound")
        }
        let request = OpenAiEmbeddingRequest {
            input: text,
            model: &self.descriptor.model,
            dimensions: if self.descriptor.model.starts_with("text-embedding-3") {
                self.dimensions_requested
            } else {
                None
            },
            encoding_format: "float",
        };
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .context("send bounded embedding request")?;
        let status = response.status();
        let body = response.text().context("read bounded embedding response")?;
        if !status.is_success() {
            bail!("embedding provider returned HTTP {status}")
        }
        decode_embedding_response(&body, self.descriptor.dimensions)
    }
}

fn default_embedding_dimensions(model: &str) -> usize {
    if model == "text-embedding-3-large" {
        3_072
    } else {
        1_536
    }
}

fn decode_embedding_response(body: &str, expected_dimensions: usize) -> Result<Vec<f32>> {
    let response: OpenAiEmbeddingResponse =
        serde_json::from_str(body).context("decode embedding response")?;
    let item = response
        .data
        .into_iter()
        .find(|item| item.index == 0)
        .context("embedding response did not contain item index 0")?;
    if item.embedding.len() != expected_dimensions {
        bail!(
            "embedding dimension mismatch: expected {}, got {}",
            expected_dimensions,
            item.embedding.len()
        )
    }
    if item.embedding.iter().any(|value| !value.is_finite()) {
        bail!("embedding response contained a non-finite value")
    }
    Ok(item.embedding)
}

/// Small deterministic local baseline used for development and evaluation.
/// It is a feature-hashing vectorizer, not a semantic foundation model; it
/// gives AMCP a real pluggable vector path without requiring network egress.
#[derive(Debug, Clone)]
pub struct HashedEmbeddingProvider {
    descriptor: EmbeddingProviderDescriptor,
}

impl HashedEmbeddingProvider {
    pub fn new(model: impl Into<String>, dimensions: usize) -> Result<Self> {
        let dimensions = dimensions.clamp(8, 2_048);
        Ok(Self {
            descriptor: EmbeddingProviderDescriptor {
                id: "local-hash".into(),
                model: model.into(),
                dimensions,
            },
        })
    }
}

impl EmbeddingProvider for HashedEmbeddingProvider {
    fn descriptor(&self) -> EmbeddingProviderDescriptor {
        self.descriptor.clone()
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let mut vector = vec![0.0_f32; self.descriptor.dimensions];
        for term in text.split_whitespace().filter(|term| !term.is_empty()) {
            let normalized = term
                .chars()
                .filter(|character| character.is_alphanumeric())
                .collect::<String>()
                .to_lowercase();
            if normalized.is_empty() {
                continue;
            }
            let digest = Sha256::digest(normalized.as_bytes());
            let bucket =
                u16::from_le_bytes([digest[0], digest[1]]) as usize % self.descriptor.dimensions;
            let sign = if digest[2] & 1 == 0 { 1.0 } else { -1.0 };
            vector[bucket] += sign;
        }
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in &mut vector {
                *value /= norm;
            }
        }
        Ok(vector)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DisabledRagManager {
    config: RagConfig,
}

#[derive(Debug, Clone)]
struct IndexedChunk {
    record_id: String,
    title: String,
    text: String,
    scope: Scope,
    source_reference: String,
    source_hash: String,
    sensitivity: SensitivityClass,
    lifecycle: LifecycleState,
    chunk_index: usize,
    indexed_at: DateTime<Utc>,
    embedding: Option<Vec<f32>>,
    embedding_provider: Option<String>,
    embedding_model: Option<String>,
}

/// Durable derived RAG projection owned by the central Controller database.
/// Native provider files remain authoritative; this table can be rebuilt or
/// deleted independently from the catalog and lexical FTS projection.
pub struct PersistentRagIndex {
    connection: rusqlite::Connection,
    database_path: Option<PathBuf>,
}

impl PersistentRagIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        prepare_private_database_path(&path)?;
        let connection = rusqlite::Connection::open(&path)?;
        let index = Self {
            connection,
            database_path: Some(path),
        };
        index.migrate()?;
        index.harden_database_files()?;
        Ok(index)
    }

    pub fn open_in_memory() -> Result<Self> {
        let index = Self {
            connection: rusqlite::Connection::open_in_memory()?,
            database_path: None,
        };
        index.migrate()?;
        Ok(index)
    }

    fn harden_database_files(&self) -> Result<()> {
        if let Some(path) = &self.database_path {
            harden_private_database_path(path)?;
        }
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS rag_chunks (
                chunk_id TEXT PRIMARY KEY,
                record_id TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                title TEXT NOT NULL,
                text TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                lifecycle TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                indexed_at TEXT NOT NULL,
                embedding_provider TEXT,
                embedding_model TEXT,
                embedding_json TEXT
            );
            CREATE INDEX IF NOT EXISTS rag_chunks_source_hash_idx
                ON rag_chunks(source_hash);
            CREATE TABLE IF NOT EXISTS rag_retrieval_runs (
                run_id TEXT PRIMARY KEY,
                query TEXT NOT NULL DEFAULT '',
                scope_json TEXT NOT NULL,
                embedding_provider TEXT,
                embedding_model TEXT,
                result_count INTEGER NOT NULL,
                citation_count INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                correlation_id TEXT NOT NULL DEFAULT '',
                policy_version TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rag_configuration (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )?;
        let columns = self
            .connection
            .prepare("PRAGMA table_info(rag_retrieval_runs)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (column, declaration) in [
            ("citation_count", "INTEGER NOT NULL DEFAULT 0"),
            ("duration_ms", "INTEGER NOT NULL DEFAULT 0"),
            ("correlation_id", "TEXT NOT NULL DEFAULT ''"),
        ] {
            if !columns.iter().any(|existing| existing == column) {
                self.connection.execute_batch(&format!(
                    "ALTER TABLE rag_retrieval_runs ADD COLUMN {column} {declaration};"
                ))?;
            }
        }
        // Retrieval phrases are user content, not operational metadata. Clear
        // legacy values as part of the privacy migration; the derived index
        // itself remains unchanged and can still be cleared explicitly.
        self.connection.execute(
            "UPDATE rag_retrieval_runs SET query = '' WHERE query <> ''",
            [],
        )?;
        Ok(())
    }

    /// The persisted policy is derived-data metadata only. It contains no API
    /// key, query, source content, or provider-native path; credentials and
    /// remote-egress consent remain process-local requirements.
    pub fn load_config(&self) -> Result<RagConfig> {
        let config_json = self
            .connection
            .query_row(
                "SELECT config_json FROM rag_configuration WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let config = match config_json {
            Some(config_json) => {
                serde_json::from_str(&config_json).context("decode persisted RAG configuration")?
            }
            None => RagConfig::default(),
        };
        validate_rag_config(&config)?;
        Ok(config)
    }

    pub fn save_config(&self, config: &RagConfig) -> Result<()> {
        validate_rag_config(config)?;
        if config.enabled && config.allowed_scopes.is_empty() {
            bail!("an enabled persisted RAG policy requires at least one allowed scope")
        }
        self.connection.execute(
            "INSERT INTO rag_configuration(singleton, config_json, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at",
            rusqlite::params![serde_json::to_string(config)?, Utc::now().to_rfc3339()],
        )?;
        self.harden_database_files()?;
        Ok(())
    }

    /// Return only derived-index metadata. This intentionally excludes source
    /// content, provider files and the central catalog.
    pub fn stats(&self) -> Result<RagIndexStats> {
        let (chunk_count, source_count, oldest_indexed_at, newest_indexed_at) =
            self.connection.query_row(
                "SELECT COUNT(*), COUNT(DISTINCT record_id), MIN(indexed_at), MAX(indexed_at)
                 FROM rag_chunks",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )?;
        let retrieval_run_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM rag_retrieval_runs", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        let (retrieval_context_item_count, retrieval_citation_count, average_latency_ms) = self
            .connection
            .query_row(
                "SELECT COALESCE(SUM(result_count), 0), COALESCE(SUM(citation_count), 0), AVG(duration_ms)
                 FROM rag_retrieval_runs",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<f64>>(2)?,
                    ))
                },
            )?;
        let retrieval_context_item_count = usize::try_from(retrieval_context_item_count)?;
        let retrieval_citation_count = usize::try_from(retrieval_citation_count)?;
        Ok(RagIndexStats {
            chunk_count: usize::try_from(chunk_count)?,
            source_count: usize::try_from(source_count)?,
            retrieval_run_count: usize::try_from(retrieval_run_count)?,
            average_retrieval_latency_ms: average_latency_ms
                .map(|value| value.max(0.0).round() as u64),
            retrieval_context_item_count,
            retrieval_citation_count,
            retrieval_citation_coverage_basis_points: citation_coverage_basis_points(
                retrieval_citation_count,
                retrieval_context_item_count,
            ),
            oldest_indexed_at: oldest_indexed_at
                .map(|value| DateTime::parse_from_rfc3339(&value))
                .transpose()?
                .map(|value| value.with_timezone(&Utc)),
            newest_indexed_at: newest_indexed_at
                .map(|value| DateTime::parse_from_rfc3339(&value))
                .transpose()?
                .map(|value| value.with_timezone(&Utc)),
        })
    }

    /// Delete the complete AMCP-derived RAG projection and retrieval audit
    /// runs. Native provider state, catalog records and lexical FTS content
    /// are deliberately left untouched and can rebuild this projection.
    pub fn clear_derived_data(&mut self) -> Result<RagClearReceipt> {
        let transaction = self.connection.transaction()?;
        let deleted_chunks = transaction.execute("DELETE FROM rag_chunks", [])?;
        let deleted_retrieval_runs = transaction.execute("DELETE FROM rag_retrieval_runs", [])?;
        transaction.commit()?;
        self.harden_database_files()?;
        Ok(RagClearReceipt {
            deleted_chunks,
            deleted_retrieval_runs,
            cleared_at: Utc::now(),
        })
    }

    fn load_chunks(&self) -> Result<Vec<IndexedChunk>> {
        let mut statement = self.connection.prepare(
            "SELECT record_id, scope_json, title, text, source_reference, source_hash,
                    sensitivity, lifecycle, chunk_index, indexed_at, embedding_provider,
                    embedding_model, embedding_json
             FROM rag_chunks ORDER BY record_id, chunk_index",
        )?;
        let rows = statement.query_map([], |row| {
            let scope_json: String = row.get(1)?;
            let sensitivity_json: String = row.get(6)?;
            let lifecycle_json: String = row.get(7)?;
            let indexed_at: String = row.get(9)?;
            let embedding_json: Option<String> = row.get(12)?;
            Ok((
                row.get::<_, String>(0)?,
                scope_json,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                sensitivity_json,
                lifecycle_json,
                row.get::<_, i64>(8)?,
                indexed_at,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                embedding_json,
            ))
        })?;
        let mut chunks = Vec::new();
        for row in rows {
            let (
                record_id,
                scope_json,
                title,
                text,
                source_reference,
                source_hash,
                sensitivity_json,
                lifecycle_json,
                chunk_index,
                indexed_at,
                embedding_provider,
                embedding_model,
                embedding_json,
            ) = row?;
            chunks.push(IndexedChunk {
                record_id,
                title,
                text,
                scope: serde_json::from_str(&scope_json)?,
                source_reference,
                source_hash,
                sensitivity: serde_json::from_str(&sensitivity_json)?,
                lifecycle: serde_json::from_str(&lifecycle_json)?,
                chunk_index: usize::try_from(chunk_index)?,
                indexed_at: DateTime::parse_from_rfc3339(&indexed_at)?.with_timezone(&Utc),
                embedding: embedding_json
                    .map(|value| serde_json::from_str(&value))
                    .transpose()?,
                embedding_provider,
                embedding_model,
            });
        }
        Ok(chunks)
    }

    fn replace_chunks(&mut self, chunks: &[IndexedChunk]) -> Result<usize> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM rag_chunks", [])?;
        for chunk in chunks {
            let chunk_id = format!("{}#{}", chunk.record_id, chunk.chunk_index);
            transaction.execute(
                "INSERT INTO rag_chunks(
                    chunk_id, record_id, scope_json, title, text, source_reference,
                    source_hash, sensitivity, lifecycle, chunk_index, indexed_at,
                    embedding_provider, embedding_model, embedding_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    chunk_id,
                    chunk.record_id,
                    serde_json::to_string(&chunk.scope)?,
                    chunk.title,
                    chunk.text,
                    chunk.source_reference,
                    chunk.source_hash,
                    serde_json::to_string(&chunk.sensitivity)?,
                    serde_json::to_string(&chunk.lifecycle)?,
                    chunk.chunk_index as i64,
                    chunk.indexed_at.to_rfc3339(),
                    chunk.embedding_provider,
                    chunk.embedding_model,
                    chunk
                        .embedding
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                ],
            )?;
        }
        transaction.commit()?;
        self.harden_database_files()?;
        Ok(chunks.len())
    }

    /// Remove derived chunks whose catalog source disappeared or changed.
    /// The caller supplies the current central artifact projection; this
    /// keeps native provider state authoritative and prevents stale RAG hits.
    pub fn invalidate_stale_sources(
        &mut self,
        current_sources: &HashMap<String, String>,
    ) -> Result<usize> {
        let stale_records = self
            .load_chunks()?
            .into_iter()
            .filter(|chunk| {
                current_sources
                    .get(&chunk.record_id)
                    .is_none_or(|source_hash| source_hash != &chunk.source_hash)
            })
            .map(|chunk| chunk.record_id)
            .collect::<HashSet<_>>();
        if stale_records.is_empty() {
            return Ok(0);
        }
        let transaction = self.connection.transaction()?;
        let mut removed = 0;
        for record_id in stale_records {
            removed += transaction.execute(
                "DELETE FROM rag_chunks WHERE record_id = ?1",
                rusqlite::params![record_id],
            )?;
        }
        transaction.commit()?;
        self.harden_database_files()?;
        Ok(removed)
    }

    fn record_retrieval(
        &mut self,
        scope: &Scope,
        embedding_provider: Option<&str>,
        embedding_model: Option<&str>,
        context_item_count: usize,
        citation_count: usize,
        duration_ms: u64,
    ) -> Result<()> {
        let run_id = format!(
            "rag-retrieval-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        self.connection.execute(
            "INSERT INTO rag_retrieval_runs(
                run_id, query, scope_json, embedding_provider, embedding_model,
                result_count, citation_count, duration_ms, correlation_id, policy_version, created_at
            ) VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, ?7, ?1, ?8, ?9)",
            rusqlite::params![
                run_id,
                serde_json::to_string(scope)?,
                embedding_provider,
                embedding_model,
                context_item_count as i64,
                citation_count as i64,
                duration_ms.min(i64::MAX as u64) as i64,
                RAG_POLICY_VERSION,
                Utc::now().to_rfc3339(),
            ],
        )?;
        self.connection.execute(
            "DELETE FROM rag_retrieval_runs WHERE run_id IN (
                 SELECT run_id FROM rag_retrieval_runs
                 ORDER BY created_at DESC, run_id DESC
                 LIMIT -1 OFFSET 1000
             )",
            [],
        )?;
        self.harden_database_files()?;
        Ok(())
    }
}

/// A bounded, in-memory lexical retriever used when the user explicitly enables
/// RAG without configuring an embedding provider. It keeps the same citation and
/// invalidation contract as a future vector implementation.
pub struct LexicalRagManager {
    config: RagConfig,
    chunks: Vec<IndexedChunk>,
    embedding_provider: Option<Box<dyn EmbeddingProvider>>,
}

impl LexicalRagManager {
    pub fn new(config: RagConfig) -> Self {
        Self {
            config,
            chunks: Vec::new(),
            embedding_provider: None,
        }
    }

    pub fn with_embedding_provider(
        mut config: RagConfig,
        provider: Box<dyn EmbeddingProvider>,
    ) -> Self {
        let descriptor = provider.descriptor();
        config.embedding_provider = Some(descriptor.id);
        config.embedding_model = Some(descriptor.model);
        Self {
            config,
            chunks: Vec::new(),
            embedding_provider: Some(provider),
        }
    }

    pub fn load_from_index(
        config: RagConfig,
        provider: Option<Box<dyn EmbeddingProvider>>,
        index: &PersistentRagIndex,
    ) -> Result<Self> {
        let descriptor = provider.as_ref().map(|provider| provider.descriptor());
        let mut manager = match provider {
            Some(provider) => Self::with_embedding_provider(config, provider),
            None => Self::new(config),
        };
        for mut chunk in index.load_chunks()? {
            if !manager.scope_allowed(&chunk.scope) {
                continue;
            }
            let embedding_is_current = descriptor.as_ref().is_some_and(|descriptor| {
                chunk.embedding_provider.as_deref() == Some(descriptor.id.as_str())
                    && chunk.embedding_model.as_deref() == Some(descriptor.model.as_str())
            });
            if !embedding_is_current {
                chunk.embedding = None;
                chunk.embedding_provider = None;
                chunk.embedding_model = None;
            }
            manager.chunks.push(chunk);
        }
        Ok(manager)
    }

    pub fn persist_to_index(&self, index: &mut PersistentRagIndex) -> Result<usize> {
        index.replace_chunks(&self.chunks)
    }

    pub fn record_retrieval(
        &self,
        index: &mut PersistentRagIndex,
        scope: &Scope,
        context_item_count: usize,
        citation_count: usize,
        duration_ms: u64,
    ) -> Result<()> {
        let descriptor = self
            .embedding_provider
            .as_ref()
            .map(|provider| provider.descriptor());
        index.record_retrieval(
            scope,
            descriptor.as_ref().map(|descriptor| descriptor.id.as_str()),
            descriptor
                .as_ref()
                .map(|descriptor| descriptor.model.as_str()),
            context_item_count,
            citation_count,
            duration_ms,
        )
    }

    /// Execute a redacted evaluation set through the production retrieval
    /// path. This is intentionally read-only: it does not persist retrieval
    /// history or alter the derived RAG projection.
    pub fn evaluate(
        &self,
        cases: &[RagEvaluationCase],
        limit: usize,
    ) -> Result<RagEvaluationReport> {
        let mut report = RagEvaluationReport {
            cases: Vec::with_capacity(cases.len()),
            context_item_count: 0,
            citation_count: 0,
            expected_record_count: 0,
            expected_record_hits: 0,
            forbidden_record_hits: 0,
        };
        for case in cases {
            let context = self.retrieve(&case.query, &case.scope, limit)?;
            let cited_record_ids = context
                .citations
                .iter()
                .map(|citation| citation.record_id.as_str())
                .collect::<HashSet<_>>();
            let expected_record_hits = case
                .expected_record_ids
                .iter()
                .filter(|record_id| cited_record_ids.contains(record_id.as_str()))
                .count();
            let forbidden_record_hits = case
                .forbidden_record_ids
                .iter()
                .filter(|record_id| cited_record_ids.contains(record_id.as_str()))
                .count();
            report.context_item_count += context.context.len();
            report.citation_count += context.citations.len();
            report.expected_record_count += case.expected_record_ids.len();
            report.expected_record_hits += expected_record_hits;
            report.forbidden_record_hits += forbidden_record_hits;
            report.cases.push(RagEvaluationCaseResult {
                id: case.id.clone(),
                context_item_count: context.context.len(),
                citation_count: context.citations.len(),
                expected_record_hits,
                forbidden_record_hits,
            });
        }
        Ok(report)
    }

    fn scope_allowed(&self, scope: &Scope) -> bool {
        self.config.allowed_scopes.is_empty()
            || self
                .config
                .allowed_scopes
                .iter()
                .any(|allowed| scope_matches(allowed, scope))
    }
}

impl RagManager for LexicalRagManager {
    fn config(&self) -> &RagConfig {
        &self.config
    }

    fn index(&mut self, documents: &[RagDocument]) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }
        let chunk_size = self.config.chunk_size.max(1);
        let indexed_at = Utc::now();
        let mut indexed = 0;
        for document in documents {
            if !self.scope_allowed(&document.scope)
                || document.lifecycle != LifecycleState::Active
                || document.sensitivity == SensitivityClass::SecretLike
            {
                continue;
            }
            self.chunks
                .retain(|chunk| chunk.record_id != document.record_id);
            for (chunk_index, text) in document.content.as_bytes().chunks(chunk_size).enumerate() {
                let text = String::from_utf8_lossy(text).into_owned();
                let embedding = self
                    .embedding_provider
                    .as_ref()
                    .map(|provider| provider.embed(&text))
                    .transpose()?;
                let embedding_provider = self
                    .embedding_provider
                    .as_ref()
                    .map(|provider| provider.descriptor().id);
                let embedding_model = self
                    .embedding_provider
                    .as_ref()
                    .map(|provider| provider.descriptor().model);
                self.chunks.push(IndexedChunk {
                    record_id: document.record_id.clone(),
                    title: document.title.clone(),
                    text,
                    scope: document.scope.clone(),
                    source_reference: document.source_reference.clone(),
                    source_hash: document.source_hash.clone(),
                    sensitivity: document.sensitivity.clone(),
                    lifecycle: document.lifecycle.clone(),
                    chunk_index,
                    indexed_at,
                    embedding,
                    embedding_provider,
                    embedding_model,
                });
                indexed += 1;
            }
        }
        Ok(indexed)
    }

    fn retrieve(&self, query: &str, scope: &Scope, limit: usize) -> Result<RetrievalContext> {
        let query_embedding = self
            .embedding_provider
            .as_ref()
            .map(|provider| provider.embed(query))
            .transpose()?;
        let mut ranked = self
            .chunks
            .iter()
            .filter(|chunk| {
                chunk.lifecycle == LifecycleState::Active
                    && chunk.sensitivity != SensitivityClass::SecretLike
                    && scope_matches(scope, &chunk.scope)
            })
            .map(|chunk| {
                let lower = chunk.text.to_lowercase();
                let lexical_score = query
                    .split_whitespace()
                    .filter(|term| lower.contains(&term.to_lowercase()))
                    .count();
                let semantic_score = query_embedding
                    .as_ref()
                    .zip(chunk.embedding.as_ref())
                    .map(|(query, document)| cosine_similarity(query, document))
                    .unwrap_or(0.0);
                (lexical_score, semantic_score, chunk)
            })
            .filter(|(lexical_score, semantic_score, _)| {
                *lexical_score > 0 || *semantic_score > 0.05
            })
            .collect::<Vec<_>>();
        ranked.sort_by(
            |(left_lexical, left_semantic, left), (right_lexical, right_semantic, right)| {
                right_semantic
                    .partial_cmp(left_semantic)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| right_lexical.cmp(left_lexical))
                    .then_with(|| left.source_reference.cmp(&right.source_reference))
                    .then_with(|| left.chunk_index.cmp(&right.chunk_index))
            },
        );
        let selected = ranked.into_iter().take(limit).collect::<Vec<_>>();
        Ok(RetrievalContext {
            enabled: self.config.enabled,
            query: query.to_owned(),
            scope: scope.clone(),
            context: selected
                .iter()
                .map(|(_, _, chunk)| format!("{}: {}", chunk.title, chunk.text))
                .collect(),
            citations: selected
                .iter()
                .map(|(_, _, chunk)| RagCitation {
                    record_id: chunk.record_id.clone(),
                    source_reference: chunk.source_reference.clone(),
                    source_hash: chunk.source_hash.clone(),
                    chunk_index: chunk.chunk_index,
                    embedding_provider: chunk.embedding_provider.clone(),
                    embedding_model: chunk.embedding_model.clone(),
                })
                .collect(),
            policy_version: RAG_POLICY_VERSION.to_owned(),
            warning: if self.config.enabled
                && self.config.embedding_provider.is_some()
                && self.embedding_provider.is_none()
            {
                Some("Configured embedding provider is unavailable; using lexical ranking.".into())
            } else if self.config.enabled {
                None
            } else {
                Some("RAG is disabled; use AMCP lexical search instead.".to_owned())
            },
        })
    }

    fn invalidate_source(&mut self, source_hash: &str) -> Result<usize> {
        let before = self.chunks.len();
        self.chunks.retain(|chunk| chunk.source_hash != source_hash);
        Ok(before - self.chunks.len())
    }

    fn purge_expired(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let Some(days) = self.config.retention_days else {
            return Ok(0);
        };
        let cutoff = now - Duration::days(days as i64);
        let before = self.chunks.len();
        self.chunks.retain(|chunk| chunk.indexed_at >= cutoff);
        Ok(before - self.chunks.len())
    }
}

fn cosine_similarity(left: &[f32], right: &[f32]) -> f32 {
    if left.len() != right.len() {
        return 0.0;
    }
    left.iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum()
}

pub fn validate_rag_config(config: &RagConfig) -> Result<()> {
    if !(64..=16_384).contains(&config.chunk_size) {
        bail!("RAG chunk_size must be between 64 and 16384 bytes")
    }
    if !(1..=20).contains(&config.retrieval_limit) {
        bail!("RAG retrieval_limit must be between 1 and 20")
    }
    if config.allowed_scopes.len() > 128 {
        bail!("RAG supports at most 128 explicitly allowed scopes")
    }
    if let Some(provider) = config.embedding_provider.as_deref()
        && !matches!(provider, "local-hash" | "openai")
    {
        bail!("unsupported RAG embedding provider")
    }
    if let Some(model) = config.embedding_model.as_deref()
        && (model.trim().is_empty() || model.len() > 160)
    {
        bail!("RAG embedding model must be between 1 and 160 characters")
    }
    Ok(())
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn citation_coverage_basis_points(citation_count: usize, context_item_count: usize) -> u16 {
    if context_item_count == 0 {
        return 10_000;
    }
    ((citation_count.saturating_mul(10_000) / context_item_count).min(10_000)) as u16
}

fn scope_matches(requested: &Scope, actual: &Scope) -> bool {
    requested
        .host_id
        .as_deref()
        .is_none_or(|id| actual.host_id.as_deref() == Some(id))
        && requested
            .provider_id
            .as_deref()
            .is_none_or(|id| actual.provider_id.as_deref() == Some(id))
        && requested
            .project_id
            .as_deref()
            .is_none_or(|id| actual.project_id.as_deref() == Some(id))
}

impl DisabledRagManager {
    pub fn new(config: RagConfig) -> Self {
        Self { config }
    }
}

impl RagManager for DisabledRagManager {
    fn config(&self) -> &RagConfig {
        &self.config
    }

    fn index(&mut self, _documents: &[RagDocument]) -> Result<usize> {
        Ok(0)
    }

    fn retrieve(&self, query: &str, scope: &Scope, _limit: usize) -> Result<RetrievalContext> {
        Ok(RetrievalContext {
            enabled: false,
            query: query.to_owned(),
            scope: scope.clone(),
            context: Vec::new(),
            citations: Vec::new(),
            policy_version: RAG_POLICY_VERSION.to_owned(),
            warning: Some("RAG is disabled; use AMCP lexical search instead.".to_owned()),
        })
    }

    fn invalidate_source(&mut self, _source_hash: &str) -> Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[derive(Deserialize)]
    struct RagEvaluationFixture {
        documents: Vec<RagDocument>,
        cases: Vec<RagEvaluationCase>,
    }

    #[test]
    fn rag_is_disabled_by_default_and_returns_explicit_warning() {
        let manager = DisabledRagManager::default();
        let context = manager
            .retrieve("sandbox", &Scope::host("host-test"), 5)
            .expect("disabled retrieval");
        assert!(!context.enabled);
        assert!(context.warning.unwrap().contains("disabled"));
        assert_eq!(manager.config().chunk_size, 800);
    }

    #[test]
    fn persisted_rag_configuration_is_private_validated_and_defaults_to_disabled() {
        let index = PersistentRagIndex::open_in_memory().expect("in-memory RAG index");
        assert_eq!(
            index.load_config().expect("default configuration"),
            RagConfig::default()
        );

        let configured = RagConfig {
            enabled: true,
            allowed_scopes: vec![Scope {
                host_id: Some("host-a".into()),
                provider_id: Some("codex".into()),
                project_id: Some("project-a".into()),
            }],
            embedding_provider: Some("local-hash".into()),
            embedding_model: Some("hash-v1".into()),
            retention_days: Some(14),
            chunk_size: 1_024,
            retrieval_limit: 7,
        };
        index.save_config(&configured).expect("save configuration");
        assert_eq!(index.load_config().expect("load configuration"), configured);

        let invalid = RagConfig {
            chunk_size: 1,
            ..RagConfig::default()
        };
        assert!(index.save_config(&invalid).is_err());
        assert!(
            index
                .save_config(&RagConfig {
                    enabled: true,
                    ..RagConfig::default()
                })
                .is_err()
        );
    }

    #[test]
    fn narrowed_persisted_scope_excludes_previously_indexed_chunks() {
        let mut index = PersistentRagIndex::open_in_memory().expect("in-memory RAG index");
        let mut unrestricted = LexicalRagManager::new(RagConfig {
            enabled: true,
            ..RagConfig::default()
        });
        unrestricted
            .index(&[RagDocument {
                record_id: "artifact-host-b".into(),
                scope: Scope::host("host-b"),
                title: "Scoped memory".into(),
                content: "only host b may contain this marker".into(),
                source_reference: "amcp://host-b/memory".into(),
                source_hash: "host-b-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index unrestricted document");
        unrestricted
            .persist_to_index(&mut index)
            .expect("persist unrestricted chunks");

        let narrowed = RagConfig {
            enabled: true,
            allowed_scopes: vec![Scope::host("host-a")],
            ..RagConfig::default()
        };
        let manager = LexicalRagManager::load_from_index(narrowed, None, &index)
            .expect("load narrowed policy");
        let context = manager
            .retrieve("marker", &Scope::host("host-b"), 5)
            .expect("retrieve narrowed policy");
        assert!(context.context.is_empty());
        assert!(context.citations.is_empty());
    }

    #[test]
    fn lexical_rag_is_opt_in_cited_and_invalidatable() {
        let mut manager = LexicalRagManager::new(RagConfig {
            enabled: true,
            chunk_size: 20,
            ..RagConfig::default()
        });
        let document = RagDocument {
            record_id: "artifact-1".into(),
            scope: Scope::host("host-test"),
            title: "AGENTS.md".into(),
            content: "Use the sandbox workflow.".into(),
            source_reference: "/project/AGENTS.md".into(),
            source_hash: "hash-1".into(),
            sensitivity: SensitivityClass::Internal,
            lifecycle: LifecycleState::Active,
        };
        assert!(manager.index(&[document]).expect("index") > 0);
        let context = manager
            .retrieve("sandbox", &Scope::host("host-test"), 5)
            .expect("retrieve");
        assert!(context.enabled);
        assert_eq!(context.citations.len(), 1);
        assert_eq!(manager.invalidate_source("hash-1").expect("invalidate"), 2);
        assert!(
            manager
                .retrieve("sandbox", &Scope::host("host-test"), 5)
                .expect("retrieve after invalidation")
                .context
                .is_empty()
        );
    }

    #[test]
    fn redacted_evaluation_fixture_measures_citations_and_scope_isolation() {
        let fixture: RagEvaluationFixture = serde_json::from_str(include_str!(
            "../../../fixtures/rag/retrieval-evaluation.json"
        ))
        .expect("parse redacted RAG evaluation fixture");
        let mut manager = LexicalRagManager::new(RagConfig {
            enabled: true,
            ..RagConfig::default()
        });
        assert_eq!(
            manager.index(&fixture.documents).expect("index fixture"),
            2,
            "stale documents are excluded from the derived RAG index"
        );

        let report = manager
            .evaluate(&fixture.cases, 3)
            .expect("evaluate retrieval fixture");
        assert_eq!(report.cases.len(), 2);
        assert_eq!(report.expected_record_count, 1);
        assert_eq!(report.expected_record_hits, 1);
        assert_eq!(report.forbidden_record_hits, 0);
        assert_eq!(report.citation_coverage(), 1.0);
        assert_eq!(report.expected_record_recall(), 1.0);
        assert_eq!(report.cases[1].context_item_count, 0);
        assert_eq!(report.cases[1].citation_count, 0);
    }

    #[test]
    fn lexical_rag_purges_chunks_after_configured_retention() {
        let mut manager = LexicalRagManager::new(RagConfig {
            enabled: true,
            retention_days: Some(0),
            ..RagConfig::default()
        });
        manager
            .index(&[RagDocument {
                record_id: "artifact-ttl".into(),
                scope: Scope::host("host-test"),
                title: "memory".into(),
                content: "short-lived context".into(),
                source_reference: "/memory.md".into(),
                source_hash: "ttl-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index retained document");
        assert_eq!(manager.purge_expired(Utc::now()).expect("purge"), 1);
    }

    #[test]
    fn local_embedding_provider_is_opt_in_and_cited() {
        let provider = HashedEmbeddingProvider::new("hash-v1", 32).expect("provider");
        let descriptor = provider.descriptor();
        assert_eq!(descriptor.id, "local-hash");
        assert_eq!(
            provider.embed("sandbox workflow").expect("embedding").len(),
            32
        );
        let mut manager = LexicalRagManager::with_embedding_provider(
            RagConfig {
                enabled: true,
                ..RagConfig::default()
            },
            Box::new(provider),
        );
        manager
            .index(&[RagDocument {
                record_id: "artifact-vector".into(),
                scope: Scope::host("host-test"),
                title: "memory".into(),
                content: "sandbox workflow guidance".into(),
                source_reference: "/memory.md".into(),
                source_hash: "vector-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index embedded document");
        let context = manager
            .retrieve("sandbox workflow", &Scope::host("host-test"), 1)
            .expect("retrieve embedded context");
        assert_eq!(context.citations.len(), 1);
        assert_eq!(
            context.citations[0].embedding_provider.as_deref(),
            Some("local-hash")
        );
        assert_eq!(
            context.citations[0].embedding_model.as_deref(),
            Some("hash-v1")
        );
    }

    #[test]
    fn persistent_index_round_trips_and_invalidates_changed_embedding_model() {
        let mut index = PersistentRagIndex::open_in_memory().expect("persistent index");
        let mut manager = LexicalRagManager::with_embedding_provider(
            RagConfig {
                enabled: true,
                ..RagConfig::default()
            },
            Box::new(HashedEmbeddingProvider::new("hash-v1", 32).expect("provider")),
        );
        manager
            .index(&[RagDocument {
                record_id: "artifact-persisted".into(),
                scope: Scope::host("host-test"),
                title: "persistent memory".into(),
                content: "durable context".into(),
                source_reference: "/memory.md".into(),
                source_hash: "persisted-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index document");
        assert_eq!(manager.persist_to_index(&mut index).expect("persist"), 1);
        manager
            .record_retrieval(&mut index, &Scope::host("host-test"), 1, 1, 7)
            .expect("record retrieval");
        let stored_query: String = index
            .connection
            .query_row("SELECT query FROM rag_retrieval_runs", [], |row| row.get(0))
            .expect("stored retrieval query");
        assert!(stored_query.is_empty());
        let stats = index.stats().expect("retrieval stats");
        assert_eq!(stats.average_retrieval_latency_ms, Some(7));
        assert_eq!(stats.retrieval_citation_coverage_basis_points, 10_000);

        let restored = LexicalRagManager::load_from_index(
            RagConfig {
                enabled: true,
                ..RagConfig::default()
            },
            Some(Box::new(
                HashedEmbeddingProvider::new("hash-v1", 32).expect("provider"),
            )),
            &index,
        )
        .expect("restore index");
        let context = restored
            .retrieve("durable", &Scope::host("host-test"), 1)
            .expect("retrieve restored");
        assert_eq!(
            context.citations[0].embedding_model.as_deref(),
            Some("hash-v1")
        );

        let changed = LexicalRagManager::load_from_index(
            RagConfig {
                enabled: true,
                ..RagConfig::default()
            },
            Some(Box::new(
                HashedEmbeddingProvider::new("hash-v2", 32).expect("provider"),
            )),
            &index,
        )
        .expect("restore changed model");
        let context = changed
            .retrieve("durable", &Scope::host("host-test"), 1)
            .expect("retrieve changed model");
        assert_eq!(context.citations[0].embedding_model, None);
    }

    #[test]
    fn retrieval_privacy_migration_clears_legacy_queries_and_adds_metrics() {
        let directory = tempfile::tempdir().expect("RAG migration directory");
        let database = directory.path().join("rag.sqlite");
        let connection = rusqlite::Connection::open(&database).expect("legacy RAG database");
        connection
            .execute_batch(
                "CREATE TABLE rag_retrieval_runs (
                    run_id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    embedding_provider TEXT,
                    embedding_model TEXT,
                    result_count INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO rag_retrieval_runs(run_id, query, scope_json, result_count, policy_version, created_at)
                VALUES ('legacy-run', 'sensitive user phrase', '{}', 1, 'legacy', '2026-07-18T00:00:00Z');",
            )
            .expect("legacy retrieval fixture");
        drop(connection);

        let index = PersistentRagIndex::open(&database).expect("migrate RAG index");
        let query: String = index
            .connection
            .query_row(
                "SELECT query FROM rag_retrieval_runs WHERE run_id = 'legacy-run'",
                [],
                |row| row.get(0),
            )
            .expect("migrated query");
        assert!(query.is_empty());
        let stats = index.stats().expect("migrated metrics");
        assert_eq!(stats.average_retrieval_latency_ms, Some(0));
        assert_eq!(stats.retrieval_citation_coverage_basis_points, 0);
    }

    #[test]
    fn persistent_index_removes_missing_or_changed_catalog_sources() {
        let mut index = PersistentRagIndex::open_in_memory().expect("persistent index");
        let mut manager = LexicalRagManager::new(RagConfig {
            enabled: true,
            ..RagConfig::default()
        });
        manager
            .index(&[RagDocument {
                record_id: "artifact-stale".into(),
                scope: Scope::host("host-test"),
                title: "stale".into(),
                content: "old context".into(),
                source_reference: "/old.md".into(),
                source_hash: "old-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index stale document");
        manager
            .persist_to_index(&mut index)
            .expect("persist stale document");
        let mut current = HashMap::new();
        current.insert("artifact-stale".into(), "new-hash".into());
        assert_eq!(
            index
                .invalidate_stale_sources(&current)
                .expect("invalidate"),
            1
        );
        let restored = LexicalRagManager::load_from_index(RagConfig::default(), None, &index)
            .expect("load after invalidation");
        assert!(
            restored
                .retrieve("old", &Scope::host("host-test"), 1)
                .expect("retrieve after invalidation")
                .context
                .is_empty()
        );
    }

    #[test]
    fn persistent_index_reports_and_clears_only_derived_data() {
        let mut index = PersistentRagIndex::open_in_memory().expect("persistent index");
        let mut manager = LexicalRagManager::new(RagConfig {
            enabled: true,
            ..RagConfig::default()
        });
        manager
            .index(&[RagDocument {
                record_id: "artifact-clear".into(),
                scope: Scope::host("host-test"),
                title: "derived memory".into(),
                content: "clearable context".into(),
                source_reference: "/memory.md".into(),
                source_hash: "clear-hash".into(),
                sensitivity: SensitivityClass::Internal,
                lifecycle: LifecycleState::Active,
            }])
            .expect("index document");
        manager
            .persist_to_index(&mut index)
            .expect("persist chunks");
        manager
            .record_retrieval(&mut index, &Scope::host("host-test"), 1, 1, 7)
            .expect("record retrieval");

        let stats = index.stats().expect("stats");
        assert_eq!(stats.chunk_count, 1);
        assert_eq!(stats.source_count, 1);
        assert_eq!(stats.retrieval_run_count, 1);
        let receipt = index.clear_derived_data().expect("clear derived data");
        assert_eq!(receipt.deleted_chunks, 1);
        assert_eq!(receipt.deleted_retrieval_runs, 1);
        assert_eq!(index.stats().expect("empty stats").chunk_count, 0);
        assert_eq!(index.stats().expect("empty stats").retrieval_run_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn persistent_disk_index_uses_the_private_catalog_database_policy() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory = tempfile::tempdir().expect("RAG directory");
        let database = directory.path().join("private/controller.sqlite");
        drop(PersistentRagIndex::open(&database).expect("private RAG index"));
        assert_eq!(
            fs::metadata(database.parent().expect("database parent"))
                .expect("database parent metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(&database)
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644))
            .expect("broaden database permissions");
        drop(PersistentRagIndex::open(&database).expect("repair RAG database permissions"));
        assert_eq!(
            fs::metadata(&database)
                .expect("repaired database metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[test]
    fn openai_embedding_provider_uses_bounded_authenticated_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock embedding endpoint");
        let address = listener.local_addr().expect("mock endpoint address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept embedding request");
            let mut request = [0_u8; 8_192];
            let read = stream.read(&mut request).expect("read embedding request");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-key")
            );
            assert!(request.contains("\"model\":\"text-embedding-3-small\""));
            let body = r#"{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"text-embedding-3-small"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write embedding response");
        });
        let provider = OpenAiEmbeddingProvider::with_endpoint(
            "test-key",
            "text-embedding-3-small",
            Some(3),
            format!("http://127.0.0.1:{}", address.port()),
        )
        .expect("provider");
        assert_eq!(
            provider.embed("redacted context").expect("embedding"),
            vec![0.1, 0.2, 0.3]
        );
        server.join().expect("mock endpoint");
    }

    #[test]
    fn openai_embedding_provider_rejects_insecure_non_loopback_endpoint() {
        assert!(
            OpenAiEmbeddingProvider::with_endpoint(
                "test-key",
                "text-embedding-3-small",
                Some(3),
                "http://embedding.example/v1/embeddings",
            )
            .is_err()
        );
        assert!(OpenAiEmbeddingProvider::new("", "text-embedding-3-small", Some(3)).is_err());
    }
}
