use amcp_domain::{LifecycleState, Scope, SensitivityClass};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RAG_POLICY_VERSION: &str = "amcp-rag-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagConfig {
    pub enabled: bool,
    pub allowed_scopes: Vec<Scope>,
    pub embedding_provider: Option<String>,
    pub embedding_model: Option<String>,
    pub retention_days: Option<u32>,
    pub chunk_size: usize,
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

/// Embedding providers are deliberately isolated from retrieval policy. A
/// provider can be local or remote, but it must return only bounded vectors;
/// the Controller decides whether the provider is allowed for a scope.
pub trait EmbeddingProvider: Send + Sync {
    fn descriptor(&self) -> EmbeddingProviderDescriptor;
    fn embed(&self, text: &str) -> Result<Vec<f32>>;
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
}
