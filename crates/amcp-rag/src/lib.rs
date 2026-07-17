use amcp_domain::{LifecycleState, Scope, SensitivityClass};
use anyhow::Result;
use serde::{Deserialize, Serialize};

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
}

/// A bounded, in-memory lexical retriever used when the user explicitly enables
/// RAG without configuring an embedding provider. It keeps the same citation and
/// invalidation contract as a future vector implementation.
#[derive(Debug, Clone)]
pub struct LexicalRagManager {
    config: RagConfig,
    chunks: Vec<IndexedChunk>,
}

impl LexicalRagManager {
    pub fn new(config: RagConfig) -> Self {
        Self {
            config,
            chunks: Vec::new(),
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
                });
                indexed += 1;
            }
        }
        Ok(indexed)
    }

    fn retrieve(&self, query: &str, scope: &Scope, limit: usize) -> Result<RetrievalContext> {
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
                let score = query
                    .split_whitespace()
                    .filter(|term| lower.contains(&term.to_lowercase()))
                    .count();
                (score, chunk)
            })
            .filter(|(score, _)| *score > 0)
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.source_reference.cmp(&right.source_reference))
                .then_with(|| left.chunk_index.cmp(&right.chunk_index))
        });
        let selected = ranked.into_iter().take(limit).collect::<Vec<_>>();
        Ok(RetrievalContext {
            enabled: self.config.enabled,
            query: query.to_owned(),
            scope: scope.clone(),
            context: selected
                .iter()
                .map(|(_, chunk)| format!("{}: {}", chunk.title, chunk.text))
                .collect(),
            citations: selected
                .iter()
                .map(|(_, chunk)| RagCitation {
                    record_id: chunk.record_id.clone(),
                    source_reference: chunk.source_reference.clone(),
                    source_hash: chunk.source_hash.clone(),
                    chunk_index: chunk.chunk_index,
                })
                .collect(),
            policy_version: RAG_POLICY_VERSION.to_owned(),
            warning: if self.config.enabled {
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
}
