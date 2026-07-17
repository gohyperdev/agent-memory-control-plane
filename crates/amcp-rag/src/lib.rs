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
}
