use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type HostId = String;
pub type ProviderId = String;
pub type ProjectId = String;
pub type ArtifactId = String;
pub type ObservationId = String;
pub type EvidenceId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SensitivityClass {
    Public,
    Internal,
    Sensitive,
    SecretLike,
}

impl Default for SensitivityClass {
    fn default() -> Self {
        Self::Internal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactKind {
    Configuration,
    Instruction,
    Memory,
    Session,
    Tooling,
    ProjectContext,
    RuntimeEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObservationState {
    Present,
    Changed,
    Missing,
    Inaccessible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleState {
    Discovered,
    Candidate,
    Approved,
    Active,
    Stale,
    Superseded,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub host_id: Option<HostId>,
    pub provider_id: Option<ProviderId>,
    pub project_id: Option<ProjectId>,
}

impl Scope {
    pub fn host(host_id: impl Into<HostId>) -> Self {
        Self {
            host_id: Some(host_id.into()),
            provider_id: None,
            project_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceObservation {
    pub observation_id: ObservationId,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub native_id: String,
    pub source_reference: String,
    pub source_hash: String,
    pub observed_at: DateTime<Utc>,
    pub parser_version: String,
    pub schema_fingerprint: String,
    pub redaction_policy_version: String,
    pub collection_run_id: String,
    pub state: ObservationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSnapshot {
    pub evidence_id: EvidenceId,
    pub observation_id: ObservationId,
    pub excerpt: String,
    pub source_hash: String,
    pub observed_at: DateTime<Utc>,
    pub sensitivity: SensitivityClass,
    pub retention_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub artifact_id: ArtifactId,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub project_id: Option<ProjectId>,
    pub native_id: String,
    pub kind: ArtifactKind,
    pub title: String,
    pub source_reference: String,
    pub content: String,
    pub sensitivity: SensitivityClass,
    pub lifecycle: LifecycleState,
    pub observation: SourceObservation,
    pub evidence: Option<EvidenceSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: ProviderId,
    pub display_name: String,
    pub version: Option<String>,
    pub adapter_version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host_id: HostId,
    pub display_name: String,
    pub platform: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionBatch {
    pub collection_run_id: String,
    pub host: HostIdentity,
    pub providers: Vec<ProviderDescriptor>,
    pub artifacts: Vec<ArtifactRecord>,
    pub next_cursor: Option<String>,
}

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_prefixed_and_unique() {
        let first = new_id("obs");
        let second = new_id("obs");
        assert!(first.starts_with("obs_"));
        assert_ne!(first, second);
    }

    #[test]
    fn scope_can_be_serialized() {
        let scope = Scope::host("host_local");
        let json = serde_json::to_string(&scope).expect("scope should serialize");
        assert!(json.contains("host_local"));
    }
}
