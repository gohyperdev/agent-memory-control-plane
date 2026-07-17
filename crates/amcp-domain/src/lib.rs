use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub type HostId = String;
pub type ProviderId = String;
pub type ProjectId = String;
pub type ArtifactId = String;
pub type ObservationId = String;
pub type EvidenceId = String;
pub type ConfigLayerId = String;
pub type GuidanceId = String;
pub type ChangeSetId = String;
pub type ChangeOperationId = String;
pub type ApprovalId = String;
pub type AuditEventId = String;

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
pub enum HostStatus {
    Enrolling,
    Connected,
    Disconnected,
    Suspended,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeStatus {
    Proposed,
    Approved,
    Applying,
    Applied,
    Rejected,
    Conflict,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeOperationKind {
    ReplaceText,
    CreateText,
    DeleteFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    AllowRead,
    AllowRedactedRead,
    AllowProposal,
    RequireApproval,
    Deny,
    Unsupported,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub native_id: String,
    pub source_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    pub identity: HostIdentity,
    pub endpoint: Option<String>,
    pub agent_version: Option<String>,
    pub status: HostStatus,
    pub capabilities: Vec<String>,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionCursor {
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub cursor: Option<String>,
    pub collection_run_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTombstone {
    pub tombstone_id: String,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub native_id: String,
    pub source_hash: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRequest {
    pub actor: String,
    pub scope: Scope,
    pub target: ArtifactRef,
    pub expected_source_hash: Option<String>,
    pub operation: ChangeOperationKind,
    pub replacement_content: Option<String>,
    pub reason: String,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeOperation {
    pub operation_id: ChangeOperationId,
    pub target: ArtifactRef,
    pub operation: ChangeOperationKind,
    pub expected_source_hash: Option<String>,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub replacement_content: Option<String>,
    pub diff: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    pub change_set_id: ChangeSetId,
    pub actor: String,
    pub scope: Scope,
    pub provider_id: ProviderId,
    pub reason: String,
    pub evidence_ids: Vec<EvidenceId>,
    pub status: ChangeStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub operations: Vec<ChangeOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEnvelope {
    pub approval_id: ApprovalId,
    pub change_set_id: ChangeSetId,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub idempotency_key: String,
    pub operations_hash: String,
    pub approval_token: String,
}

impl ApprovalEnvelope {
    pub fn issue(
        secret: &str,
        change_set_id: impl Into<ChangeSetId>,
        approved_by: impl Into<String>,
        approved_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        idempotency_key: impl Into<String>,
        operations_hash: impl Into<String>,
    ) -> Self {
        let envelope = Self {
            approval_id: new_id("approval"),
            change_set_id: change_set_id.into(),
            approved_by: approved_by.into(),
            approved_at,
            expires_at,
            idempotency_key: idempotency_key.into(),
            operations_hash: operations_hash.into(),
            approval_token: String::new(),
        };
        let approval_token = envelope.signature(secret);
        Self {
            approval_token,
            ..envelope
        }
    }

    pub fn is_valid(&self, secret: &str, now: DateTime<Utc>) -> bool {
        !self.approved_by.trim().is_empty()
            && now >= self.approved_at
            && now <= self.expires_at
            && self.approval_token == self.signature(secret)
    }

    fn signature(&self, secret: &str) -> String {
        let payload = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.approval_id,
            self.change_set_id,
            self.approved_by,
            self.approved_at.to_rfc3339(),
            self.expires_at.to_rfc3339(),
            self.idempotency_key,
            self.operations_hash,
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts keys of any length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeReceipt {
    pub change_set_id: ChangeSetId,
    pub status: ChangeStatus,
    pub applied_at: DateTime<Utc>,
    pub backup_references: Vec<String>,
    pub before_hashes: Vec<String>,
    pub after_hashes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_event_id: AuditEventId,
    pub actor: String,
    pub operation: String,
    pub target: String,
    pub host_id: Option<HostId>,
    pub provider_id: Option<ProviderId>,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub result: String,
    pub correlation_id: String,
    pub timestamp: DateTime<Utc>,
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
pub struct ProjectRecord {
    pub project_id: ProjectId,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub root_path: String,
    pub display_name: String,
    pub trust_level: Option<String>,
    pub discovered_from: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub project_id: Option<ProjectId>,
    pub title: Option<String>,
    pub cwd: Option<String>,
    pub model: Option<String>,
    pub branch: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub archived: bool,
    pub source_reference: String,
    pub source_hash: String,
    pub metadata_json: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionItem {
    pub session_id: String,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub sequence: i64,
    pub role: Option<String>,
    pub item_kind: String,
    pub content: Option<String>,
    pub source_reference: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub memory_record_id: String,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub project_id: Option<ProjectId>,
    pub title: String,
    pub content: String,
    pub source_reference: String,
    pub source_hash: String,
    pub lifecycle: LifecycleState,
    pub confidence: Option<f32>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLayerRecord {
    pub config_layer_id: ConfigLayerId,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub project_id: Option<ProjectId>,
    pub source_reference: String,
    pub scope: String,
    pub profile: Option<String>,
    pub precedence_rank: i32,
    pub source_hash: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceRecord {
    pub guidance_id: GuidanceId,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub project_id: Option<ProjectId>,
    pub source_reference: String,
    pub relative_scope: String,
    pub kind: String,
    pub precedence_rank: i32,
    pub source_hash: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceEdge {
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub lower_guidance_id: GuidanceId,
    pub higher_guidance_id: GuidanceId,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub host_id: HostId,
    pub provider_id: ProviderId,
    pub event_type: String,
    pub sequence: i64,
    pub payload_json: String,
    pub occurred_at: DateTime<Utc>,
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
    #[serde(default)]
    pub projects: Vec<ProjectRecord>,
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
    #[serde(default)]
    pub session_items: Vec<SessionItem>,
    #[serde(default)]
    pub memory_records: Vec<MemoryRecord>,
    #[serde(default)]
    pub config_layers: Vec<ConfigLayerRecord>,
    #[serde(default)]
    pub guidance_records: Vec<GuidanceRecord>,
    #[serde(default)]
    pub guidance_edges: Vec<GuidanceEdge>,
    #[serde(default)]
    pub runtime_events: Vec<RuntimeEvent>,
    pub artifacts: Vec<ArtifactRecord>,
    pub next_cursor: Option<String>,
}

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4())
}

pub fn change_set_operations_hash(change_set: &ChangeSet) -> String {
    let encoded = serde_json::to_vec(&change_set.operations)
        .expect("change operations should always be serializable");
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    hex::encode(hasher.finalize())
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

    #[test]
    fn approval_envelope_is_bound_to_secret_and_expiry() {
        let now = Utc::now();
        let approval = ApprovalEnvelope::issue(
            "shared-secret",
            "change_1",
            "human",
            now,
            now + chrono::Duration::minutes(5),
            "idem_1",
            "ops_hash",
        );
        assert!(approval.is_valid("shared-secret", now));
        assert!(!approval.is_valid("wrong-secret", now));
        assert!(!approval.is_valid("shared-secret", now + chrono::Duration::minutes(6)));
    }
}
