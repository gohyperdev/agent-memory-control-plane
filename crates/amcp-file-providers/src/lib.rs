#![allow(clippy::too_many_arguments)]

use amcp_domain::{
    ArtifactKind, ArtifactRecord, ArtifactRef, CollectionBatch, ConfigLayerRecord,
    EvidenceSnapshot, GuidanceRecord, HostIdentity, LifecycleState, MemoryRecord, ObservationState,
    ProjectRecord, ProviderCompatibility, ProviderDescriptor, ProviderHealth, ProviderSupportLevel,
    SensitivityClass, SourceObservation, new_id,
};
use amcp_provider_api::ProviderAdapter;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use walkdir::WalkDir;

pub const CLAUDE_CODE_PROVIDER_ID: &str = "claude-code";
pub const KIRO_PROVIDER_ID: &str = "kiro";
pub const ANTIGRAVITY_PROVIDER_ID: &str = "antigravity";
pub const ADAPTER_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    Instruction,
    Configuration,
    Tooling,
}

#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    kind: CandidateKind,
    project_id: Option<String>,
    scope: String,
    precedence_rank: i32,
    memory: bool,
    guidance_kind: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileProviderAdapter {
    descriptor: ProviderDescriptor,
    user_root: PathBuf,
    project_roots: Vec<PathBuf>,
    family: ProviderFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderFamily {
    ClaudeCode,
    Kiro,
    Antigravity,
}

impl ProviderFamily {
    fn schema_fingerprint(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code-file-state-v1",
            Self::Kiro => "kiro-file-state-v1",
            Self::Antigravity => "antigravity-file-state-v1",
        }
    }
}

pub type ClaudeCodeAdapter = FileProviderAdapter;
pub type KiroAdapter = FileProviderAdapter;
pub type AntigravityAdapter = FileProviderAdapter;

impl FileProviderAdapter {
    pub fn claude_code_from_environment() -> ClaudeCodeAdapter {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let user_root = env::var_os("AMCP_CLAUDE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"));
        Self::new(
            CLAUDE_CODE_PROVIDER_ID,
            "Claude Code",
            user_root,
            project_roots("AMCP_CLAUDE_PROJECT_ROOTS"),
            ProviderFamily::ClaudeCode,
        )
    }

    pub fn kiro_from_environment() -> KiroAdapter {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let user_root = env::var_os("AMCP_KIRO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".kiro"));
        Self::new(
            KIRO_PROVIDER_ID,
            "Kiro",
            user_root,
            project_roots("AMCP_KIRO_PROJECT_ROOTS"),
            ProviderFamily::Kiro,
        )
    }

    pub fn antigravity_from_environment() -> AntigravityAdapter {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let user_root = env::var_os("AMCP_ANTIGRAVITY_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".gemini/antigravity"));
        Self::new(
            ANTIGRAVITY_PROVIDER_ID,
            "Google Antigravity",
            user_root,
            project_roots("AMCP_ANTIGRAVITY_PROJECT_ROOTS"),
            ProviderFamily::Antigravity,
        )
    }

    fn new(
        id: &str,
        display_name: &str,
        user_root: PathBuf,
        project_roots: Vec<PathBuf>,
        family: ProviderFamily,
    ) -> Self {
        let native_roots = native_root_references(&user_root, &project_roots);
        Self {
            descriptor: ProviderDescriptor {
                id: id.into(),
                display_name: display_name.into(),
                version: None,
                adapter_version: ADAPTER_VERSION.into(),
                schema_fingerprint: family.schema_fingerprint().into(),
                support_level: ProviderSupportLevel::ReadOnly,
                health: ProviderHealth::Healthy,
                compatibility: ProviderCompatibility::Compatible,
                native_roots,
                capabilities: vec![
                    "inventory".into(),
                    "search".into(),
                    "memory".into(),
                    "configuration".into(),
                    "guidance".into(),
                    "projects".into(),
                ],
            },
            user_root,
            project_roots,
            family,
        }
    }

    fn candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        match self.family {
            ProviderFamily::ClaudeCode => self.claude_candidates(&mut candidates),
            ProviderFamily::Kiro => self.kiro_candidates(&mut candidates),
            ProviderFamily::Antigravity => self.antigravity_candidates(&mut candidates),
        }
        candidates.sort_by(|left, right| left.path.cmp(&right.path));
        candidates.dedup_by(|left, right| left.path == right.path);
        candidates
    }

    fn claude_candidates(&self, candidates: &mut Vec<Candidate>) {
        self.add_file(
            candidates,
            self.user_root.join("CLAUDE.md"),
            CandidateKind::Instruction,
            None,
            "user",
            20,
            true,
            Some("user"),
        );
        self.add_file(
            candidates,
            self.user_root.join("settings.json"),
            CandidateKind::Configuration,
            None,
            "user",
            20,
            false,
            None,
        );
        for root in &self.project_roots {
            let project_id = project_id(root);
            self.add_file(
                candidates,
                root.join("CLAUDE.md"),
                CandidateKind::Instruction,
                project_id.clone(),
                "project",
                40,
                true,
                Some("project"),
            );
            self.add_file(
                candidates,
                root.join("CLAUDE.local.md"),
                CandidateKind::Instruction,
                project_id.clone(),
                "project-local",
                41,
                true,
                Some("project-local"),
            );
            self.add_file(
                candidates,
                root.join(".mcp.json"),
                CandidateKind::Tooling,
                project_id.clone(),
                "project",
                40,
                false,
                None,
            );
            self.add_file(
                candidates,
                root.join(".claude/settings.json"),
                CandidateKind::Configuration,
                project_id.clone(),
                "project",
                40,
                false,
                None,
            );
            self.add_file(
                candidates,
                root.join(".claude/settings.local.json"),
                CandidateKind::Configuration,
                project_id.clone(),
                "project-local",
                41,
                false,
                None,
            );
            self.add_directory(
                candidates,
                &root.join(".claude/commands"),
                project_id.clone(),
                CandidateKind::Instruction,
                42,
                false,
                Some("command"),
            );
            self.add_directory(
                candidates,
                &root.join(".claude/agents"),
                project_id,
                CandidateKind::Instruction,
                42,
                false,
                Some("agent"),
            );
        }
    }

    fn kiro_candidates(&self, candidates: &mut Vec<Candidate>) {
        self.add_directory(
            candidates,
            &self.user_root.join("steering"),
            None,
            CandidateKind::Instruction,
            20,
            true,
            Some("user-steering"),
        );
        self.add_file(
            candidates,
            self.user_root.join("settings/cli.json"),
            CandidateKind::Configuration,
            None,
            "user",
            20,
            false,
            None,
        );
        self.add_file(
            candidates,
            self.user_root.join("settings/mcp.json"),
            CandidateKind::Tooling,
            None,
            "user",
            20,
            false,
            None,
        );
        self.add_directory(
            candidates,
            &self.user_root.join("prompts"),
            None,
            CandidateKind::Instruction,
            20,
            true,
            Some("user-prompt"),
        );
        self.add_directory(
            candidates,
            &self.user_root.join("agents"),
            None,
            CandidateKind::Instruction,
            20,
            true,
            Some("user-agent"),
        );
        for root in &self.project_roots {
            let project_id = project_id(root);
            let project_root = root.join(".kiro");
            self.add_directory(
                candidates,
                &project_root.join("steering"),
                project_id.clone(),
                CandidateKind::Instruction,
                40,
                true,
                Some("project-steering"),
            );
            self.add_file(
                candidates,
                project_root.join("settings/mcp.json"),
                CandidateKind::Tooling,
                project_id.clone(),
                "project",
                40,
                false,
                None,
            );
            self.add_directory(
                candidates,
                &project_root.join("agents"),
                project_id.clone(),
                CandidateKind::Instruction,
                41,
                true,
                Some("project-agent"),
            );
            self.add_directory(
                candidates,
                &project_root.join("prompts"),
                project_id,
                CandidateKind::Instruction,
                41,
                true,
                Some("project-prompt"),
            );
        }
    }

    fn antigravity_candidates(&self, candidates: &mut Vec<Candidate>) {
        self.add_directory(
            candidates,
            &self.user_root.join("knowledge"),
            None,
            CandidateKind::Instruction,
            20,
            true,
            Some("knowledge"),
        );
        self.add_directory(
            candidates,
            &self.user_root.join("plugins"),
            None,
            CandidateKind::Tooling,
            20,
            true,
            Some("global-plugin"),
        );
        self.add_file(
            candidates,
            self.user_root
                .parent()
                .unwrap_or(&self.user_root)
                .join("antigravity-cli/settings.json"),
            CandidateKind::Configuration,
            None,
            "user",
            20,
            false,
            None,
        );
        self.add_directory(
            candidates,
            &self
                .user_root
                .parent()
                .unwrap_or(&self.user_root)
                .join("config/plugins"),
            None,
            CandidateKind::Tooling,
            20,
            true,
            Some("global-plugin"),
        );
        for root in &self.project_roots {
            let project_id = project_id(root);
            self.add_directory(
                candidates,
                &root.join(".agents/plugins"),
                project_id.clone(),
                CandidateKind::Tooling,
                40,
                true,
                Some("workspace-plugin"),
            );
            self.add_directory(
                candidates,
                &root.join("_agents/plugins"),
                project_id,
                CandidateKind::Tooling,
                40,
                true,
                Some("workspace-plugin"),
            );
        }
    }

    fn add_file(
        &self,
        candidates: &mut Vec<Candidate>,
        path: PathBuf,
        kind: CandidateKind,
        project_id: Option<String>,
        scope: &str,
        precedence_rank: i32,
        memory: bool,
        guidance_kind: Option<&str>,
    ) {
        if path.is_file() && !is_sensitive_path(&path) {
            candidates.push(Candidate {
                path,
                kind,
                project_id,
                scope: scope.into(),
                precedence_rank,
                memory,
                guidance_kind: guidance_kind.map(str::to_owned),
            });
        }
    }

    fn add_directory(
        &self,
        candidates: &mut Vec<Candidate>,
        directory: &Path,
        project_id: Option<String>,
        kind: CandidateKind,
        precedence_rank: i32,
        memory: bool,
        guidance_kind: Option<&str>,
    ) {
        if !directory.is_dir() {
            return;
        }
        for entry in WalkDir::new(directory)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file()
                && !is_sensitive_path(entry.path())
                && supported_file(entry.path())
            {
                self.add_file(
                    candidates,
                    entry.path().to_path_buf(),
                    kind,
                    project_id.clone(),
                    "directory",
                    precedence_rank,
                    memory,
                    guidance_kind,
                );
            }
        }
    }

    fn authorized_candidate(&self, source_reference: &str) -> Result<Candidate> {
        let requested = PathBuf::from(source_reference);
        if !requested.is_absolute() {
            bail!("provider artifact reference must be an absolute path");
        }
        let metadata = fs::symlink_metadata(&requested)
            .with_context(|| format!("stat provider artifact {source_reference}"))?;
        if !metadata.file_type().is_file() {
            bail!("provider artifact is not a regular file");
        }
        if metadata.file_type().is_symlink() || is_sensitive_path(&requested) {
            bail!("provider artifact is not readable by policy");
        }
        let canonical = fs::canonicalize(&requested)?;
        self.candidates()
            .into_iter()
            .find(|candidate| {
                fs::canonicalize(&candidate.path)
                    .map(|path| path == canonical)
                    .unwrap_or(false)
            })
            .with_context(|| "provider artifact is outside discovered adapter roots")
    }

    fn live_artifact(&self, target: &ArtifactRef, host: &HostIdentity) -> Result<ArtifactRecord> {
        if target.provider_id != self.descriptor.id || target.host_id != host.host_id {
            bail!("artifact target is outside this provider Agent scope");
        }
        let candidate = self.authorized_candidate(&target.source_reference)?;
        let metadata = fs::metadata(&candidate.path)?;
        if metadata.len() > 1_000_000 {
            bail!("provider artifact exceeds the 1 MiB live-read safety limit");
        }
        let bytes = fs::read(&candidate.path)?;
        let source_reference = candidate.path.to_string_lossy().into_owned();
        let source_hash = hash_bytes(&bytes);
        let observed_at = Utc::now();
        let collection_run_id = new_id("read");
        let observation_id = new_id("obs");
        let content = redact_text(
            &String::from_utf8_lossy(&bytes)
                .chars()
                .take(4_000)
                .collect::<String>(),
        );
        let sensitivity = classify(&content);
        Ok(ArtifactRecord {
            artifact_id: new_id("artifact"),
            host_id: host.host_id.clone(),
            provider_id: self.descriptor.id.clone(),
            project_id: candidate.project_id,
            native_id: source_reference.clone(),
            kind: candidate.kind.to_artifact_kind(),
            title: candidate
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("provider file")
                .into(),
            source_reference: source_reference.clone(),
            content: content.clone(),
            sensitivity: sensitivity.clone(),
            lifecycle: LifecycleState::Active,
            observation: SourceObservation {
                observation_id: observation_id.clone(),
                host_id: host.host_id.clone(),
                provider_id: self.descriptor.id.clone(),
                native_id: source_reference.clone(),
                source_reference: source_reference.clone(),
                source_hash: source_hash.clone(),
                observed_at,
                parser_version: ADAPTER_VERSION.into(),
                schema_fingerprint: format!("file:{}", extension(&candidate.path)),
                redaction_policy_version: "amcp-redaction-v1".into(),
                collection_run_id,
                state: ObservationState::Present,
            },
            evidence: Some(EvidenceSnapshot {
                evidence_id: new_id("evidence"),
                observation_id,
                excerpt: content,
                source_hash,
                observed_at,
                sensitivity,
                retention_until: None,
            }),
        })
    }
}

impl ProviderAdapter for FileProviderAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn read_artifact(&self, target: &ArtifactRef, host: &HostIdentity) -> Result<ArtifactRecord> {
        self.live_artifact(target, host)
    }

    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch> {
        let collection_run_id = new_id("run");
        let candidates = self.candidates();
        let mut projects = Vec::new();
        for root in &self.project_roots {
            if root.is_dir() {
                projects.push(ProjectRecord {
                    project_id: project_id(root).unwrap_or_else(|| root.display().to_string()),
                    host_id: host.host_id.clone(),
                    provider_id: self.descriptor.id.clone(),
                    root_path: root.to_string_lossy().into_owned(),
                    display_name: root
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("project")
                        .into(),
                    trust_level: None,
                    discovered_from: self.user_root.to_string_lossy().into_owned(),
                    observed_at: Utc::now(),
                });
            }
        }
        let mut artifacts = Vec::new();
        let mut memory_records = Vec::new();
        let mut config_layers = Vec::new();
        let mut guidance_records = Vec::new();
        for candidate in candidates {
            let bytes = fs::read(&candidate.path)
                .with_context(|| format!("read provider file {}", candidate.path.display()))?;
            let source_reference = candidate.path.to_string_lossy().into_owned();
            let content = redact_text(&String::from_utf8_lossy(&bytes));
            let preview = content.chars().take(4_000).collect::<String>();
            let source_hash = hash_bytes(&bytes);
            let observed_at = Utc::now();
            let observation_id = new_id("obs");
            let sensitivity = classify(&preview);
            artifacts.push(ArtifactRecord {
                artifact_id: new_id("artifact"),
                host_id: host.host_id.clone(),
                provider_id: self.descriptor.id.clone(),
                project_id: candidate.project_id.clone(),
                native_id: source_reference.clone(),
                kind: candidate.kind.to_artifact_kind(),
                title: candidate
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("provider file")
                    .into(),
                source_reference: source_reference.clone(),
                content: preview.clone(),
                sensitivity: sensitivity.clone(),
                lifecycle: LifecycleState::Active,
                observation: SourceObservation {
                    observation_id: observation_id.clone(),
                    host_id: host.host_id.clone(),
                    provider_id: self.descriptor.id.clone(),
                    native_id: source_reference.clone(),
                    source_reference: source_reference.clone(),
                    source_hash: source_hash.clone(),
                    observed_at,
                    parser_version: ADAPTER_VERSION.into(),
                    schema_fingerprint: format!("file:{}", extension(&candidate.path)),
                    redaction_policy_version: "amcp-redaction-v1".into(),
                    collection_run_id: collection_run_id.clone(),
                    state: ObservationState::Present,
                },
                evidence: Some(EvidenceSnapshot {
                    evidence_id: new_id("evidence"),
                    observation_id,
                    excerpt: preview.clone(),
                    source_hash: source_hash.clone(),
                    observed_at,
                    sensitivity: sensitivity.clone(),
                    retention_until: None,
                }),
            });
            if candidate.memory {
                memory_records.push(MemoryRecord {
                    memory_record_id: format!("memory_{}", hash_bytes(source_reference.as_bytes())),
                    host_id: host.host_id.clone(),
                    provider_id: self.descriptor.id.clone(),
                    project_id: candidate.project_id.clone(),
                    title: candidate
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("provider memory")
                        .into(),
                    content: redact_text(
                        &String::from_utf8_lossy(&bytes)
                            .chars()
                            .take(12_000)
                            .collect::<String>(),
                    ),
                    source_reference: source_reference.clone(),
                    source_hash: source_hash.clone(),
                    lifecycle: LifecycleState::Active,
                    confidence: None,
                    observed_at,
                });
            }
            if matches!(
                candidate.kind,
                CandidateKind::Configuration | CandidateKind::Tooling
            ) {
                config_layers.push(ConfigLayerRecord {
                    config_layer_id: format!("config_{}", hash_bytes(source_reference.as_bytes())),
                    host_id: host.host_id.clone(),
                    provider_id: self.descriptor.id.clone(),
                    project_id: candidate.project_id.clone(),
                    source_reference: source_reference.clone(),
                    scope: candidate.scope.clone(),
                    profile: None,
                    precedence_rank: candidate.precedence_rank,
                    source_hash: source_hash.clone(),
                    observed_at,
                });
            }
            if let Some(kind) = candidate.guidance_kind {
                guidance_records.push(GuidanceRecord {
                    guidance_id: format!("guidance_{}", hash_bytes(source_reference.as_bytes())),
                    host_id: host.host_id.clone(),
                    provider_id: self.descriptor.id.clone(),
                    project_id: candidate.project_id.clone(),
                    source_reference: source_reference.clone(),
                    relative_scope: candidate
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("provider guidance")
                        .into(),
                    kind,
                    precedence_rank: candidate.precedence_rank,
                    source_hash,
                    observed_at,
                });
            }
        }
        Ok(CollectionBatch {
            collection_run_id,
            host: host.clone(),
            providers: vec![self.descriptor()],
            projects,
            sessions: Vec::new(),
            session_items: Vec::new(),
            memory_records,
            config_layers,
            guidance_records,
            guidance_edges: Vec::new(),
            runtime_events: vec![amcp_domain::RuntimeEvent {
                event_id: new_id("event"),
                host_id: host.host_id,
                provider_id: self.descriptor.id.clone(),
                event_type: "inventory.completed".into(),
                sequence: 0,
                payload_json: serde_json::json!({"artifacts": artifacts.len()}).to_string(),
                occurred_at: Utc::now(),
            }],
            artifacts,
            next_cursor: None,
        })
    }
}

impl CandidateKind {
    fn to_artifact_kind(self) -> ArtifactKind {
        match self {
            Self::Instruction => ArtifactKind::Instruction,
            Self::Configuration => ArtifactKind::Configuration,
            Self::Tooling => ArtifactKind::Tooling,
        }
    }
}

fn project_roots(variable: &str) -> Vec<PathBuf> {
    env::var_os(variable)
        .or_else(|| env::var_os("AMCP_SCAN_ROOTS"))
        .map(|value| {
            value
                .to_string_lossy()
                .split(':')
                .filter(|part| !part.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn native_root_references(user_root: &Path, project_roots: &[PathBuf]) -> Vec<String> {
    let mut roots = Vec::with_capacity(project_roots.len() + 1);
    roots.push(user_root.to_string_lossy().into_owned());
    roots.extend(
        project_roots
            .iter()
            .map(|root| root.to_string_lossy().into_owned()),
    );
    roots.sort();
    roots.dedup();
    roots
}

fn project_id(root: &Path) -> Option<String> {
    fs::canonicalize(root)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn supported_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("md" | "markdown" | "json" | "toml" | "yaml" | "yml")
    )
}

fn is_sensitive_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some("auth.json" | ".env" | ".env.local" | "credentials" | "secrets")
        )
    })
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("unknown")
        .into()
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn classify(content: &str) -> SensitivityClass {
    if content.contains("[REDACTED]") {
        SensitivityClass::Sensitive
    } else {
        SensitivityClass::Internal
    }
}

fn redact_text(input: &str) -> String {
    static KEY_VALUE: OnceLock<Regex> = OnceLock::new();
    static BEARER: OnceLock<Regex> = OnceLock::new();
    let key_value = KEY_VALUE.get_or_init(|| {
        Regex::new(r#"(?i)(api[_-]?key|token|password|secret|authorization)\s*["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s\n,}]+)"#)
            .expect("file provider redaction regex")
    });
    let bearer = BEARER.get_or_init(|| {
        Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+").expect("file provider bearer regex")
    });
    let value = key_value.replace_all(input, "$1=[REDACTED]");
    bearer.replace_all(&value, "Bearer [REDACTED]").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcp_domain::HostIdentity;

    fn host() -> HostIdentity {
        HostIdentity {
            host_id: "file-provider-host".into(),
            display_name: "File provider host".into(),
            platform: "macos".into(),
            hostname: "file-provider.local".into(),
        }
    }

    #[test]
    fn claude_fixture_discovers_memory_config_and_redacts_secrets() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/claude-code");
        let project = root.join("project");
        let adapter = FileProviderAdapter::new(
            CLAUDE_CODE_PROVIDER_ID,
            "Claude Code",
            root.join(".claude"),
            vec![project],
            ProviderFamily::ClaudeCode,
        );
        let batch = adapter.discover(host()).expect("Claude fixture");
        assert_eq!(batch.providers[0].id, CLAUDE_CODE_PROVIDER_ID);
        assert_eq!(
            batch.providers[0].schema_fingerprint,
            "claude-code-file-state-v1"
        );
        assert_eq!(
            batch.providers[0].support_level,
            ProviderSupportLevel::ReadOnly
        );
        assert_eq!(batch.providers[0].health, ProviderHealth::Healthy);
        assert_eq!(
            batch.providers[0].compatibility,
            ProviderCompatibility::Compatible
        );
        assert!(
            batch.providers[0]
                .native_roots
                .iter()
                .any(|root| root.ends_with("fixtures/claude-code/.claude"))
        );
        assert!(
            batch
                .memory_records
                .iter()
                .any(|record| record.title == "CLAUDE.md")
        );
        assert!(
            batch
                .config_layers
                .iter()
                .any(|layer| layer.source_reference.ends_with("settings.json"))
        );
        assert!(
            batch
                .artifacts
                .iter()
                .all(|artifact| !artifact.content.contains("fixture-secret"))
        );
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|guidance| guidance.kind == "project")
        );
    }

    #[test]
    fn future_file_providers_support_scoped_live_reads_without_mutation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let host = host();
        let providers = [
            (
                FileProviderAdapter::new(
                    CLAUDE_CODE_PROVIDER_ID,
                    "Claude Code",
                    root.join("claude-code/.claude"),
                    vec![root.join("claude-code/project")],
                    ProviderFamily::ClaudeCode,
                ),
                "CLAUDE.md",
            ),
            (
                FileProviderAdapter::new(
                    KIRO_PROVIDER_ID,
                    "Kiro",
                    root.join("kiro/.kiro"),
                    vec![root.join("kiro/project")],
                    ProviderFamily::Kiro,
                ),
                "product.md",
            ),
            (
                FileProviderAdapter::new(
                    ANTIGRAVITY_PROVIDER_ID,
                    "Google Antigravity",
                    root.join("antigravity/.gemini/antigravity"),
                    vec![root.join("antigravity/project")],
                    ProviderFamily::Antigravity,
                ),
                "team.md",
            ),
        ];

        for (adapter, title) in providers {
            assert_eq!(
                adapter.descriptor().support_level,
                ProviderSupportLevel::ReadOnly
            );
            assert!(adapter.descriptor().schema_fingerprint.ends_with("-v1"));
            let batch = adapter.discover(host.clone()).expect("provider fixture");
            let source_reference = batch
                .artifacts
                .iter()
                .find(|artifact| artifact.title == title)
                .map(|artifact| artifact.source_reference.clone())
                .expect("fixture artifact");
            let artifact = adapter
                .read_artifact(
                    &ArtifactRef {
                        host_id: host.host_id.clone(),
                        provider_id: adapter.descriptor().id,
                        native_id: source_reference.clone(),
                        source_reference,
                    },
                    &host,
                )
                .expect("live provider read");
            assert_eq!(artifact.title, title);
            assert!(!artifact.content.contains("fixture-secret"));
        }
    }

    #[test]
    fn kiro_fixture_discovers_project_steering() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/kiro");
        let project = root.join("project");
        let adapter = FileProviderAdapter::new(
            KIRO_PROVIDER_ID,
            "Kiro",
            root.join(".kiro"),
            vec![project],
            ProviderFamily::Kiro,
        );
        let batch = adapter.discover(host()).expect("Kiro fixture");
        assert!(
            batch
                .memory_records
                .iter()
                .any(|record| record.title == "product.md")
        );
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|record| record.kind == "project-steering")
        );
        assert!(
            batch
                .projects
                .iter()
                .any(|project| project.display_name == "project")
        );
    }

    #[test]
    fn antigravity_fixture_discovers_knowledge_cli_settings_and_plugins() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/antigravity");
        let adapter = FileProviderAdapter::new(
            ANTIGRAVITY_PROVIDER_ID,
            "Google Antigravity",
            root.join(".gemini/antigravity"),
            vec![root.join("project")],
            ProviderFamily::Antigravity,
        );
        let batch = adapter.discover(host()).expect("Antigravity fixture");
        assert!(
            batch
                .memory_records
                .iter()
                .any(|record| record.title == "team.md")
        );
        assert!(
            batch
                .config_layers
                .iter()
                .any(|layer| layer.source_reference.ends_with("settings.json"))
        );
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|record| record.kind == "workspace-plugin")
        );
        assert!(
            batch
                .artifacts
                .iter()
                .all(|artifact| !artifact.content.contains("fixture-secret"))
        );
    }
}
