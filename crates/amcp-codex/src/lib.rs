#![allow(clippy::too_many_arguments)]

use amcp_domain::{
    ArtifactKind, ArtifactRecord, ArtifactRef, ChangeOperationKind, ChangeReceipt, ChangeRequest,
    ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord, EvidenceSnapshot, GuidanceEdge,
    GuidanceRecord, HostIdentity, LifecycleState, MemoryRecord, ObservationState, ProjectRecord,
    ProviderCompatibility, ProviderDescriptor, ProviderHealth, ProviderSupportLevel, RuntimeEvent,
    RuntimeThreadRecord, SensitivityClass, SessionItem, SessionRecord, SourceObservation, new_id,
    stable_runtime_event_id,
};
use amcp_provider_api::{ProviderAdapter, RuntimeAdapterDescriptor, RuntimeRequest};
use anyhow::{Result, bail};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};
use walkdir::WalkDir;

pub const CODEX_PROVIDER_ID: &str = "codex";
pub const ADAPTER_VERSION: &str = "0.1.0";
pub const PROVIDER_SCHEMA_FINGERPRINT: &str = "codex-file-state-v1";
pub const REDACTION_POLICY_VERSION: &str = "amcp-redaction-v1";

#[derive(Debug, Clone)]
pub struct CodexAdapter {
    pub codex_home: PathBuf,
    pub scan_roots: Vec<PathBuf>,
}

impl CodexAdapter {
    pub fn from_environment(codex_home: Option<PathBuf>) -> Self {
        let home = codex_home
            .or_else(|| env::var_os("CODEX_HOME").map(PathBuf::from))
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex")))
            .unwrap_or_else(|| PathBuf::from(".codex"));

        let scan_roots = env::var_os("AMCP_SCAN_ROOTS")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(':')
                    .filter(|part| !part.is_empty())
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default();

        Self {
            codex_home: home,
            scan_roots,
        }
    }

    pub fn provider(&self) -> ProviderDescriptor {
        let installation = codex_installation_metadata(&self.codex_home);
        let mut capabilities = vec![
            "inventory".to_owned(),
            "read".to_owned(),
            "search".to_owned(),
            "projects".to_owned(),
            "sessions".to_owned(),
            "memory".to_owned(),
            "runtime".to_owned(),
        ];
        if installation.codex_home_detected {
            capabilities.push("codex-home-detected".to_owned());
        }
        if installation.sqlite_home_detected {
            capabilities.push("codex-sqlite-home-detected".to_owned());
        } else if installation.sqlite_home_configured {
            capabilities.push("codex-sqlite-home-unavailable".to_owned());
        }
        if installation.executable_detected {
            capabilities.push("codex-cli-detected".to_owned());
        }
        if installation.version.is_some() {
            capabilities.push("codex-version-detected".to_owned());
        }
        let native_roots = self
            .discovery_roots()
            .into_iter()
            .map(|root| root.to_string_lossy().into_owned())
            .collect();
        ProviderDescriptor {
            id: CODEX_PROVIDER_ID.to_owned(),
            display_name: "OpenAI Codex".to_owned(),
            version: installation.version,
            adapter_version: ADAPTER_VERSION.to_owned(),
            schema_fingerprint: PROVIDER_SCHEMA_FINGERPRINT.to_owned(),
            support_level: ProviderSupportLevel::Full,
            health: ProviderHealth::Healthy,
            compatibility: ProviderCompatibility::Compatible,
            native_roots,
            capabilities,
        }
    }

    pub fn discover(&self, host: HostIdentity) -> io::Result<CollectionBatch> {
        let collection_run_id = new_id("run");
        let mut artifacts = Vec::new();
        let mut projects = Vec::new();
        let mut sessions = Vec::new();
        let mut session_items = Vec::new();
        let mut memory_records = Vec::new();
        let mut config_layers = Vec::new();
        let mut guidance_records = Vec::new();
        let roots = self.discovery_roots();

        for root in roots {
            if !root.exists() {
                continue;
            }
            self.discover_root(
                &root,
                &host,
                &collection_run_id,
                &mut artifacts,
                &mut projects,
                &mut sessions,
                &mut session_items,
                &mut memory_records,
                &mut config_layers,
                &mut guidance_records,
            )?;
        }

        self.discover_projects_from_session_metadata(&host, &mut projects, &mut sessions);

        artifacts.sort_by(|left, right| left.source_reference.cmp(&right.source_reference));
        projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
        projects.dedup_by(|left, right| left.project_id == right.project_id);
        sessions.sort_by(|left, right| {
            left.session_id.cmp(&right.session_id).then_with(|| {
                session_source_priority(&left.source_reference)
                    .cmp(&session_source_priority(&right.source_reference))
            })
        });
        sessions.dedup_by(|left, right| left.session_id == right.session_id);
        config_layers.sort_by(|left, right| left.source_reference.cmp(&right.source_reference));
        config_layers.dedup_by(|left, right| left.source_reference == right.source_reference);
        guidance_records.sort_by(|left, right| {
            left.source_reference
                .cmp(&right.source_reference)
                .then(left.precedence_rank.cmp(&right.precedence_rank))
        });
        guidance_records.dedup_by(|left, right| left.source_reference == right.source_reference);
        let guidance_edges = self.guidance_edges(&guidance_records, &projects);

        let mut batch = CollectionBatch {
            collection_run_id,
            host,
            providers: vec![self.provider()],
            projects,
            sessions,
            session_items,
            memory_records,
            config_layers,
            guidance_records,
            guidance_edges,
            runtime_events: Vec::new(),
            artifacts,
            next_cursor: None,
        };
        batch.runtime_events.push(RuntimeEvent {
            event_id: new_id("event"),
            host_id: batch.host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            event_type: "inventory.completed".to_owned(),
            sequence: 0,
            payload_json: serde_json::json!({
                "artifacts": batch.artifacts.len(),
                "projects": batch.projects.len(),
                "sessions": batch.sessions.len(),
                "memories": batch.memory_records.len()
            })
            .to_string(),
            occurred_at: Utc::now(),
        });
        Ok(batch)
    }

    pub fn propose_change(&self, request: &ChangeRequest) -> Result<ChangeSet> {
        if request.target.provider_id != CODEX_PROVIDER_ID {
            bail!("unsupported provider: {}", request.target.provider_id);
        }
        if request.target.host_id.trim().is_empty() {
            bail!("change target has no host id");
        }
        let path = self.authorized_path(&request.target.source_reference)?;
        self.ensure_project_is_writable(&path)?;
        if matches!(request.operation, ChangeOperationKind::DeleteFile) {
            bail!("Codex adapter does not allow file deletion in this release");
        }
        let current = read_optional(&path)?;
        let before_hash = current.as_deref().map(hash_bytes);
        if let Some(expected) = &request.expected_source_hash
            && before_hash.as_deref() != Some(expected.as_str())
        {
            bail!(
                "source hash conflict: expected {expected}, found {:?}",
                before_hash
            );
        }
        let replacement = request
            .replacement_content
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("replacement content is required"))?;
        if replacement.len() > 1_000_000 {
            bail!("replacement content exceeds 1 MiB safety limit");
        }
        let redacted = redact_text(replacement);
        if redacted != replacement {
            bail!("replacement content contains secret-like material");
        }
        validate_replacement(&path, replacement)?;
        let after_hash = hash_bytes(replacement.as_bytes());
        let before_text = redact_text(&String::from_utf8_lossy(
            current.as_deref().unwrap_or_default(),
        ));
        let diff = text_diff(&before_text, replacement, &path);
        let now = Utc::now();
        Ok(ChangeSet {
            change_set_id: new_id("change"),
            actor: request.actor.clone(),
            scope: request.scope.clone(),
            provider_id: request.target.provider_id.clone(),
            reason: request.reason.clone(),
            evidence_ids: request.evidence_ids.clone(),
            status: ChangeStatus::Proposed,
            created_at: now,
            updated_at: now,
            operations: vec![amcp_domain::ChangeOperation {
                operation_id: new_id("op"),
                target: request.target.clone(),
                operation: if before_hash.is_none() {
                    ChangeOperationKind::CreateText
                } else {
                    ChangeOperationKind::ReplaceText
                },
                expected_source_hash: request.expected_source_hash.clone().or(before_hash.clone()),
                before_hash,
                after_hash: Some(after_hash),
                replacement_content: Some(replacement.to_owned()),
                diff,
            }],
        })
    }

    pub fn read_artifact(
        &self,
        target: &ArtifactRef,
        host: &HostIdentity,
    ) -> Result<ArtifactRecord> {
        if target.provider_id != CODEX_PROVIDER_ID || target.host_id != host.host_id {
            bail!("artifact target is outside this Codex Agent scope");
        }
        let (path, kind) = match self.authorized_path(&target.source_reference) {
            Ok(path) => {
                let kind = match path.file_name().and_then(|name| name.to_str()) {
                    Some("AGENTS.md") | Some("AGENTS.override.md") => ArtifactKind::Instruction,
                    Some(name) if is_config_document_name(name) => ArtifactKind::Configuration,
                    _ => bail!("artifact is not a supported safe Codex document"),
                };
                (path, kind)
            }
            Err(_) => (
                self.authorized_session_read_path(&target.source_reference)?,
                ArtifactKind::Session,
            ),
        };
        let metadata = fs::metadata(&path)?;
        if metadata.len() > 1_000_000 {
            bail!("artifact exceeds the 1 MiB live-read safety limit");
        }
        Ok(self.file_artifact(&path, kind, host, &new_id("read"), true)?)
    }

    pub fn apply_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt> {
        if change_set.operations.is_empty() {
            bail!("change set contains no operations");
        }
        for operation in &change_set.operations {
            let path = self.authorized_path(&operation.target.source_reference)?;
            self.ensure_project_is_writable(&path)?;
            let replacement = operation
                .replacement_content
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("replacement content is required"))?;
            if redact_text(replacement) != replacement {
                bail!("replacement content contains secret-like material");
            }
            validate_replacement(&path, replacement)?;
        }
        let mut backups = Vec::new();
        let mut before_hashes = Vec::new();
        let mut after_hashes = Vec::new();
        for (index, operation) in change_set.operations.iter().enumerate() {
            if matches!(operation.operation, ChangeOperationKind::DeleteFile) {
                bail!("Codex adapter does not allow file deletion in this release");
            }
            let path = self.authorized_path(&operation.target.source_reference)?;
            let current = read_optional(&path)?;
            let current_hash = current.as_deref().map(hash_bytes);
            if operation.expected_source_hash != current_hash {
                return Ok(ChangeReceipt {
                    change_set_id: change_set.change_set_id.clone(),
                    status: ChangeStatus::Conflict,
                    applied_at: Utc::now(),
                    backup_references: Vec::new(),
                    before_hashes: current_hash.into_iter().collect(),
                    after_hashes: Vec::new(),
                    message: format!(
                        "source changed before apply for {}",
                        operation.target.source_reference
                    ),
                });
            }
            let replacement = operation
                .replacement_content
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("replacement content is required"))?;
            fs::create_dir_all(backup_dir)?;
            if path.is_file() {
                let backup = backup_path(backup_dir, &change_set.change_set_id, index, &path);
                fs::copy(&path, &backup)?;
                backups.push(backup.to_string_lossy().into_owned());
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let temp = path.with_file_name(format!(
                ".amcp-{}-{}-{}.tmp",
                change_set.change_set_id,
                index,
                new_id("write")
            ));
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            file.write_all(replacement.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &path)?;
            let after = fs::read(&path)?;
            let after_hash = hash_bytes(&after);
            if operation.after_hash.as_deref() != Some(after_hash.as_str()) {
                bail!("post-write hash verification failed for {}", path.display());
            }
            before_hashes.extend(current_hash);
            after_hashes.push(after_hash);
        }
        Ok(ChangeReceipt {
            change_set_id: change_set.change_set_id.clone(),
            status: ChangeStatus::Applied,
            applied_at: Utc::now(),
            backup_references: backups,
            before_hashes,
            after_hashes,
            message: "change set applied and verified".to_owned(),
        })
    }

    pub fn rollback_change(
        &self,
        change_set: &ChangeSet,
        backup_dir: &Path,
    ) -> Result<ChangeReceipt> {
        if change_set.operations.is_empty() {
            bail!("change set contains no operations");
        }
        let mut before_hashes = Vec::new();
        let mut after_hashes = Vec::new();
        for (index, operation) in change_set.operations.iter().enumerate() {
            let path = self.authorized_path(&operation.target.source_reference)?;
            let current = read_optional(&path)?;
            let current_hash = current.as_deref().map(hash_bytes);
            if operation.after_hash != current_hash {
                return Ok(ChangeReceipt {
                    change_set_id: change_set.change_set_id.clone(),
                    status: ChangeStatus::Conflict,
                    applied_at: Utc::now(),
                    backup_references: Vec::new(),
                    before_hashes: current_hash.into_iter().collect(),
                    after_hashes: Vec::new(),
                    message: format!("source changed before rollback for {}", path.display()),
                });
            }
            let backup = backup_path(backup_dir, &change_set.change_set_id, index, &path);
            if let Some(expected_before_hash) = &operation.before_hash {
                if !backup.is_file() {
                    bail!("backup is missing for {}", path.display());
                }
                let restored = fs::read(&backup)?;
                if hash_bytes(&restored) != *expected_before_hash {
                    bail!("backup hash verification failed for {}", path.display());
                }
                let temp = path.with_file_name(format!(
                    ".amcp-rollback-{}-{}-{}.tmp",
                    change_set.change_set_id,
                    index,
                    new_id("write")
                ));
                fs::write(&temp, restored)?;
                fs::rename(&temp, &path)?;
            } else if path.is_file() {
                fs::remove_file(&path)?;
            }
            let restored = read_optional(&path)?;
            let restored_hash = restored.as_deref().map(hash_bytes);
            if restored_hash != operation.before_hash {
                bail!(
                    "post-rollback hash verification failed for {}",
                    path.display()
                );
            }
            before_hashes.extend(current_hash);
            after_hashes.extend(restored_hash);
        }
        Ok(ChangeReceipt {
            change_set_id: change_set.change_set_id.clone(),
            status: ChangeStatus::RolledBack,
            applied_at: Utc::now(),
            backup_references: change_set
                .operations
                .iter()
                .enumerate()
                .filter_map(|(index, operation)| {
                    self.authorized_path(&operation.target.source_reference)
                        .ok()
                        .map(|path| {
                            backup_path(backup_dir, &change_set.change_set_id, index, &path)
                        })
                        .filter(|path| path.exists())
                        .map(|path| path.to_string_lossy().into_owned())
                })
                .collect(),
            before_hashes,
            after_hashes,
            message: "pre-change backups restored and verified".to_owned(),
        })
    }

    fn authorized_path(&self, source_reference: &str) -> Result<PathBuf> {
        let requested = PathBuf::from(source_reference);
        if !requested.is_absolute() {
            bail!("change target must be an absolute path");
        }
        let roots = self
            .discovery_roots()
            .into_iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .collect::<Vec<_>>();
        let canonical_parent = requested
            .parent()
            .map(fs::canonicalize)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("change target has no parent"))?;
        let canonical = canonical_parent.join(
            requested
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("change target has no filename"))?,
        );
        if !roots.iter().any(|root| canonical.starts_with(root)) {
            bail!("change target is outside configured provider roots");
        }
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        if requested
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| matches!(name, "auth.json" | "history.jsonl" | "session_index.jsonl"))
            .unwrap_or(true)
        {
            bail!("change target is not writable by Codex policy");
        }
        let file_name = requested
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("change target has no valid filename"))?;
        let supported_document = matches!(file_name, "AGENTS.md" | "AGENTS.override.md")
            || file_name == "config.toml"
            || (file_name.ends_with(".config.toml")
                && canonical.parent() == Some(codex_home.as_path()));
        if !supported_document {
            bail!("change target is not a supported Codex text document");
        }
        if requested.exists() && fs::symlink_metadata(&requested)?.file_type().is_symlink() {
            bail!("symlink targets are not writable");
        }
        Ok(canonical)
    }

    /// Session source files are evidence-only: they can be read through the
    /// normal bounded redaction path, but are deliberately excluded from the
    /// write allowlist in `authorized_path`.
    fn authorized_session_read_path(&self, source_reference: &str) -> Result<PathBuf> {
        let requested = PathBuf::from(source_reference);
        if !requested.is_absolute() {
            bail!("session source must be an absolute path");
        }
        if requested.exists() && fs::symlink_metadata(&requested)?.file_type().is_symlink() {
            bail!("symlink session sources are not readable");
        }
        let canonical_parent = requested
            .parent()
            .map(fs::canonicalize)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("session source has no parent"))?;
        let canonical = canonical_parent.join(
            requested
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("session source has no filename"))?,
        );
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        let in_session_directory = canonical.starts_with(codex_home.join("sessions"))
            || canonical.starts_with(codex_home.join("archived_sessions"));
        if !in_session_directory
            || canonical
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("jsonl")
            || !canonical.is_file()
        {
            bail!("artifact is not a supported read-only Codex session source");
        }
        Ok(canonical)
    }

    fn discover_root(
        &self,
        root: &Path,
        host: &HostIdentity,
        collection_run_id: &str,
        artifacts: &mut Vec<ArtifactRecord>,
        projects: &mut Vec<ProjectRecord>,
        sessions: &mut Vec<SessionRecord>,
        session_items: &mut Vec<SessionItem>,
        memory_records: &mut Vec<MemoryRecord>,
        config_layers: &mut Vec<ConfigLayerRecord>,
        guidance_records: &mut Vec<GuidanceRecord>,
    ) -> io::Result<()> {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        self.discover_projects(&root, host, projects)?;
        let explicit_files = [
            ("config.toml", ArtifactKind::Configuration),
            ("projects.toml", ArtifactKind::Configuration),
            ("AGENTS.md", ArtifactKind::Instruction),
            ("AGENTS.override.md", ArtifactKind::Instruction),
            ("history.jsonl", ArtifactKind::Session),
            ("session_index.jsonl", ArtifactKind::Session),
        ];

        for (relative, kind) in explicit_files {
            let path = root.join(relative);
            if path.is_file() {
                let allow_content = !matches!(kind, ArtifactKind::Session);
                artifacts.push(self.file_artifact(
                    &path,
                    kind.clone(),
                    host,
                    collection_run_id,
                    allow_content,
                )?);
                if kind == ArtifactKind::Session && relative != "history.jsonl" {
                    self.discover_session_file(&path, host, sessions, session_items)?;
                }
                if kind == ArtifactKind::Configuration
                    && relative != "projects.toml"
                    && let Ok(layer) = self.config_layer(&path, host)
                {
                    config_layers.push(layer);
                }
                if kind == ArtifactKind::Instruction
                    && let Ok(guidance) = self.guidance_record(&path, host)
                {
                    guidance_records.push(guidance);
                }
            }
        }

        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        if root == codex_home {
            for entry in fs::read_dir(&root)? {
                let entry = entry?;
                let path = entry.path();
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                if !path.is_file()
                    || file_name == "config.toml"
                    || !file_name.ends_with(".config.toml")
                {
                    continue;
                }
                artifacts.push(self.file_artifact(
                    &path,
                    ArtifactKind::Configuration,
                    host,
                    collection_run_id,
                    true,
                )?);
                if let Ok(layer) = self.config_layer(&path, host) {
                    config_layers.push(layer);
                }
            }
        }

        let history = root.join("history.jsonl");
        let session_index = root.join("session_index.jsonl");
        if !session_index.is_file() && history.is_file() {
            self.discover_session_file(&history, host, sessions, session_items)?;
        }

        for directory in ["sessions", "archived_sessions", "memories"] {
            let path = root.join(directory);
            if path.is_dir() {
                self.discover_directory_metadata(
                    &path,
                    host,
                    collection_run_id,
                    artifacts,
                    sessions,
                    session_items,
                    memory_records,
                )?;
            }
        }

        for entry in WalkDir::new(&root)
            .max_depth(4)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| should_descend(entry.path(), &root))
        {
            let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
            if !entry.file_type().is_file() || entry.path() == root {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            if entry.path().parent() == Some(root.as_path())
                && [
                    "config.toml",
                    "projects.toml",
                    "AGENTS.md",
                    "AGENTS.override.md",
                    "history.jsonl",
                    "session_index.jsonl",
                ]
                .contains(&name.as_ref())
            {
                continue;
            }
            if name == "config.toml" || name == "AGENTS.md" || name == "AGENTS.override.md" {
                artifacts.push(self.file_artifact(
                    entry.path(),
                    if name == "AGENTS.md" || name == "AGENTS.override.md" {
                        ArtifactKind::Instruction
                    } else {
                        ArtifactKind::Configuration
                    },
                    host,
                    collection_run_id,
                    true,
                )?);
                if name == "config.toml" {
                    if let Ok(layer) = self.config_layer(entry.path(), host) {
                        config_layers.push(layer);
                    }
                } else if let Ok(guidance) = self.guidance_record(entry.path(), host) {
                    guidance_records.push(guidance);
                }
            } else if let Some(kind) = codex_auxiliary_artifact_kind(entry.path(), &root) {
                artifacts.push(self.file_artifact(
                    entry.path(),
                    kind.clone(),
                    host,
                    collection_run_id,
                    true,
                )?);
                if kind == ArtifactKind::Instruction
                    && let Ok(guidance) = self.guidance_record(entry.path(), host)
                {
                    guidance_records.push(guidance);
                }
            }
        }

        Ok(())
    }

    fn discover_directory_metadata(
        &self,
        directory: &Path,
        host: &HostIdentity,
        collection_run_id: &str,
        artifacts: &mut Vec<ArtifactRecord>,
        sessions: &mut Vec<SessionRecord>,
        session_items: &mut Vec<SessionItem>,
        memory_records: &mut Vec<MemoryRecord>,
    ) -> io::Result<()> {
        for entry in WalkDir::new(directory).max_depth(2).follow_links(false) {
            let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            let is_memory =
                directory.file_name().and_then(|name| name.to_str()) == Some("memories");
            artifacts.push(self.file_artifact(
                entry.path(),
                if is_memory {
                    ArtifactKind::Memory
                } else {
                    ArtifactKind::Session
                },
                host,
                collection_run_id,
                is_memory,
            )?);
            if is_memory {
                if let Ok(record) = self.memory_record(entry.path(), host) {
                    memory_records.push(record);
                }
            } else {
                self.discover_session_file(entry.path(), host, sessions, session_items)?;
            }
        }
        Ok(())
    }

    fn discover_projects(
        &self,
        root: &Path,
        host: &HostIdentity,
        projects: &mut Vec<ProjectRecord>,
    ) -> io::Result<()> {
        let projects_file = root.join("projects.toml");
        if projects_file.is_file() {
            let content = fs::read_to_string(&projects_file)?;
            if let Ok(document) = content.parse::<toml::Value>()
                && let Some(entries) = document.get("projects").and_then(toml::Value::as_table)
            {
                for (path, metadata) in entries {
                    let root_path = PathBuf::from(path);
                    let project_id = canonical_project_path(&root_path);
                    let trust_level = metadata
                        .get("trust_level")
                        .and_then(toml::Value::as_str)
                        .map(str::to_owned);
                    projects.push(ProjectRecord {
                        project_id,
                        host_id: host.host_id.clone(),
                        provider_id: CODEX_PROVIDER_ID.to_owned(),
                        root_path: path.clone(),
                        display_name: root_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or(path)
                            .to_owned(),
                        trust_level,
                        discovered_from: projects_file.to_string_lossy().into_owned(),
                        observed_at: Utc::now(),
                    });
                }
            }
        }

        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        if root != codex_home {
            let project_id = canonical_project_path(root);
            if !projects
                .iter()
                .any(|project| project.project_id == project_id)
            {
                projects.push(ProjectRecord {
                    project_id,
                    host_id: host.host_id.clone(),
                    provider_id: CODEX_PROVIDER_ID.to_owned(),
                    root_path: root.to_string_lossy().into_owned(),
                    display_name: root
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("project")
                        .to_owned(),
                    trust_level: None,
                    discovered_from: "amcp-scan-root".to_owned(),
                    observed_at: Utc::now(),
                });
            }
        }
        Ok(())
    }

    /// Session metadata is provider-owned inventory, so it can establish a
    /// project record without reading any project file. When a Git root is
    /// present, use it; otherwise retain the validated session cwd itself.
    fn discover_projects_from_session_metadata(
        &self,
        host: &HostIdentity,
        projects: &mut Vec<ProjectRecord>,
        sessions: &mut [SessionRecord],
    ) {
        for session in sessions {
            let Some(cwd) = session.cwd.as_deref() else {
                continue;
            };
            let Some(root) = project_root_from_session_cwd(Path::new(cwd)) else {
                continue;
            };
            let project_id = root.to_string_lossy().into_owned();
            if !projects
                .iter()
                .any(|project| project.project_id == project_id)
            {
                projects.push(ProjectRecord {
                    project_id: project_id.clone(),
                    host_id: host.host_id.clone(),
                    provider_id: CODEX_PROVIDER_ID.to_owned(),
                    root_path: project_id.clone(),
                    display_name: root
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("project")
                        .to_owned(),
                    trust_level: self.project_trust_level(&root),
                    discovered_from: "codex-session-cwd".to_owned(),
                    observed_at: Utc::now(),
                });
            }
            session.project_id = Some(project_id);
        }
    }

    fn discover_session_file(
        &self,
        path: &Path,
        host: &HostIdentity,
        sessions: &mut Vec<SessionRecord>,
        session_items: &mut Vec<SessionItem>,
    ) -> io::Result<()> {
        let bytes = fs::read(path)?;
        let source_hash = hash_bytes(&bytes);
        let source_reference = path.to_string_lossy().into_owned();
        if path.file_name().and_then(|name| name.to_str()) == Some("session_index.jsonl") {
            for line in String::from_utf8_lossy(&bytes).lines() {
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                let Some(session_id) = entry
                    .get("id")
                    .or_else(|| entry.get("session_id"))
                    .and_then(|value| value.as_str())
                else {
                    continue;
                };
                let session_source = entry
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(|value| self.codex_home.join(value))
                    .unwrap_or_else(|| path.to_path_buf());
                let session_bytes = fs::read(&session_source).unwrap_or_default();
                sessions.push(SessionRecord {
                    session_id: session_id.to_owned(),
                    host_id: host.host_id.clone(),
                    provider_id: CODEX_PROVIDER_ID.to_owned(),
                    project_id: None,
                    title: None,
                    cwd: None,
                    model: None,
                    branch: None,
                    started_at: None,
                    ended_at: None,
                    archived: session_source
                        .to_string_lossy()
                        .contains("archived_sessions"),
                    source_reference: session_source.to_string_lossy().into_owned(),
                    source_hash: if session_bytes.is_empty() {
                        source_hash.clone()
                    } else {
                        hash_bytes(&session_bytes)
                    },
                    metadata_json: serde_json::to_string(&entry)
                        .unwrap_or_else(|_| "{}".to_owned()),
                    observed_at: Utc::now(),
                });
            }
            return Ok(());
        }

        let mut metadata = serde_json::Value::Object(serde_json::Map::new());
        for line in String::from_utf8_lossy(&bytes).lines().take(8) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
                && (value.get("session_id").is_some() || value.get("thread_id").is_some())
            {
                metadata = value;
                break;
            }
        }
        let session_id = metadata
            .get("session_id")
            .or_else(|| metadata.get("thread_id"))
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .or_else(|| {
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| new_id("session"));
        let cwd = metadata
            .get("cwd")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        sessions.push(SessionRecord {
            session_id: session_id.clone(),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            project_id: cwd
                .as_deref()
                .map(PathBuf::from)
                .and_then(|path| self.project_id_for(&path)),
            title: metadata
                .get("title")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            cwd,
            model: metadata
                .get("model")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            branch: metadata
                .get("branch")
                .and_then(|value| value.as_str())
                .map(str::to_owned),
            started_at: metadata.get("started_at").and_then(parse_datetime),
            ended_at: metadata.get("ended_at").and_then(parse_datetime),
            archived: source_reference.contains("archived_sessions"),
            source_reference: source_reference.clone(),
            source_hash,
            metadata_json: serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_owned()),
            observed_at: Utc::now(),
        });
        for (sequence, line) in String::from_utf8_lossy(&bytes)
            .lines()
            .enumerate()
            .take(1_000)
        {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let item_kind = value
                .get("type")
                .or_else(|| value.get("kind"))
                .or_else(|| value.get("event"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("event")
                .to_owned();
            let role = value
                .get("role")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            session_items.push(SessionItem {
                session_id: session_id.clone(),
                host_id: host.host_id.clone(),
                provider_id: CODEX_PROVIDER_ID.to_owned(),
                sequence: sequence as i64,
                role,
                item_kind,
                content: None,
                source_reference: source_reference.clone(),
                observed_at: Utc::now(),
            });
        }
        Ok(())
    }

    fn memory_record(&self, path: &Path, host: &HostIdentity) -> io::Result<MemoryRecord> {
        let bytes = fs::read(path)?;
        let content = redact_text(
            &String::from_utf8_lossy(&bytes)
                .chars()
                .take(12_000)
                .collect::<String>(),
        );
        let source_reference = path.to_string_lossy().into_owned();
        Ok(MemoryRecord {
            memory_record_id: format!("memory_{}", hash_bytes(source_reference.as_bytes())),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            project_id: self.project_id_for(path),
            title: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("memory")
                .to_owned(),
            content,
            source_reference,
            source_hash: hash_bytes(&bytes),
            lifecycle: LifecycleState::Active,
            confidence: None,
            observed_at: Utc::now(),
        })
    }

    fn file_artifact(
        &self,
        path: &Path,
        kind: ArtifactKind,
        host: &HostIdentity,
        collection_run_id: &str,
        allow_content: bool,
    ) -> io::Result<ArtifactRecord> {
        let metadata = fs::metadata(path)?;
        let source_reference = path.to_string_lossy().into_owned();
        let native_id = source_reference.clone();
        let bytes = fs::read(path)?;
        let source_hash = hash_bytes(&bytes);
        let observed_at = Utc::now();
        let observation_id = new_id("obs");
        let evidence_id = new_id("evidence");
        let content = if allow_content {
            redact_text(
                &String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(4000)
                    .collect::<String>(),
            )
        } else {
            format!("metadata-only file; size={} bytes", metadata.len())
        };
        let sensitivity = if allow_content {
            classify(&content)
        } else {
            SensitivityClass::Sensitive
        };
        let observation = SourceObservation {
            observation_id: observation_id.clone(),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            native_id,
            source_reference: source_reference.clone(),
            source_hash: source_hash.clone(),
            observed_at,
            parser_version: ADAPTER_VERSION.to_owned(),
            schema_fingerprint: format!("file:{}", extension(path)),
            redaction_policy_version: REDACTION_POLICY_VERSION.to_owned(),
            collection_run_id: collection_run_id.to_owned(),
            state: ObservationState::Present,
        };
        let evidence = Some(EvidenceSnapshot {
            evidence_id,
            observation_id: observation_id.clone(),
            excerpt: content.clone(),
            source_hash,
            observed_at,
            sensitivity: sensitivity.clone(),
            retention_until: None,
        });

        Ok(ArtifactRecord {
            artifact_id: new_id("artifact"),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            project_id: self.project_id_for(path),
            native_id: source_reference.clone(),
            kind,
            title: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            source_reference,
            content,
            sensitivity,
            lifecycle: LifecycleState::Active,
            observation,
            evidence,
        })
    }

    fn project_id_for(&self, path: &Path) -> Option<String> {
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        self.discovery_roots()
            .into_iter()
            .filter(|root| root != &codex_home)
            .filter_map(|root| fs::canonicalize(root).ok())
            .find(|root| path.starts_with(root))
            .map(|root| root.to_string_lossy().into_owned())
    }

    fn ensure_project_is_writable(&self, path: &Path) -> Result<()> {
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        if path.starts_with(&codex_home) {
            return Ok(());
        }
        let project_root = self
            .discovery_roots()
            .into_iter()
            .filter(|root| root != &codex_home)
            .find(|root| path.starts_with(root))
            .ok_or_else(|| anyhow::anyhow!("change target is outside a trusted project root"))?;
        let trust_level = self.project_trust_level(&project_root);
        if trust_level
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("trusted"))
        {
            return Ok(());
        }
        bail!(
            "project is not trusted for mutation: {} ({})",
            project_root.display(),
            trust_level.unwrap_or_else(|| "unknown".to_owned())
        );
    }

    fn project_trust_level(&self, project_root: &Path) -> Option<String> {
        let content = fs::read_to_string(self.codex_home.join("projects.toml")).ok()?;
        let document = content.parse::<toml::Value>().ok()?;
        let entries = document.get("projects")?.as_table()?;
        entries.iter().find_map(|(path, metadata)| {
            let configured_root = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
            (configured_root == project_root)
                .then(|| metadata.get("trust_level")?.as_str().map(str::to_owned))
                .flatten()
        })
    }

    fn discovery_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.codex_home.clone()];
        roots.extend(self.scan_roots.iter().cloned());
        let projects_file = self.codex_home.join("projects.toml");
        if let Ok(content) = fs::read_to_string(projects_file)
            && let Ok(document) = content.parse::<toml::Value>()
            && let Some(entries) = document.get("projects").and_then(toml::Value::as_table)
        {
            roots.extend(
                entries
                    .keys()
                    .map(PathBuf::from)
                    .filter(|path| path.is_dir()),
            );
        }
        let mut unique = Vec::new();
        for root in roots {
            let canonical = fs::canonicalize(&root).unwrap_or(root);
            if !unique.iter().any(|existing| existing == &canonical) {
                unique.push(canonical);
            }
        }
        unique.sort_by_key(|root| Reverse(root.components().count()));
        unique
    }

    pub fn discovery_cursor(&self) -> String {
        let mut entries = Vec::new();
        for root in self.discovery_roots() {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(&root)
                .max_depth(4)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| should_descend(entry.path(), &root))
                .flatten()
            {
                if !entry.file_type().is_file() || !is_cursor_file(entry.path(), &root) {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|value| value.as_nanos().to_string())
                    .unwrap_or_default();
                entries.push(format!(
                    "{}:{}:{}",
                    entry.path().display(),
                    metadata.len(),
                    modified
                ));
            }
            for directory in ["sessions", "archived_sessions", "memories"] {
                let path = root.join(directory);
                if !path.is_dir() {
                    continue;
                }
                for entry in WalkDir::new(path)
                    .max_depth(2)
                    .follow_links(false)
                    .into_iter()
                    .flatten()
                {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    let Ok(metadata) = entry.metadata() else {
                        continue;
                    };
                    let modified = metadata
                        .modified()
                        .ok()
                        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|value| value.as_nanos().to_string())
                        .unwrap_or_default();
                    entries.push(format!(
                        "{}:{}:{}",
                        entry.path().display(),
                        metadata.len(),
                        modified
                    ));
                }
            }
        }
        entries.sort();
        hash_bytes(entries.join("\n").as_bytes())
    }

    fn config_layer(&self, path: &Path, host: &HostIdentity) -> io::Result<ConfigLayerRecord> {
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml");
        let (scope, profile, precedence_rank, project_id) = if path
            == codex_home.join("config.toml")
        {
            ("user".to_owned(), None, 20, None)
        } else if path.parent() == Some(codex_home.as_path()) && file_name.ends_with(".config.toml")
        {
            (
                "profile".to_owned(),
                file_name.strip_suffix(".config.toml").map(str::to_owned),
                30,
                None,
            )
        } else if let Some(project_id) = self.project_id_for(&path) {
            let project_root = PathBuf::from(&project_id);
            let relative = path.strip_prefix(&project_root).unwrap_or(&path);
            let is_project =
                relative == Path::new("config.toml") || relative == Path::new(".codex/config.toml");
            (
                if is_project { "project" } else { "directory" }.to_owned(),
                None,
                40 + if is_project {
                    0
                } else {
                    relative.components().count() as i32
                },
                Some(project_id),
            )
        } else {
            ("system".to_owned(), None, 10, None)
        };
        let bytes = fs::read(&path)?;
        Ok(ConfigLayerRecord {
            config_layer_id: format!("config_{}", hash_bytes(path.to_string_lossy().as_bytes())),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            project_id,
            source_reference: path.to_string_lossy().into_owned(),
            scope,
            profile,
            precedence_rank,
            source_hash: hash_bytes(&bytes),
            observed_at: Utc::now(),
        })
    }

    fn guidance_record(&self, path: &Path, host: &HostIdentity) -> io::Result<GuidanceRecord> {
        let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let codex_home =
            fs::canonicalize(&self.codex_home).unwrap_or_else(|_| self.codex_home.clone());
        let project_id = self.project_id_for(&path);
        let relative_scope = project_id
            .as_deref()
            .and_then(|root| path.strip_prefix(root).ok())
            .or_else(|| path.strip_prefix(&codex_home).ok())
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let depth = relative_scope.matches(std::path::MAIN_SEPARATOR).count() as i32;
        let base_rank = if project_id.is_some() { 40 } else { 20 } + depth;
        let kind = guidance_kind(&path);
        let bytes = fs::read(&path)?;
        Ok(GuidanceRecord {
            guidance_id: format!("guidance_{}", hash_bytes(path.to_string_lossy().as_bytes())),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.to_owned(),
            project_id,
            source_reference: path.to_string_lossy().into_owned(),
            relative_scope,
            kind: kind.to_owned(),
            precedence_rank: base_rank + i32::from(kind == "override"),
            source_hash: hash_bytes(&bytes),
            observed_at: Utc::now(),
        })
    }

    fn guidance_edges(
        &self,
        records: &[GuidanceRecord],
        projects: &[ProjectRecord],
    ) -> Vec<GuidanceEdge> {
        let mut edges = Vec::new();
        let mut scopes = vec![None];
        scopes.extend(
            projects
                .iter()
                .map(|project| Some(project.project_id.clone())),
        );
        for project_id in scopes {
            let mut applicable = records
                .iter()
                .filter(|record| record.project_id.is_none() || record.project_id == project_id)
                .collect::<Vec<_>>();
            applicable.sort_by(|left, right| {
                left.precedence_rank
                    .cmp(&right.precedence_rank)
                    .then(left.source_reference.cmp(&right.source_reference))
            });
            for pair in applicable.windows(2) {
                edges.push(GuidanceEdge {
                    host_id: records[0].host_id.clone(),
                    provider_id: records[0].provider_id.clone(),
                    lower_guidance_id: pair[0].guidance_id.clone(),
                    higher_guidance_id: pair[1].guidance_id.clone(),
                    relation: if pair[1].kind == "override" {
                        "overrides"
                    } else {
                        "more_specific"
                    }
                    .to_owned(),
                });
            }
        }
        edges.sort_by(|left, right| {
            left.lower_guidance_id
                .cmp(&right.lower_guidance_id)
                .then(left.higher_guidance_id.cmp(&right.higher_guidance_id))
        });
        edges.dedup_by(|left, right| {
            left.lower_guidance_id == right.lower_guidance_id
                && left.higher_guidance_id == right.higher_guidance_id
        });
        edges
    }
}

impl ProviderAdapter for CodexAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        self.provider()
    }

    fn runtime_descriptor(&self) -> Option<RuntimeAdapterDescriptor> {
        Some(RuntimeAdapterDescriptor {
            transport: "codex-app-server".into(),
            operations: vec![
                "list".into(),
                "read".into(),
                "archive".into(),
                "unarchive".into(),
            ],
        })
    }

    fn collection_cursor(&self) -> Option<String> {
        Some(self.discovery_cursor())
    }

    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch> {
        Self::discover(self, host).map_err(Into::into)
    }

    fn map_runtime_thread(
        &self,
        host: &HostIdentity,
        thread: &serde_json::Value,
        sequence: &mut i64,
    ) -> Result<Option<RuntimeEvent>> {
        codex_runtime_event_from_thread(host, thread, sequence)
    }

    fn map_runtime_thread_record(
        &self,
        host: &HostIdentity,
        thread: &serde_json::Value,
    ) -> Result<Option<RuntimeThreadRecord>> {
        let mut sequence = 0;
        let Some(event) = codex_runtime_event_from_thread(host, thread, &mut sequence)? else {
            return Ok(None);
        };
        let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
        Ok(Some(RuntimeThreadRecord {
            thread_id: payload
                .get("thread_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.into(),
            title: payload
                .get("title")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            cwd: payload
                .get("cwd")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            model: payload
                .get("model")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            status: payload
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            archived: payload
                .get("archived")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            source_reference: format!(
                "codex://thread/{}",
                payload
                    .get("thread_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .replace('/', "%2F")
            ),
            observed_at: event.occurred_at,
        }))
    }

    fn runtime_list_request(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Option<RuntimeRequest>> {
        let mut params = serde_json::Map::new();
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), serde_json::Value::String(cursor.into()));
        }
        params.insert(
            "limit".into(),
            serde_json::Value::Number((limit.clamp(1, 256) as u64).into()),
        );
        Ok(Some(RuntimeRequest {
            method: "thread/list".into(),
            params: serde_json::Value::Object(params),
        }))
    }

    fn runtime_read_request(&self, thread_id: &str) -> Result<Option<RuntimeRequest>> {
        Ok(Some(RuntimeRequest {
            method: "thread/read".into(),
            params: serde_json::json!({ "threadId": thread_id }),
        }))
    }

    fn runtime_change_request(
        &self,
        thread_id: &str,
        archived: bool,
    ) -> Result<Option<RuntimeRequest>> {
        Ok(Some(RuntimeRequest {
            method: if archived {
                "thread/archive"
            } else {
                "thread/unarchive"
            }
            .into(),
            params: serde_json::json!({ "threadId": thread_id }),
        }))
    }

    fn read_artifact(&self, target: &ArtifactRef, host: &HostIdentity) -> Result<ArtifactRecord> {
        Self::read_artifact(self, target, host)
    }

    fn propose_change(&self, request: &ChangeRequest) -> Result<ChangeSet> {
        Self::propose_change(self, request)
    }

    fn apply_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt> {
        Self::apply_change(self, change_set, backup_dir)
    }

    fn rollback_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt> {
        Self::rollback_change(self, change_set, backup_dir)
    }
}

fn codex_runtime_event_from_thread(
    host: &HostIdentity,
    thread: &serde_json::Value,
    sequence: &mut i64,
) -> Result<Option<RuntimeEvent>> {
    let Some(native_id) = first_string(thread, &["id", "threadId", "thread_id"]) else {
        return Ok(None);
    };
    let mut payload = serde_json::Map::new();
    payload.insert("source".into(), serde_json::json!("codex.app-server"));
    payload.insert("metadata_only".into(), serde_json::json!(true));
    payload.insert("thread_id".into(), serde_json::json!(native_id));
    for (output_key, input_keys) in [
        ("title", &["title", "name"][..]),
        ("cwd", &["cwd", "workingDirectory", "working_directory"][..]),
        ("model", &["model", "modelProvider"][..]),
        ("status", &["status", "state"][..]),
        ("updated_at", &["updatedAt", "updated_at"][..]),
    ] {
        if let Some(value) = first_scalar(thread, input_keys) {
            payload.insert(output_key.into(), value);
        }
    }
    for key in ["archived", "isArchived"] {
        if let Some(value) = thread.get(key).filter(|value| value.is_boolean()) {
            payload.insert("archived".into(), value.clone());
            break;
        }
    }
    let payload_json = serde_json::to_string(&payload)?;
    let event_type = "session.updated";
    *sequence += 1;
    Ok(Some(RuntimeEvent {
        event_id: stable_runtime_event_id(
            &host.host_id,
            CODEX_PROVIDER_ID,
            event_type,
            &native_id,
            &payload_json,
        ),
        host_id: host.host_id.clone(),
        provider_id: CODEX_PROVIDER_ID.into(),
        event_type: event_type.into(),
        sequence: *sequence,
        payload_json,
        occurred_at: Utc::now(),
    }))
}

fn first_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::to_owned)
}

fn first_scalar(value: &serde_json::Value, keys: &[&str]) -> Option<serde_json::Value> {
    keys.iter()
        .find_map(|key| {
            value.get(*key).filter(|candidate| {
                candidate.is_string() || candidate.is_number() || candidate.is_boolean()
            })
        })
        .map(|candidate| match candidate {
            serde_json::Value::String(value) => {
                let redacted = redact_text(value);
                let bounded = redacted.chars().take(512).collect::<String>();
                serde_json::Value::String(bounded)
            }
            other => other.clone(),
        })
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or("none")
        .to_owned()
}

fn canonical_project_path(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn project_root_from_session_cwd(cwd: &Path) -> Option<PathBuf> {
    let cwd = fs::canonicalize(cwd).ok()?;
    let cwd = if cwd.is_file() {
        cwd.parent()?.to_path_buf()
    } else if cwd.is_dir() {
        cwd
    } else {
        return None;
    };
    for ancestor in cwd.ancestors().take(32) {
        // A Git worktree can expose `.git` as either a directory or a file.
        // Metadata inspection is sufficient; AMCP does not execute Git or
        // read project contents during this inventory step.
        if fs::symlink_metadata(ancestor.join(".git")).is_ok() {
            return Some(ancestor.to_path_buf());
        }
    }
    Some(cwd)
}

fn parse_datetime(value: &serde_json::Value) -> Option<chrono::DateTime<Utc>> {
    value
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn session_source_priority(source: &str) -> u8 {
    if source.contains("/sessions/") || source.contains("/archived_sessions/") {
        0
    } else if source.ends_with("session_index.jsonl") {
        1
    } else {
        2
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CodexInstallationMetadata {
    codex_home_detected: bool,
    sqlite_home_configured: bool,
    sqlite_home_detected: bool,
    executable_detected: bool,
    version: Option<String>,
}

fn codex_installation_metadata(codex_home: &Path) -> CodexInstallationMetadata {
    let sqlite_home = env::var_os("CODEX_SQLITE_HOME").map(PathBuf::from);
    let configured_executable = env::var_os("AMCP_CODEX_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("codex"));
    let executable = resolve_executable(&configured_executable);
    let version = executable.as_deref().and_then(read_codex_version);
    CodexInstallationMetadata {
        codex_home_detected: codex_home.is_dir(),
        sqlite_home_configured: sqlite_home.is_some(),
        sqlite_home_detected: sqlite_home.is_some_and(|path| path.is_dir()),
        executable_detected: executable.is_some(),
        version,
    }
}

fn resolve_executable(configured: &Path) -> Option<PathBuf> {
    if configured.components().count() > 1 {
        return configured.is_file().then(|| configured.to_path_buf());
    }
    let command = configured.to_str()?;
    env::var_os("PATH")
        .and_then(|paths| {
            env::split_paths(&paths)
                .map(|directory| directory.join(command))
                .find(|candidate| candidate.is_file())
        })
        .or_else(|| configured.is_file().then(|| configured.to_path_buf()))
}

fn read_codex_version(executable: &Path) -> Option<String> {
    let output = Command::new(executable).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_codex_version(&output.stdout)
}

fn parse_codex_version(output: &[u8]) -> Option<String> {
    String::from_utf8(output.to_vec())
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(256).collect())
}

fn backup_path(backup_dir: &Path, change_set_id: &str, index: usize, path: &Path) -> PathBuf {
    backup_dir.join(format!(
        "{}-{}-{}.bak",
        change_set_id,
        index,
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("source")
    ))
}

fn validate_replacement(path: &Path, replacement: &str) -> Result<()> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_config_document_name)
    {
        replacement
            .parse::<toml::Value>()
            .map_err(|error| anyhow::anyhow!("replacement is not valid TOML: {error}"))?;
    }
    Ok(())
}

fn is_config_document_name(name: &str) -> bool {
    name == "config.toml" || name.ends_with(".config.toml")
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn text_diff(before: &str, after: &str, path: &Path) -> String {
    if before == after {
        return format!("no textual change: {}", path.display());
    }
    format!(
        "--- {}\n+++ {}\n@@\n-{}\n+{}\n",
        path.display(),
        path.display(),
        before,
        after
    )
}

fn classify(content: &str) -> SensitivityClass {
    if content.contains("[REDACTED]") {
        SensitivityClass::Sensitive
    } else {
        SensitivityClass::Internal
    }
}

pub fn redact_text(input: &str) -> String {
    let key_value =
        Regex::new(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*[^\s\n]+")
            .expect("redaction regex is valid");
    let bearer = Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+").expect("redaction regex is valid");
    let value = key_value.replace_all(input, "$1=[REDACTED]");
    bearer.replace_all(&value, "Bearer [REDACTED]").into_owned()
}

fn should_descend(path: &Path, root: &Path) -> bool {
    if path == root {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            !matches!(
                name,
                "sessions"
                    | "archived_sessions"
                    | "memories"
                    | "logs"
                    | "shell_snapshots"
                    | "plugins"
                    | "node_modules"
                    | ".git"
            )
        })
        .unwrap_or(true)
}

fn codex_auxiliary_artifact_kind(path: &Path, root: &Path) -> Option<ArtifactKind> {
    let relative = path.strip_prefix(root).ok()?;
    let name = path.file_name()?.to_string_lossy();
    if matches!(name.as_ref(), "auth.json" | ".env" | ".env.local") {
        return None;
    }
    let components = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    let is_text = matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "md" | "toml"
                | "json"
                | "jsonc"
                | "yaml"
                | "yml"
                | "sh"
                | "bash"
                | "zsh"
                | "py"
                | "js"
                | "ts"
        )
    );
    let in_rules = components.contains(&"rules");
    let in_skills = components.contains(&"skills");
    let in_hooks = components.contains(&"hooks");
    let in_mcp = components.contains(&"mcp");
    if in_skills && components.contains(&".system") {
        return None;
    }
    let is_mcp_config = matches!(
        name.as_ref(),
        "mcp.json" | ".mcp.json" | "mcp.toml" | "mcp.yaml" | "mcp.yml" | "mcp_servers.json"
    );

    if (in_rules || (in_skills && name == "SKILL.md")) && is_text {
        Some(ArtifactKind::Instruction)
    } else if (in_hooks || in_mcp || is_mcp_config) && is_text {
        Some(ArtifactKind::Tooling)
    } else {
        None
    }
}

fn guidance_kind(path: &Path) -> &'static str {
    if path.file_name().and_then(|name| name.to_str()) == Some("AGENTS.override.md") {
        "override"
    } else if path.file_name().and_then(|name| name.to_str()) == Some("SKILL.md") {
        "skill"
    } else if path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .any(|component| component == "rules")
    {
        "rule"
    } else {
        "agents"
    }
}

fn is_cursor_file(path: &Path, root: &Path) -> bool {
    if path == root {
        return false;
    }
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "config.toml"
                | "projects.toml"
                | "AGENTS.md"
                | "AGENTS.override.md"
                | "history.jsonl"
                | "session_index.jsonl",
        )
    ) || codex_auxiliary_artifact_kind(path, root).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use amcp_domain::{ArtifactRef, ChangeOperationKind, ChangeRequest, Scope};

    #[test]
    fn redacts_secret_like_values() {
        let result = redact_text("api_key=abc123\nauthorization: Bearer token");
        assert!(!result.contains("abc123"));
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn provider_descriptor_is_codex() {
        let adapter = CodexAdapter::from_environment(Some(PathBuf::from("/tmp/codex")));
        let descriptor = adapter.provider();
        assert_eq!(descriptor.id, CODEX_PROVIDER_ID);
        assert_eq!(descriptor.schema_fingerprint, PROVIDER_SCHEMA_FINGERPRINT);
        assert_eq!(descriptor.support_level, ProviderSupportLevel::Full);
        assert_eq!(descriptor.health, ProviderHealth::Healthy);
        assert_eq!(descriptor.compatibility, ProviderCompatibility::Compatible);
        assert_eq!(descriptor.native_roots, vec!["/tmp/codex"]);
        assert!(descriptor.capabilities.contains(&"runtime".into()));
    }

    #[test]
    fn parses_a_bounded_codex_version_line() {
        assert_eq!(
            parse_codex_version(b"\n codex 1.2.3 \nextra output\n"),
            Some("codex 1.2.3".to_owned())
        );
        assert_eq!(parse_codex_version(b"\n\n"), None);
    }

    #[test]
    fn resolves_an_explicit_existing_codex_executable() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let executable = directory.path().join("codex");
        fs::write(&executable, "fixture executable").expect("fixture executable");
        assert_eq!(resolve_executable(&executable), Some(executable));
    }

    #[test]
    fn runtime_mapping_is_provider_neutral_and_redacted() {
        let adapter = CodexAdapter::from_environment(Some(PathBuf::from("/tmp/codex")));
        let host = HostIdentity {
            host_id: "host-runtime".into(),
            display_name: "Runtime host".into(),
            platform: "macos".into(),
            hostname: "runtime.local".into(),
        };
        let mut sequence = 0;
        let event = adapter
            .map_runtime_thread(
                &host,
                &serde_json::json!({
                    "id": "thread-1",
                    "title": "Safe title api_key=secret-value",
                    "cwd": "/work/project",
                    "model": "gpt-test",
                    "status": "idle",
                    "archived": false,
                    "delta": "must not be persisted"
                }),
                &mut sequence,
            )
            .expect("runtime event conversion")
            .expect("thread id");
        assert_eq!(event.provider_id, CODEX_PROVIDER_ID);
        assert_eq!(event.event_type, "session.updated");
        assert_eq!(event.sequence, 1);
        assert!(event.payload_json.contains("metadata_only"));
        assert!(!event.payload_json.contains("secret-value"));
        assert!(!event.payload_json.contains("must not be persisted"));
    }

    #[test]
    fn codex_owns_runtime_requests_while_agent_owns_transport() {
        let adapter = CodexAdapter::from_environment(Some(PathBuf::from("/tmp/codex")));
        let list = adapter
            .runtime_list_request(Some("cursor-1"), 999)
            .expect("list request")
            .expect("Codex runtime capability");
        assert_eq!(list.method, "thread/list");
        assert_eq!(list.params["cursor"], "cursor-1");
        assert_eq!(list.params["limit"], 256);

        let read = adapter
            .runtime_read_request("thread-1")
            .expect("read request")
            .expect("Codex runtime capability");
        assert_eq!(read.method, "thread/read");
        assert_eq!(read.params["threadId"], "thread-1");

        let archive = adapter
            .runtime_change_request("thread-1", true)
            .expect("archive request")
            .expect("Codex runtime capability");
        assert_eq!(archive.method, "thread/archive");
        let unarchive = adapter
            .runtime_change_request("thread-1", false)
            .expect("unarchive request")
            .expect("Codex runtime capability");
        assert_eq!(unarchive.method, "thread/unarchive");
    }

    #[test]
    fn fixture_discovery_collects_project_instructions_without_secrets() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/codex");
        let adapter = CodexAdapter::from_environment(Some(root));
        let batch = adapter
            .discover(HostIdentity {
                host_id: "host_fixture".into(),
                display_name: "Fixture".into(),
                platform: "macos".into(),
                hostname: "fixture.local".into(),
            })
            .expect("fixture should be readable");

        assert_eq!(batch.artifacts.len(), 9);
        assert_eq!(batch.config_layers.len(), 1);
        assert_eq!(batch.config_layers[0].scope, "user");
        assert_eq!(batch.guidance_records.len(), 3);
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|item| item.precedence_rank == 20)
        );
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|item| item.precedence_rank == 21 && item.kind == "override")
        );
        assert!(!batch.guidance_edges.is_empty());
        assert!(
            batch
                .projects
                .iter()
                .any(|project| project.root_path == "/Users/example/alpha")
        );
        assert!(batch.sessions.iter().any(|session| {
            session.session_id == "fixture-session-1"
                && session
                    .source_reference
                    .ends_with("sessions/fixture-session-1.jsonl")
        }));
        assert_eq!(batch.session_items.len(), 1);
        assert!(batch.session_items[0].content.is_none());
        assert!(
            batch
                .memory_records
                .iter()
                .any(|memory| memory.title == "fixture-memory.md"
                    && memory.content.contains("Memory fixture"))
        );
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact
                .source_reference
                .ends_with("projects/alpha/AGENTS.md")
        }));
        assert!(batch.artifacts.iter().all(|artifact| {
            !artifact
                .content
                .contains("fixture-secret-must-not-be-indexed")
        }));
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact.kind == ArtifactKind::Session
                && artifact.content.starts_with("metadata-only file")
        }));
    }

    #[test]
    fn codex_home_profile_is_discovered_as_a_redacted_profile_layer() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let codex_home = directory.path().join("codex-home");
        fs::create_dir_all(&codex_home).expect("Codex home");
        fs::write(
            codex_home.join("review.config.toml"),
            "model = \"gpt-test\"\napi_key = \"profile-secret\"\n",
        )
        .expect("profile configuration");

        let batch = CodexAdapter::from_environment(Some(codex_home.clone()))
            .discover(HostIdentity {
                host_id: "host-profile".into(),
                display_name: "Profile host".into(),
                platform: "macos".into(),
                hostname: "profile.local".into(),
            })
            .expect("profile discovery");

        let profile = batch
            .config_layers
            .iter()
            .find(|layer| layer.source_reference.ends_with("/review.config.toml"))
            .expect("profile layer");
        assert_eq!(profile.scope, "profile");
        assert_eq!(profile.profile.as_deref(), Some("review"));
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact.source_reference.ends_with("/review.config.toml")
                && artifact.kind == ArtifactKind::Configuration
                && !artifact.content.contains("profile-secret")
        }));
    }

    #[test]
    fn codex_home_profile_can_be_proposed_applied_and_rolled_back() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let profile = directory.path().join("review.config.toml");
        fs::write(&profile, "model = \"gpt-test\"\n").expect("profile configuration");
        let adapter = CodexAdapter::from_environment(Some(directory.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host-profile"),
            target: ArtifactRef {
                host_id: "host-profile".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: profile.to_string_lossy().into_owned(),
                source_reference: profile.to_string_lossy().into_owned(),
            },
            expected_source_hash: Some(hash_bytes(&fs::read(&profile).expect("profile bytes"))),
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("model = \"gpt-updated\"\n".into()),
            reason: "update profile fixture".into(),
            evidence_ids: Vec::new(),
        };
        let change_set = adapter.propose_change(&request).expect("profile proposal");
        let receipt = adapter
            .apply_change(&change_set, &directory.path().join("backups"))
            .expect("profile apply");
        assert_eq!(receipt.status, ChangeStatus::Applied);
        assert_eq!(
            fs::read_to_string(&profile).expect("updated profile"),
            "model = \"gpt-updated\"\n"
        );
        let rollback = adapter
            .rollback_change(&change_set, &directory.path().join("backups"))
            .expect("profile rollback");
        assert_eq!(rollback.status, ChangeStatus::RolledBack);
        assert_eq!(
            fs::read_to_string(&profile).expect("restored profile"),
            "model = \"gpt-test\"\n"
        );
    }

    #[test]
    fn profile_outside_codex_home_is_not_a_mutation_target() {
        let codex_home = tempfile::tempdir().expect("Codex home");
        let project = tempfile::tempdir().expect("project");
        let profile = project.path().join("review.config.toml");
        fs::write(&profile, "model = \"gpt-test\"\n").expect("project profile");
        fs::write(
            codex_home.path().join("projects.toml"),
            format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                project.path().display()
            ),
        )
        .expect("project registry");
        let adapter = CodexAdapter::from_environment(Some(codex_home.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host-project"),
            target: ArtifactRef {
                host_id: "host-project".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: profile.to_string_lossy().into_owned(),
                source_reference: profile.to_string_lossy().into_owned(),
            },
            expected_source_hash: None,
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("model = \"gpt-updated\"\n".into()),
            reason: "reject non-root profile".into(),
            evidence_ids: Vec::new(),
        };
        let error = adapter
            .propose_change(&request)
            .expect_err("only root-level Codex profiles are writable");
        assert!(
            error
                .to_string()
                .contains("not a supported Codex text document")
        );
    }

    #[test]
    fn recognized_rules_skills_hooks_and_mcp_configuration_are_discovered_without_execution() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let codex_home = directory.path().join("codex-home");
        fs::create_dir_all(codex_home.join("rules")).expect("rules directory");
        fs::create_dir_all(codex_home.join("skills/review")).expect("skills directory");
        fs::create_dir_all(codex_home.join("hooks")).expect("hooks directory");
        fs::create_dir_all(codex_home.join("mcp")).expect("MCP directory");
        fs::write(
            codex_home.join("rules/security.md"),
            "Never expose credentials.\n",
        )
        .expect("rule");
        fs::write(
            codex_home.join("skills/review/SKILL.md"),
            "Review the diff first.\n",
        )
        .expect("skill");
        fs::write(
            codex_home.join("hooks/pre-commit.sh"),
            "token=hook-secret\necho never-runs\n",
        )
        .expect("hook");
        fs::write(
            codex_home.join("mcp/servers.toml"),
            "[servers.local]\ncommand = \"tool\"\n",
        )
        .expect("MCP configuration");

        let batch = CodexAdapter::from_environment(Some(codex_home))
            .discover(HostIdentity {
                host_id: "host-auxiliary".into(),
                display_name: "Auxiliary host".into(),
                platform: "macos".into(),
                hostname: "auxiliary.local".into(),
            })
            .expect("auxiliary discovery");

        assert!(batch.artifacts.iter().any(|artifact| {
            artifact.source_reference.ends_with("/rules/security.md")
                && artifact.kind == ArtifactKind::Instruction
        }));
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact
                .source_reference
                .ends_with("/skills/review/SKILL.md")
                && artifact.kind == ArtifactKind::Instruction
        }));
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact.source_reference.ends_with("/hooks/pre-commit.sh")
                && artifact.kind == ArtifactKind::Tooling
                && !artifact.content.contains("hook-secret")
        }));
        assert!(batch.artifacts.iter().any(|artifact| {
            artifact.source_reference.ends_with("/mcp/servers.toml")
                && artifact.kind == ArtifactKind::Tooling
        }));
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|guidance| guidance.kind == "rule")
        );
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|guidance| guidance.kind == "skill")
        );
    }

    #[test]
    fn session_source_can_be_read_as_redacted_evidence_but_not_mutated() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let codex_home = directory.path().join("codex-home");
        let session_source = codex_home.join("sessions/session-evidence.jsonl");
        fs::create_dir_all(session_source.parent().expect("session parent"))
            .expect("session directory");
        fs::write(
            &session_source,
            "{\"session_id\":\"session-evidence\",\"message\":\"token=session-secret\"}\n",
        )
        .expect("session source");
        let adapter = CodexAdapter::from_environment(Some(codex_home));
        let host = HostIdentity {
            host_id: "host-session-evidence".into(),
            display_name: "Session evidence host".into(),
            platform: "macos".into(),
            hostname: "session-evidence.local".into(),
        };
        let target = ArtifactRef {
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.into(),
            native_id: session_source.display().to_string(),
            source_reference: session_source.display().to_string(),
        };

        let artifact = adapter
            .read_artifact(&target, &host)
            .expect("read-only session evidence");
        assert_eq!(artifact.kind, ArtifactKind::Session);
        assert!(artifact.content.contains("session-evidence"));
        assert!(!artifact.content.contains("session-secret"));
        assert!(
            adapter
                .authorized_path(&session_source.display().to_string())
                .is_err()
        );
    }

    #[test]
    fn session_cwd_discovers_and_assigns_a_git_project_without_reading_project_files() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let codex_home = directory.path().join("codex-home");
        let project_root = directory.path().join("workspace/project");
        let project_cwd = project_root.join("src");
        std::fs::create_dir_all(codex_home.join("sessions")).expect("session directory");
        std::fs::create_dir_all(project_root.join(".git")).expect("Git directory");
        std::fs::create_dir_all(&project_cwd).expect("project cwd");
        std::fs::write(
            codex_home.join("sessions/session-cwd.jsonl"),
            format!(
                "{{\"session_id\":\"session-from-cwd\",\"cwd\":\"{}\",\"title\":\"Session project discovery\"}}\n",
                project_cwd.display()
            ),
        )
        .expect("session metadata");

        let batch = CodexAdapter::from_environment(Some(codex_home))
            .discover(HostIdentity {
                host_id: "host-session-project".into(),
                display_name: "Session project host".into(),
                platform: "macos".into(),
                hostname: "session-project.local".into(),
            })
            .expect("session project discovery");
        let project_id = canonical_project_path(&project_root);
        assert!(batch.projects.iter().any(|project| {
            project.project_id == project_id
                && project.discovered_from == "codex-session-cwd"
                && project.root_path == project_id
        }));
        assert_eq!(
            batch
                .sessions
                .iter()
                .find(|session| session.session_id == "session-from-cwd")
                .and_then(|session| session.project_id.as_deref()),
            Some(project_id.as_str())
        );
    }

    #[test]
    fn configured_existing_project_is_scanned_for_project_layers() {
        let directory = tempfile::tempdir().expect("Codex home");
        let project = directory.path().join("workspace");
        fs::create_dir_all(project.join(".codex")).expect("project config directory");
        fs::write(
            directory.path().join("config.toml"),
            "model = \"gpt-test\"\n",
        )
        .expect("user config");
        fs::write(
            directory.path().join("projects.toml"),
            format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                project.display()
            ),
        )
        .expect("projects registry");
        fs::write(
            project.join(".codex/config.toml"),
            "approval_policy = \"on-request\"\n",
        )
        .expect("project config");
        fs::write(
            project.join("AGENTS.md"),
            "Use the project test workflow.\n",
        )
        .expect("project guidance");

        let adapter = CodexAdapter::from_environment(Some(directory.path().to_path_buf()));
        let before_cursor = adapter.discovery_cursor();
        let batch = adapter
            .discover(HostIdentity {
                host_id: "host_project_fixture".into(),
                display_name: "Fixture".into(),
                platform: "macos".into(),
                hostname: "fixture.local".into(),
            })
            .expect("project fixture should be readable");
        let project_id = fs::canonicalize(&project)
            .expect("canonical project")
            .to_string_lossy()
            .into_owned();
        assert!(
            batch
                .projects
                .iter()
                .any(|item| item.project_id == project_id)
        );
        assert!(batch.config_layers.iter().any(|item| {
            item.scope == "project" && item.project_id.as_deref() == Some(project_id.as_str())
        }));
        assert!(
            batch
                .guidance_records
                .iter()
                .any(|item| { item.project_id.as_deref() == Some(project_id.as_str()) })
        );
        fs::write(
            project.join(".codex/config.toml"),
            "approval_policy = \"never\"\n",
        )
        .expect("change project config");
        assert_ne!(before_cursor, adapter.discovery_cursor());
    }

    #[test]
    fn live_artifact_read_is_bounded_redacted_and_host_scoped() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("config.toml");
        std::fs::write(
            &config,
            "model = \"gpt-test\"\napi_key = \"fixture-secret\"\n",
        )
        .expect("write config");
        let adapter = CodexAdapter::from_environment(Some(temp.path().to_path_buf()));
        let host = HostIdentity {
            host_id: "host-live-read".into(),
            display_name: "Live read fixture".into(),
            platform: "macos".into(),
            hostname: "fixture.local".into(),
        };
        let target = ArtifactRef {
            host_id: host.host_id.clone(),
            provider_id: CODEX_PROVIDER_ID.into(),
            native_id: config.to_string_lossy().into_owned(),
            source_reference: config.to_string_lossy().into_owned(),
        };
        let artifact = adapter
            .read_artifact(&target, &host)
            .expect("read artifact");
        assert!(artifact.content.contains("[REDACTED]"));
        assert!(!artifact.content.contains("fixture-secret"));
        assert!(
            adapter
                .read_artifact(
                    &ArtifactRef {
                        host_id: "other-host".into(),
                        ..target
                    },
                    &host
                )
                .is_err()
        );
    }

    #[test]
    fn change_path_is_hashed_backed_up_and_verified() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("config.toml");
        std::fs::write(&config, "sandbox_mode = \"workspace-write\"\n").expect("write fixture");
        let adapter = CodexAdapter::from_environment(Some(temp.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host_fixture"),
            target: ArtifactRef {
                host_id: "host_fixture".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: config.to_string_lossy().into_owned(),
                source_reference: config.to_string_lossy().into_owned(),
            },
            expected_source_hash: Some(hash_bytes(&std::fs::read(&config).expect("read fixture"))),
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("sandbox_mode = \"read-only\"\n".into()),
            reason: "test safe mutation".into(),
            evidence_ids: Vec::new(),
        };
        let change_set = adapter.propose_change(&request).expect("proposal");
        let receipt = adapter
            .apply_change(&change_set, &temp.path().join("backups"))
            .expect("apply");
        assert_eq!(receipt.status, ChangeStatus::Applied);
        assert_eq!(
            std::fs::read_to_string(&config).expect("read result"),
            "sandbox_mode = \"read-only\"\n"
        );
        assert_eq!(receipt.backup_references.len(), 1);
        let rollback = adapter
            .rollback_change(&change_set, &temp.path().join("backups"))
            .expect("rollback");
        assert_eq!(rollback.status, ChangeStatus::RolledBack);
        assert_eq!(
            std::fs::read_to_string(&config).expect("read rollback"),
            "sandbox_mode = \"workspace-write\"\n"
        );
    }

    #[test]
    fn invalid_toml_is_rejected_before_a_change_set_is_created() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("config.toml");
        std::fs::write(&config, "sandbox_mode = \"read-only\"\n").expect("write fixture");
        let adapter = CodexAdapter::from_environment(Some(temp.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host_fixture"),
            target: ArtifactRef {
                host_id: "host_fixture".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: config.to_string_lossy().into_owned(),
                source_reference: config.to_string_lossy().into_owned(),
            },
            expected_source_hash: None,
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("sandbox_mode = [\n".into()),
            reason: "invalid TOML fixture".into(),
            evidence_ids: Vec::new(),
        };
        let error = adapter
            .propose_change(&request)
            .expect_err("invalid TOML is rejected");
        assert!(error.to_string().contains("not valid TOML"));
        assert_eq!(
            std::fs::read_to_string(&config).expect("source remains untouched"),
            "sandbox_mode = \"read-only\"\n"
        );
    }

    #[test]
    fn untrusted_project_configuration_cannot_be_proposed_for_mutation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let project = project_dir.path().to_path_buf();
        let config = project.join(".codex/config.toml");
        std::fs::create_dir_all(config.parent().expect("config parent")).expect("project dirs");
        std::fs::write(&config, "sandbox_mode = \"read-only\"\n").expect("write fixture");
        std::fs::write(
            temp.path().join("projects.toml"),
            format!(
                "[projects.\"{}\"]\ntrust_level = \"untrusted\"\n",
                project.display()
            ),
        )
        .expect("write project trust registry");
        let adapter = CodexAdapter::from_environment(Some(temp.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host_fixture"),
            target: ArtifactRef {
                host_id: "host_fixture".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: config.to_string_lossy().into_owned(),
                source_reference: config.to_string_lossy().into_owned(),
            },
            expected_source_hash: None,
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("sandbox_mode = \"workspace-write\"\n".into()),
            reason: "untrusted project fixture".into(),
            evidence_ids: Vec::new(),
        };
        let error = adapter
            .propose_change(&request)
            .expect_err("untrusted project is proposal-only at most");
        assert!(
            error.to_string().contains("not trusted for mutation"),
            "unexpected policy error: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&config).expect("source remains untouched"),
            "sandbox_mode = \"read-only\"\n"
        );
    }

    #[test]
    fn trusted_registered_project_configuration_can_be_proposed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let config = project_dir.path().join(".codex/config.toml");
        std::fs::create_dir_all(config.parent().expect("config parent")).expect("project dirs");
        std::fs::write(&config, "sandbox_mode = \"read-only\"\n").expect("write fixture");
        std::fs::write(
            temp.path().join("projects.toml"),
            format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                project_dir.path().display()
            ),
        )
        .expect("write project trust registry");
        let adapter = CodexAdapter::from_environment(Some(temp.path().to_path_buf()));
        let request = ChangeRequest {
            actor: "test-human".into(),
            scope: Scope::host("host_fixture"),
            target: ArtifactRef {
                host_id: "host_fixture".into(),
                provider_id: CODEX_PROVIDER_ID.into(),
                native_id: config.to_string_lossy().into_owned(),
                source_reference: config.to_string_lossy().into_owned(),
            },
            expected_source_hash: None,
            operation: ChangeOperationKind::ReplaceText,
            replacement_content: Some("sandbox_mode = \"workspace-write\"\n".into()),
            reason: "trusted project fixture".into(),
            evidence_ids: Vec::new(),
        };
        assert!(adapter.propose_change(&request).is_ok());
        assert_eq!(
            std::fs::read_to_string(&config).expect("proposal does not write"),
            "sandbox_mode = \"read-only\"\n"
        );
    }
}
