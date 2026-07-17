use amcp_domain::{
    ArtifactKind, ArtifactRecord, ArtifactRef, ChangeOperationKind, ChangeReceipt, ChangeRequest,
    ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord, EvidenceSnapshot, GuidanceEdge,
    GuidanceRecord, HostIdentity, LifecycleState, MemoryRecord, ObservationState, ProjectRecord,
    ProviderDescriptor, SensitivityClass, SessionRecord, SourceObservation, new_id,
};
use amcp_provider_api::ProviderAdapter;
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
};
use walkdir::WalkDir;

pub const CODEX_PROVIDER_ID: &str = "codex";
pub const ADAPTER_VERSION: &str = "0.1.0";
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
        ProviderDescriptor {
            id: CODEX_PROVIDER_ID.to_owned(),
            display_name: "OpenAI Codex".to_owned(),
            version: None,
            adapter_version: ADAPTER_VERSION.to_owned(),
            capabilities: vec![
                "inventory".to_owned(),
                "read".to_owned(),
                "search".to_owned(),
                "projects".to_owned(),
                "sessions".to_owned(),
                "memory".to_owned(),
            ],
        }
    }

    pub fn discover(&self, host: HostIdentity) -> io::Result<CollectionBatch> {
        let collection_run_id = new_id("run");
        let mut artifacts = Vec::new();
        let mut projects = Vec::new();
        let mut sessions = Vec::new();
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
                &mut memory_records,
                &mut config_layers,
                &mut guidance_records,
            )?;
        }

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

        Ok(CollectionBatch {
            collection_run_id,
            host,
            providers: vec![self.provider()],
            projects,
            sessions,
            session_items: Vec::new(),
            memory_records,
            config_layers,
            guidance_records,
            guidance_edges,
            artifacts,
            next_cursor: None,
        })
    }

    pub fn propose_change(&self, request: &ChangeRequest) -> Result<ChangeSet> {
        if request.target.provider_id != CODEX_PROVIDER_ID {
            bail!("unsupported provider: {}", request.target.provider_id);
        }
        if request.target.host_id.trim().is_empty() {
            bail!("change target has no host id");
        }
        let path = self.authorized_path(&request.target.source_reference)?;
        if matches!(request.operation, ChangeOperationKind::DeleteFile) {
            bail!("Codex adapter does not allow file deletion in this release");
        }
        let current = read_optional(&path)?;
        let before_hash = current.as_deref().map(hash_bytes);
        if let Some(expected) = &request.expected_source_hash {
            if before_hash.as_deref() != Some(expected.as_str()) {
                bail!(
                    "source hash conflict: expected {expected}, found {:?}",
                    before_hash
                );
            }
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
        let path = self.authorized_path(&target.source_reference)?;
        let kind = match path.file_name().and_then(|name| name.to_str()) {
            Some("AGENTS.md") | Some("AGENTS.override.md") => ArtifactKind::Instruction,
            Some("config.toml") => ArtifactKind::Configuration,
            _ => bail!("artifact is not a supported safe Codex document"),
        };
        Ok(self.file_artifact(&path, kind, host, &new_id("read"), true)?)
    }

    pub fn apply_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt> {
        if change_set.operations.is_empty() {
            bail!("change set contains no operations");
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
            if redact_text(replacement) != replacement {
                bail!("replacement content contains secret-like material");
            }
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
        let mut roots = vec![self.codex_home.clone()];
        roots.extend(self.scan_roots.iter().cloned());
        let roots = roots
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
        if requested
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| matches!(name, "auth.json" | "history.jsonl" | "session_index.jsonl"))
            .unwrap_or(true)
        {
            bail!("change target is not writable by Codex policy");
        }
        if !matches!(
            requested.file_name().and_then(|name| name.to_str()),
            Some("config.toml") | Some("AGENTS.md") | Some("AGENTS.override.md")
        ) {
            bail!("change target is not a supported Codex text document");
        }
        if requested.exists() && fs::symlink_metadata(&requested)?.file_type().is_symlink() {
            bail!("symlink targets are not writable");
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
                    self.discover_session_file(&path, host, sessions)?;
                }
                if kind == ArtifactKind::Configuration && relative != "projects.toml" {
                    if let Ok(layer) = self.config_layer(&path, host) {
                        config_layers.push(layer);
                    }
                }
                if kind == ArtifactKind::Instruction {
                    if let Ok(guidance) = self.guidance_record(&path, host) {
                        guidance_records.push(guidance);
                    }
                }
            }
        }

        let history = root.join("history.jsonl");
        let session_index = root.join("session_index.jsonl");
        if !session_index.is_file() && history.is_file() {
            self.discover_session_file(&history, host, sessions)?;
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
                self.discover_session_file(entry.path(), host, sessions)?;
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
            if let Ok(document) = content.parse::<toml::Value>() {
                if let Some(entries) = document.get("projects").and_then(toml::Value::as_table) {
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

    fn discover_session_file(
        &self,
        path: &Path,
        host: &HostIdentity,
        sessions: &mut Vec<SessionRecord>,
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
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                if value.get("session_id").is_some() || value.get("thread_id").is_some() {
                    metadata = value;
                    break;
                }
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
            session_id,
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
            source_reference,
            source_hash,
            metadata_json: serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_owned()),
            observed_at: Utc::now(),
        });
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

    fn discovery_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.codex_home.clone()];
        roots.extend(self.scan_roots.iter().cloned());
        let projects_file = self.codex_home.join("projects.toml");
        if let Ok(content) = fs::read_to_string(projects_file) {
            if let Ok(document) = content.parse::<toml::Value>() {
                if let Some(entries) = document.get("projects").and_then(toml::Value::as_table) {
                    roots.extend(
                        entries
                            .keys()
                            .map(PathBuf::from)
                            .filter(|path| path.is_dir()),
                    );
                }
            }
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
        let kind = if path.file_name().and_then(|name| name.to_str()) == Some("AGENTS.override.md")
        {
            "override"
        } else {
            "agents"
        };
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

    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch> {
        Self::discover(self, host).map_err(Into::into)
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
        assert_eq!(adapter.provider().id, CODEX_PROVIDER_ID);
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

        let batch = CodexAdapter::from_environment(Some(directory.path().to_path_buf()))
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
}
