use amcp_domain::{
    ArtifactKind, ArtifactRecord, ArtifactRef, ChangeOperationKind, ChangeReceipt, ChangeRequest,
    ChangeSet, ChangeStatus, CollectionBatch, EvidenceSnapshot, HostIdentity, LifecycleState,
    ObservationState, ProviderDescriptor, SensitivityClass, SourceObservation, new_id,
};
use amcp_provider_api::ProviderAdapter;
use anyhow::{Result, bail};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
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
            ],
        }
    }

    pub fn discover(&self, host: HostIdentity) -> io::Result<CollectionBatch> {
        let collection_run_id = new_id("run");
        let mut artifacts = Vec::new();
        let mut roots = vec![self.codex_home.clone()];
        roots.extend(self.scan_roots.iter().cloned());

        for root in roots {
            if !root.exists() {
                continue;
            }
            self.discover_root(&root, &host, &collection_run_id, &mut artifacts)?;
        }

        artifacts.sort_by(|left, right| left.source_reference.cmp(&right.source_reference));

        Ok(CollectionBatch {
            collection_run_id,
            host,
            providers: vec![self.provider()],
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
    ) -> io::Result<()> {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
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
                    kind,
                    host,
                    collection_run_id,
                    allow_content,
                )?);
            }
        }

        for directory in ["sessions", "archived_sessions", "memories"] {
            let path = root.join(directory);
            if path.is_dir() {
                self.discover_directory_metadata(&path, host, collection_run_id, artifacts)?;
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
    ) -> io::Result<()> {
        for entry in WalkDir::new(directory).max_depth(2).follow_links(false) {
            let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            artifacts.push(self.file_artifact(
                entry.path(),
                if directory.file_name().and_then(|name| name.to_str()) == Some("memories") {
                    ArtifactKind::Memory
                } else {
                    ArtifactKind::Session
                },
                host,
                collection_run_id,
                false,
            )?);
        }
        Ok(())
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
        self.scan_roots
            .iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .find(|root| path.starts_with(root))
            .map(|root| root.to_string_lossy().into_owned())
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
