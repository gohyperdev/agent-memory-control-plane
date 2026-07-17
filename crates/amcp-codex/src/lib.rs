use amcp_domain::{
    ArtifactKind, ArtifactRecord, CollectionBatch, EvidenceSnapshot, HostIdentity, LifecycleState,
    ObservationState, ProviderDescriptor, SensitivityClass, SourceObservation, new_id,
};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    env, fs, io,
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
            project_id: None,
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
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or("none")
        .to_owned()
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
}
