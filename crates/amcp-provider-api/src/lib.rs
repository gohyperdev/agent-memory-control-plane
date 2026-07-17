use amcp_domain::{
    ArtifactRecord, ArtifactRef, ChangeReceipt, ChangeRequest, ChangeSet, CollectionBatch,
    HostIdentity, ProviderDescriptor, RuntimeEvent, RuntimeThreadRecord,
};
use anyhow::{Result, bail};
use std::path::Path;

/// A provider descriptor that can be registered before a provider has a full
/// parser or mutation implementation. It makes capability negotiation and UI
/// diagnostics provider-neutral without pretending that inventory-only state
/// is writable.
#[derive(Debug, Clone)]
pub struct InventoryProviderAdapter {
    descriptor: ProviderDescriptor,
}

#[derive(Debug, Clone)]
pub struct RuntimeAdapterDescriptor {
    pub transport: String,
    pub operations: Vec<String>,
}

impl InventoryProviderAdapter {
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        adapter_version: impl Into<String>,
    ) -> Self {
        Self {
            descriptor: ProviderDescriptor {
                id: id.into(),
                display_name: display_name.into(),
                version: None,
                adapter_version: adapter_version.into(),
                capabilities: vec!["inventory".into()],
            },
        }
    }
}

impl ProviderAdapter for InventoryProviderAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch> {
        Ok(CollectionBatch {
            collection_run_id: amcp_domain::new_id("run"),
            host,
            providers: vec![self.descriptor()],
            projects: Vec::new(),
            sessions: Vec::new(),
            session_items: Vec::new(),
            memory_records: Vec::new(),
            config_layers: Vec::new(),
            guidance_records: Vec::new(),
            guidance_edges: Vec::new(),
            runtime_events: Vec::new(),
            artifacts: Vec::new(),
            next_cursor: None,
        })
    }
}

pub trait ProviderAdapter: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    /// Provider-neutral runtime capability declaration. The Agent selects the
    /// connector by transport and operation instead of hard-coding provider
    /// IDs into the protocol or UI.
    fn runtime_descriptor(&self) -> Option<RuntimeAdapterDescriptor> {
        None
    }
    /// Return a cheap source-state cursor when the provider supports incremental discovery.
    fn collection_cursor(&self) -> Option<String> {
        None
    }
    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch>;
    /// Convert provider-native live thread/session metadata into a bounded,
    /// provider-neutral runtime event. Providers without a runtime connector
    /// remain inventory-only for this capability.
    fn map_runtime_thread(
        &self,
        _host: &HostIdentity,
        _thread: &serde_json::Value,
        _sequence: &mut i64,
    ) -> Result<Option<RuntimeEvent>> {
        Ok(None)
    }
    /// Convert a provider-native live thread into bounded metadata for a
    /// read-only runtime inventory request.
    fn map_runtime_thread_record(
        &self,
        _host: &HostIdentity,
        _thread: &serde_json::Value,
    ) -> Result<Option<RuntimeThreadRecord>> {
        Ok(None)
    }
    fn read_artifact(&self, _target: &ArtifactRef, _host: &HostIdentity) -> Result<ArtifactRecord> {
        bail!("provider does not expose artifact reads")
    }
    fn propose_change(&self, _request: &ChangeRequest) -> Result<ChangeSet> {
        bail!("provider is inventory-only")
    }
    fn apply_change(&self, _change_set: &ChangeSet, _backup_dir: &Path) -> Result<ChangeReceipt> {
        bail!("provider is inventory-only")
    }
    fn rollback_change(
        &self,
        _change_set: &ChangeSet,
        _backup_dir: &Path,
    ) -> Result<ChangeReceipt> {
        bail!("provider is inventory-only")
    }
}

pub struct ProviderRegistry {
    adapters: Vec<Box<dyn ProviderAdapter>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    pub fn register(&mut self, adapter: Box<dyn ProviderAdapter>) {
        self.adapters.push(adapter);
    }

    pub fn descriptors(&self) -> Vec<ProviderDescriptor> {
        self.adapters
            .iter()
            .map(|adapter| adapter.descriptor())
            .collect()
    }

    pub fn get(&self, provider_id: &str) -> Result<&dyn ProviderAdapter> {
        self.adapters
            .iter()
            .find(|adapter| adapter.descriptor().id == provider_id)
            .map(|adapter| adapter.as_ref())
            .ok_or_else(|| anyhow::anyhow!("provider is not registered: {provider_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProvider;

    impl ProviderAdapter for FakeProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                id: "fake".into(),
                display_name: "Fake".into(),
                version: None,
                adapter_version: "test".into(),
                capabilities: vec!["inventory".into()],
            }
        }

        fn discover(&self, _host: HostIdentity) -> Result<CollectionBatch> {
            anyhow::bail!("not needed")
        }

        fn read_artifact(
            &self,
            _target: &ArtifactRef,
            _host: &HostIdentity,
        ) -> Result<ArtifactRecord> {
            anyhow::bail!("not needed")
        }

        fn propose_change(&self, _request: &ChangeRequest) -> Result<ChangeSet> {
            anyhow::bail!("not needed")
        }

        fn apply_change(
            &self,
            _change_set: &ChangeSet,
            _backup_dir: &Path,
        ) -> Result<ChangeReceipt> {
            anyhow::bail!("not needed")
        }

        fn rollback_change(
            &self,
            _change_set: &ChangeSet,
            _backup_dir: &Path,
        ) -> Result<ChangeReceipt> {
            anyhow::bail!("not needed")
        }
    }

    struct InventoryOnlyProvider;

    impl ProviderAdapter for InventoryOnlyProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                id: "inventory-only".into(),
                display_name: "Inventory only".into(),
                version: None,
                adapter_version: "test".into(),
                capabilities: vec!["inventory".into()],
            }
        }

        fn discover(&self, _host: HostIdentity) -> Result<CollectionBatch> {
            anyhow::bail!("test provider does not collect")
        }
    }

    #[test]
    fn registry_resolves_provider_by_neutral_id() {
        let mut registry = ProviderRegistry::new();
        registry.register(Box::new(FakeProvider));
        assert_eq!(
            registry.get("fake").expect("provider").descriptor().id,
            "fake"
        );
        assert!(registry.get("codex").is_err());
    }

    #[test]
    fn inventory_only_provider_can_omit_mutation_methods() {
        let mut registry = ProviderRegistry::new();
        registry.register(Box::new(InventoryOnlyProvider));
        let provider = registry.get("inventory-only").expect("provider");
        assert!(
            provider
                .propose_change(&ChangeRequest {
                    actor: "test".into(),
                    scope: amcp_domain::Scope::host("host"),
                    target: ArtifactRef {
                        host_id: "host".into(),
                        provider_id: "inventory-only".into(),
                        native_id: "native".into(),
                        source_reference: "fixture://native".into(),
                    },
                    expected_source_hash: None,
                    operation: amcp_domain::ChangeOperationKind::ReplaceText,
                    replacement_content: Some("content".into()),
                    reason: "test".into(),
                    evidence_ids: Vec::new(),
                })
                .is_err()
        );
    }

    #[test]
    fn inventory_adapter_reports_capability_without_mutation_claims() {
        let adapter = InventoryProviderAdapter::new("claude-code", "Claude Code", "fixture");
        assert_eq!(adapter.descriptor().id, "claude-code");
        assert_eq!(adapter.descriptor().capabilities, vec!["inventory"]);
        assert!(
            adapter
                .propose_change(&ChangeRequest {
                    actor: "test".into(),
                    scope: amcp_domain::Scope::host("host"),
                    target: ArtifactRef {
                        host_id: "host".into(),
                        provider_id: "claude-code".into(),
                        native_id: "native".into(),
                        source_reference: "fixture://native".into(),
                    },
                    expected_source_hash: None,
                    operation: amcp_domain::ChangeOperationKind::ReplaceText,
                    replacement_content: Some("content".into()),
                    reason: "test".into(),
                    evidence_ids: Vec::new(),
                })
                .is_err()
        );
    }
}
