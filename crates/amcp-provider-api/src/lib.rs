use amcp_domain::{
    ArtifactRecord, ArtifactRef, ChangeReceipt, ChangeRequest, ChangeSet, CollectionBatch,
    HostIdentity, ProviderDescriptor, RuntimeEvent,
};
use anyhow::{Result, bail};
use std::path::Path;

pub trait ProviderAdapter: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
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
}
