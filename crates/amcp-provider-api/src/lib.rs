use amcp_domain::{
    ArtifactRecord, ArtifactRef, ChangeReceipt, ChangeRequest, ChangeSet, CollectionBatch,
    HostIdentity, ProviderDescriptor,
};
use anyhow::Result;
use std::path::Path;

pub trait ProviderAdapter: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;
    fn discover(&self, host: HostIdentity) -> Result<CollectionBatch>;
    fn read_artifact(&self, target: &ArtifactRef, host: &HostIdentity) -> Result<ArtifactRecord>;
    fn propose_change(&self, request: &ChangeRequest) -> Result<ChangeSet>;
    fn apply_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt>;
    fn rollback_change(&self, change_set: &ChangeSet, backup_dir: &Path) -> Result<ChangeReceipt>;
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
}
