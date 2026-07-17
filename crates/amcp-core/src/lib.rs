use amcp_domain::{
    AuditEvent, ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord, GuidanceRecord,
    MemoryRecord, ProjectRecord, ProviderRecord, RuntimeEvent, SessionItem, SessionRecord,
};
use amcp_storage::{Catalog, SearchHit};
use anyhow::Result;
use std::path::Path;

/// Functional Controller catalog API shared by the human UI and tool adapters.
/// Provider-specific path and parsing logic stays in the Agent adapters.
pub struct CatalogService {
    catalog: Catalog,
}

impl CatalogService {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            catalog: Catalog::open(path)?,
        })
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        self.catalog.search(query, limit)
    }

    pub fn search_scoped(
        &self,
        query: &str,
        limit: usize,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SearchHit>> {
        self.catalog
            .search_scoped(query, limit, host_id, provider_id, project_id)
    }

    pub fn list_hosts(&self) -> Result<Vec<amcp_domain::HostRecord>> {
        self.catalog.list_hosts()
    }

    pub fn list_providers(&self, host_id: Option<&str>) -> Result<Vec<ProviderRecord>> {
        self.catalog.list_providers(host_id)
    }

    pub fn list_projects(&self, host_id: Option<&str>) -> Result<Vec<ProjectRecord>> {
        self.catalog.list_projects(host_id)
    }

    pub fn list_sessions(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SessionRecord>> {
        self.catalog.list_sessions(host_id, project_id)
    }

    pub fn list_memory_records(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<MemoryRecord>> {
        self.catalog.list_memory_records(host_id, project_id)
    }

    pub fn list_session_items(
        &self,
        session_id: &str,
        host_id: Option<&str>,
    ) -> Result<Vec<SessionItem>> {
        self.catalog.list_session_items(session_id, host_id)
    }

    pub fn list_runtime_events(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RuntimeEvent>> {
        self.catalog
            .list_runtime_events(host_id, provider_id, limit)
    }

    pub fn list_config_layers(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ConfigLayerRecord>> {
        self.catalog.list_config_layers(host_id, project_id)
    }

    pub fn list_guidance(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<GuidanceRecord>> {
        self.catalog.list_guidance(host_id, project_id)
    }

    pub fn list_change_sets(&self, status: Option<ChangeStatus>) -> Result<Vec<ChangeSet>> {
        self.catalog.list_change_sets(status)
    }

    pub fn load_change_set(&self, change_set_id: &str) -> Result<Option<ChangeSet>> {
        self.catalog.load_change_set(change_set_id)
    }

    pub fn ingest(&mut self, batch: &CollectionBatch) -> Result<usize> {
        self.catalog.ingest(batch)
    }

    pub fn ingest_runtime_events(&mut self, events: &[RuntimeEvent]) -> Result<usize> {
        self.catalog.ingest_runtime_events(events)
    }

    pub fn latest_index_run(&self) -> Result<Option<amcp_storage::IndexRunRecord>> {
        self.catalog.latest_index_run()
    }

    pub fn rebuild_search_projection(
        &mut self,
        batch_size: usize,
    ) -> Result<amcp_storage::IndexRunRecord> {
        self.catalog.rebuild_search_projection(batch_size)
    }

    pub fn latest_cursor(&self, host_id: &str, provider_id: &str) -> Result<Option<String>> {
        self.catalog.latest_cursor(host_id, provider_id)
    }

    pub fn save_cursor(
        &mut self,
        host_id: &str,
        provider_id: &str,
        cursor: Option<&str>,
        collection_run_id: &str,
    ) -> Result<()> {
        self.catalog
            .save_cursor(host_id, provider_id, cursor, collection_run_id)
    }

    pub fn register_connection(
        &mut self,
        host: &amcp_domain::HostIdentity,
        endpoint: Option<&str>,
        agent_version: Option<&str>,
        capabilities: &[String],
    ) -> Result<()> {
        self.catalog
            .register_connection(host, endpoint, agent_version, capabilities)
    }

    pub fn register_provider_descriptors(
        &mut self,
        host: &amcp_domain::HostIdentity,
        descriptors: &[amcp_domain::ProviderDescriptor],
    ) -> Result<()> {
        self.catalog
            .register_provider_descriptors(host, descriptors)
    }

    pub fn save_change_set(&mut self, change_set: &ChangeSet) -> Result<()> {
        self.catalog.save_change_set(change_set)
    }

    pub fn record_audit(&mut self, event: &AuditEvent) -> Result<()> {
        self.catalog.record_audit(event)
    }
}
