use amcp_domain::{
    AuditEvent, ChangeSet, ChangeStatus, CollectionBatch, MemoryRecord, ProjectRecord,
    SessionRecord,
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

    pub fn list_change_sets(&self, status: Option<ChangeStatus>) -> Result<Vec<ChangeSet>> {
        self.catalog.list_change_sets(status)
    }

    pub fn load_change_set(&self, change_set_id: &str) -> Result<Option<ChangeSet>> {
        self.catalog.load_change_set(change_set_id)
    }

    pub fn ingest(&mut self, batch: &CollectionBatch) -> Result<usize> {
        self.catalog.ingest(batch)
    }

    pub fn save_change_set(&mut self, change_set: &ChangeSet) -> Result<()> {
        self.catalog.save_change_set(change_set)
    }

    pub fn record_audit(&mut self, event: &AuditEvent) -> Result<()> {
        self.catalog.record_audit(event)
    }
}
