use amcp_domain::{
    AuditEvent, ChangeSet, ChangeStatus, CollectionBatch, ConfigLayerRecord, GuidanceRecord,
    MemoryRecord, ProjectRecord, ProviderRecord, RuntimeEvent, SensitivityClass, SessionItem,
    SessionRecord, new_id,
};
use amcp_storage::{
    Catalog, CatalogBackupReceipt, CatalogDiagnostics, ControllerTag, CrossHostRelationship,
    HostAlias, MemoryForgetReceipt, SavedSearch, SearchFilters, SearchHit, SessionFilters,
};
use anyhow::Result;
use chrono::Utc;
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

    pub fn create_backup(&self, reason: &str) -> Result<CatalogBackupReceipt> {
        self.catalog.create_backup(reason)
    }

    pub fn search(&mut self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        self.catalog.search(query, limit)
    }

    pub fn search_scoped(
        &mut self,
        query: &str,
        limit: usize,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<SearchHit>> {
        self.catalog
            .search_scoped(query, limit, host_id, provider_id, project_id)
    }

    pub fn search_filtered(
        &mut self,
        query: &str,
        limit: usize,
        filters: &SearchFilters,
    ) -> Result<Vec<SearchHit>> {
        self.catalog.search_filtered(query, limit, filters)
    }

    pub fn save_search(
        &mut self,
        name: &str,
        query: &str,
        filters: &SearchFilters,
    ) -> Result<SavedSearch> {
        self.catalog.save_search(name, query, filters)
    }

    pub fn list_saved_searches(&self) -> Result<Vec<SavedSearch>> {
        self.catalog.list_saved_searches()
    }

    pub fn delete_saved_search(&mut self, saved_search_id: &str) -> Result<bool> {
        self.catalog.delete_saved_search(saved_search_id)
    }

    pub fn set_host_alias(&mut self, host_id: &str, alias: &str) -> Result<HostAlias> {
        self.catalog.set_host_alias(host_id, alias)
    }

    pub fn list_host_aliases(&self) -> Result<Vec<HostAlias>> {
        self.catalog.list_host_aliases()
    }

    pub fn delete_host_alias(&mut self, host_id: &str) -> Result<bool> {
        self.catalog.delete_host_alias(host_id)
    }

    pub fn tag_artifact(&mut self, artifact_id: &str, name: &str) -> Result<ControllerTag> {
        self.catalog.tag_artifact(artifact_id, name)
    }

    pub fn list_artifact_tags(&self, artifact_id: &str) -> Result<Vec<ControllerTag>> {
        self.catalog.list_artifact_tags(artifact_id)
    }

    pub fn untag_artifact(&mut self, artifact_id: &str, tag_id: &str) -> Result<bool> {
        self.catalog.untag_artifact(artifact_id, tag_id)
    }

    pub fn link_cross_host_artifacts(
        &mut self,
        first_artifact_id: &str,
        second_artifact_id: &str,
        relationship_kind: &str,
    ) -> Result<CrossHostRelationship> {
        self.catalog.link_cross_host_artifacts(
            first_artifact_id,
            second_artifact_id,
            relationship_kind,
        )
    }

    pub fn list_cross_host_relationships(
        &self,
        artifact_id: &str,
    ) -> Result<Vec<CrossHostRelationship>> {
        self.catalog.list_cross_host_relationships(artifact_id)
    }

    pub fn unlink_cross_host_relationship(&mut self, relationship_id: &str) -> Result<bool> {
        self.catalog.unlink_cross_host_relationship(relationship_id)
    }

    pub fn artifact_source_hashes(&self) -> Result<std::collections::HashMap<String, String>> {
        self.catalog.artifact_source_hashes()
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

    pub fn list_sessions_filtered(&self, filters: &SessionFilters) -> Result<Vec<SessionRecord>> {
        self.catalog.list_sessions_filtered(filters)
    }

    pub fn list_memory_records(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<MemoryRecord>> {
        self.catalog.list_memory_records(host_id, project_id)
    }

    pub fn list_memory_records_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<MemoryRecord>> {
        self.catalog
            .list_memory_records_scoped(host_id, provider_id, project_id)
    }

    pub fn forget_memory_record(
        &mut self,
        memory_record_id: &str,
        host_id: &str,
        provider_id: &str,
        reason: &str,
    ) -> Result<MemoryForgetReceipt> {
        self.catalog
            .forget_memory_record(memory_record_id, host_id, provider_id, reason)
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

    pub fn diagnostics(&self) -> Result<CatalogDiagnostics> {
        self.catalog.diagnostics()
    }

    pub fn list_config_layers(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ConfigLayerRecord>> {
        self.catalog.list_config_layers(host_id, project_id)
    }

    pub fn list_config_layers_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ConfigLayerRecord>> {
        self.catalog
            .list_config_layers_scoped(host_id, provider_id, project_id)
    }

    pub fn list_guidance(
        &self,
        host_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<GuidanceRecord>> {
        self.catalog.list_guidance(host_id, project_id)
    }

    pub fn list_guidance_scoped(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<GuidanceRecord>> {
        self.catalog
            .list_guidance_scoped(host_id, provider_id, project_id)
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

    /// Content-free catalog cardinality used to distinguish an empty index
    /// from an indexed query with no matching evidence.
    pub fn artifact_count(&self) -> Result<i64> {
        self.catalog.artifact_count()
    }

    pub fn record_collection_run(&mut self, run: &amcp_storage::CollectionRunRecord) -> Result<()> {
        self.catalog.record_collection_run(run)
    }

    pub fn list_collection_runs(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<amcp_storage::CollectionRunRecord>> {
        self.catalog
            .list_collection_runs(host_id, provider_id, limit)
    }

    pub fn list_search_runs(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<amcp_storage::SearchRunRecord>> {
        self.catalog.list_search_runs(host_id, provider_id, limit)
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

    pub fn set_provider_health(
        &mut self,
        host_id: &str,
        provider_id: &str,
        health: amcp_domain::ProviderHealth,
    ) -> Result<()> {
        self.catalog
            .set_provider_health(host_id, provider_id, health)
    }

    pub fn save_change_set(&mut self, change_set: &ChangeSet) -> Result<()> {
        self.catalog.save_change_set(change_set)
    }

    pub fn record_audit(&mut self, event: &AuditEvent) -> Result<()> {
        self.catalog.record_audit(event)
    }

    pub fn audit_event_count(&self) -> Result<usize> {
        self.catalog.audit_event_count()
    }

    pub fn list_audit_events(
        &self,
        host_id: Option<&str>,
        provider_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        self.catalog.list_audit_events(host_id, provider_id, limit)
    }

    /// Audit redacted catalog search results that are still classified as
    /// sensitive. The query and preview are intentionally never persisted in
    /// the audit record.
    pub fn audit_sensitive_search_results(
        &mut self,
        actor: &str,
        results: &[SearchHit],
    ) -> Result<usize> {
        let correlation_id = new_id("correlation");
        let mut recorded = 0;
        for hit in results.iter().filter(|hit| {
            matches!(
                hit.sensitivity,
                SensitivityClass::Sensitive | SensitivityClass::SecretLike
            )
        }) {
            self.catalog.record_audit(&AuditEvent {
                audit_event_id: new_id("audit"),
                actor: actor.to_owned(),
                operation: "catalog.search_sensitive".to_owned(),
                target: hit.source_reference.clone(),
                host_id: Some(hit.host_id.clone()),
                provider_id: Some(hit.provider_id.clone()),
                before_hash: None,
                after_hash: None,
                result: "redacted catalog search result".to_owned(),
                correlation_id: correlation_id.clone(),
                timestamp: Utc::now(),
            })?;
            recorded += 1;
        }
        Ok(recorded)
    }
}
