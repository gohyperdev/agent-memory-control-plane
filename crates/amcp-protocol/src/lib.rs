use amcp_domain::{
    ApprovalEnvelope, ArtifactRecord, ArtifactRef, ChangeReceipt, ChangeRequest, ChangeSet,
    CollectionBatch, HostIdentity, LocalSearchHit, ProviderDescriptor, RuntimeEvent,
    RuntimeThreadRecord, RuntimeThreadSnapshot, Scope,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub protocol_version: u32,
    pub request_id: String,
    pub correlation_id: String,
    pub host_id: Option<String>,
    pub deadline_ms: Option<u64>,
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub pairing_code: Option<String>,
    pub method: RequestMethod,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum RequestMethod {
    Register {
        controller_id: String,
    },
    Enroll {
        controller_id: String,
    },
    Heartbeat,
    Capabilities,
    Collect {
        scope: Option<Scope>,
        cursor: Option<String>,
    },
    SearchLocal {
        query: String,
        scope: Option<Scope>,
        limit: usize,
    },
    ReplayCollection {
        provider_id: String,
        limit: usize,
    },
    ReplayEvents {
        after_event_id: Option<String>,
        limit: usize,
    },
    SubscribeEvents {
        after_event_id: Option<String>,
        limit: usize,
        wait_ms: u64,
    },
    OpenEventStream {
        after_event_id: Option<String>,
        scope: Option<Scope>,
        max_in_flight: usize,
        heartbeat_ms: u64,
    },
    CloseEventStream {
        stream_id: String,
    },
    RuntimeListThreads {
        provider_id: String,
        scope: Option<Scope>,
        cursor: Option<String>,
        limit: usize,
    },
    RuntimeReadThread {
        provider_id: String,
        scope: Option<Scope>,
        thread_id: String,
    },
    RuntimeProposeThreadChange {
        request: ChangeRequest,
    },
    RuntimeApplyThreadChange {
        change_set: ChangeSet,
        approval: ApprovalEnvelope,
    },
    AckEvents {
        event_ids: Vec<String>,
    },
    ReadArtifact {
        target: ArtifactRef,
        redacted: bool,
    },
    ProposeChange {
        request: ChangeRequest,
    },
    ApplyChange {
        change_set: ChangeSet,
        approval: ApprovalEnvelope,
    },
    Rollback {
        change_set: ChangeSet,
        approval: ApprovalEnvelope,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub protocol_version: u32,
    pub request_id: String,
    pub result: Result<ResponsePayload, ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ResponsePayload {
    Registered {
        agent_id: String,
        host: HostIdentity,
    },
    Enrolled {
        agent_id: String,
        host: HostIdentity,
        credential: String,
        expires_at: String,
    },
    Heartbeat {
        healthy: bool,
        host_id: String,
        timestamp: String,
    },
    Capabilities {
        platform: String,
        providers: Vec<String>,
        #[serde(default)]
        provider_descriptors: Vec<ProviderDescriptor>,
        capabilities: Vec<String>,
        agent_version: String,
    },
    Collection(CollectionBatch),
    LocalSearch {
        results: Vec<LocalSearchHit>,
        cache_available: bool,
    },
    CollectionReplay {
        provider_id: String,
        batches: Vec<CollectionBatch>,
    },
    RuntimeEvents(Vec<RuntimeEvent>),
    RuntimeEventPage {
        events: Vec<RuntimeEvent>,
        next_event_id: Option<String>,
        timed_out: bool,
    },
    EventStreamOpened {
        stream_id: String,
        max_in_flight: usize,
        heartbeat_ms: u64,
    },
    EventStreamPage {
        stream_id: String,
        events: Vec<RuntimeEvent>,
        next_event_id: Option<String>,
        heartbeat: bool,
    },
    EventStreamClosed {
        stream_id: String,
        reason: String,
    },
    RuntimeThreadPage {
        provider_id: String,
        threads: Vec<RuntimeThreadRecord>,
        next_cursor: Option<String>,
    },
    RuntimeThreadSnapshot(RuntimeThreadSnapshot),
    RuntimeEventsAcked(usize),
    Artifact(ArtifactRecord),
    ChangeSet(ChangeSet),
    ChangeReceipt(ChangeReceipt),
    ShutdownAck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolError {
    pub code: String,
    pub message: String,
}

impl ProtocolError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl RequestEnvelope {
    pub fn new(method: RequestMethod, token: Option<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            host_id: None,
            deadline_ms: None,
            idempotency_key: None,
            pairing_code: None,
            method,
            token,
        }
    }

    pub fn with_pairing_code(mut self, pairing_code: impl Into<String>) -> Self {
        self.pairing_code = Some(pairing_code.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_preserves_method() {
        let request = RequestEnvelope::new(
            RequestMethod::Collect {
                scope: None,
                cursor: None,
            },
            Some("token".to_owned()),
        );
        let encoded = serde_json::to_string(&request).expect("request should serialize");
        let decoded: RequestEnvelope =
            serde_json::from_str(&encoded).expect("request should deserialize");
        assert!(matches!(decoded.method, RequestMethod::Collect { .. }));
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn enrollment_request_round_trip_preserves_pairing_code() {
        let request = RequestEnvelope::new(
            RequestMethod::Enroll {
                controller_id: "controller".into(),
            },
            None,
        )
        .with_pairing_code("12345678");
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode"))
                .expect("decode");
        assert_eq!(decoded.pairing_code.as_deref(), Some("12345678"));
        assert!(matches!(decoded.method, RequestMethod::Enroll { .. }));
    }

    #[test]
    fn replay_request_round_trip_preserves_limit() {
        let request = RequestEnvelope::new(
            RequestMethod::ReplayCollection {
                provider_id: "codex".into(),
                limit: 4,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode replay request"))
                .expect("decode replay request");
        assert!(matches!(
            decoded.method,
            RequestMethod::ReplayCollection { limit: 4, .. }
        ));
    }

    #[test]
    fn local_search_request_round_trip_preserves_scope_and_limit() {
        let request = RequestEnvelope::new(
            RequestMethod::SearchLocal {
                query: "guidance fixture".into(),
                scope: Some(Scope {
                    host_id: Some("host-local".into()),
                    provider_id: Some("codex".into()),
                    project_id: Some("project-a".into()),
                }),
                limit: 7,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode local search"))
                .expect("decode local search");
        assert!(matches!(
            decoded.method,
            RequestMethod::SearchLocal { limit: 7, .. }
        ));
    }

    #[test]
    fn event_replay_request_round_trip_preserves_cursor() {
        let request = RequestEnvelope::new(
            RequestMethod::ReplayEvents {
                after_event_id: Some("event-1".into()),
                limit: 32,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode event request"))
                .expect("decode event request");
        assert!(matches!(
            decoded.method,
            RequestMethod::ReplayEvents {
                after_event_id: Some(_),
                limit: 32
            }
        ));
    }

    #[test]
    fn event_ack_request_round_trip_preserves_ids() {
        let request = RequestEnvelope::new(
            RequestMethod::AckEvents {
                event_ids: vec!["event-1".into(), "event-2".into()],
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode ack request"))
                .expect("decode ack request");
        assert!(matches!(
            decoded.method,
            RequestMethod::AckEvents { event_ids } if event_ids.len() == 2
        ));
    }

    #[test]
    fn event_subscription_round_trip_preserves_wait_and_cursor() {
        let request = RequestEnvelope::new(
            RequestMethod::SubscribeEvents {
                after_event_id: Some("event-1".into()),
                limit: 16,
                wait_ms: 250,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode subscription"))
                .expect("decode subscription");
        assert!(matches!(
            decoded.method,
            RequestMethod::SubscribeEvents {
                after_event_id: Some(_),
                limit: 16,
                wait_ms: 250
            }
        ));
    }

    #[test]
    fn runtime_thread_request_round_trip_preserves_scope_and_pagination() {
        let request = RequestEnvelope::new(
            RequestMethod::RuntimeListThreads {
                provider_id: "codex".into(),
                scope: Some(Scope::host("host-runtime")),
                cursor: Some("page-2".into()),
                limit: 32,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode runtime request"))
                .expect("decode runtime request");
        assert!(matches!(
            decoded.method,
            RequestMethod::RuntimeListThreads {
                provider_id,
                scope: Some(Scope { host_id: Some(host_id), .. }),
                cursor: Some(cursor),
                limit: 32
            } if provider_id == "codex" && host_id == "host-runtime" && cursor == "page-2"
        ));
    }

    #[test]
    fn runtime_thread_read_round_trip_preserves_target_scope() {
        let request = RequestEnvelope::new(
            RequestMethod::RuntimeReadThread {
                provider_id: "codex".into(),
                scope: Some(Scope::host("host-runtime")),
                thread_id: "thread-42".into(),
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode runtime read"))
                .expect("decode runtime read");
        assert!(matches!(
            decoded.method,
            RequestMethod::RuntimeReadThread {
                provider_id,
                scope: Some(Scope { host_id: Some(host_id), .. }),
                thread_id
            } if provider_id == "codex" && host_id == "host-runtime" && thread_id == "thread-42"
        ));
    }

    #[test]
    fn event_stream_request_round_trip_preserves_flow_control() {
        let request = RequestEnvelope::new(
            RequestMethod::OpenEventStream {
                after_event_id: Some("event-1".into()),
                scope: Some(Scope {
                    host_id: Some("host-runtime".into()),
                    provider_id: Some("codex".into()),
                    project_id: None,
                }),
                max_in_flight: 32,
                heartbeat_ms: 1_000,
            },
            Some("token".into()),
        );
        let decoded: RequestEnvelope =
            serde_json::from_str(&serde_json::to_string(&request).expect("encode stream request"))
                .expect("decode stream request");
        assert!(matches!(
            decoded.method,
            RequestMethod::OpenEventStream {
                after_event_id: Some(_),
                scope: Some(Scope { provider_id: Some(provider_id), .. }),
                max_in_flight: 32,
                heartbeat_ms: 1_000
            } if provider_id == "codex"
        ));
    }
}
