use amcp_domain::{
    ApprovalEnvelope, ArtifactRecord, ArtifactRef, ChangeReceipt, ChangeRequest, ChangeSet,
    CollectionBatch, HostIdentity, Scope,
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
        capabilities: Vec<String>,
        agent_version: String,
    },
    Collection(CollectionBatch),
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
}
