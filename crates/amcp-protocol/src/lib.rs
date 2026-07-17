use amcp_domain::{CollectionBatch, Scope};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub protocol_version: u32,
    pub request_id: String,
    pub correlation_id: String,
    pub method: RequestMethod,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum RequestMethod {
    Register {
        controller_id: String,
    },
    Heartbeat,
    Capabilities,
    Collect {
        scope: Option<Scope>,
        cursor: Option<String>,
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
    },
    Heartbeat {
        healthy: bool,
    },
    Capabilities {
        platform: String,
        providers: Vec<String>,
    },
    Collection(CollectionBatch),
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
            method,
            token,
        }
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
}
