use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single auditable agent action event.
/// This is the core schema — every tool call produces one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActionEvent {
    // Identity
    pub event_id: String,
    pub agent_id: String,
    pub agent_version: String,
    pub authorized_by: String,
    pub session_id: String,

    // Action
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub tool_server: String,
    pub input_hash: String,
    pub output_hash: String,

    // Policy
    pub policy_decision: String,
    pub policy_rule: String,
    pub latency_ms: i64,

    // Tamper-evidence chain
    pub prev_hash: String,
    pub event_hash: String,
    pub signature: String,
    pub proxy_key_id: String,
}

impl AgentActionEvent {
    /// Compute the SHA-256 hash of this event (excluding event_hash and signature fields).
    pub fn compute_hash(&self) -> String {
        let hashable = serde_json::json!({
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "authorized_by": self.authorized_by,
            "session_id": self.session_id,
            "timestamp": self.timestamp.to_rfc3339(),
            "tool_name": self.tool_name,
            "tool_server": self.tool_server,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "policy_decision": self.policy_decision,
            "policy_rule": self.policy_rule,
            "latency_ms": self.latency_ms,
            "prev_hash": self.prev_hash,
        });

        let canonical = serde_json::to_string(&hashable).expect("serialization cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Hash arbitrary data with SHA-256, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
