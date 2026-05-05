use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NonceKey {
    node_id: String,
    type_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NonceState {
    last_issued_nonce: String,
    last_acked_nonce: Option<String>,
    last_version: String,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    Nacked { message: String },
    MissingNonce,
    StaleNonce { expected: String, actual: String },
    UnknownNonce,
    VersionDrift { expected: String, actual: String },
}

/// Per `(node_id, type_url)` ACK/NACK nonce machine.
///
/// xDS ACK state is intentionally not global: a NACK for RDS must not poison
/// an LDS update on the same node, and two nodes must never share nonce state.
#[derive(Default)]
pub struct XdsNonceTracker {
    states: DashMap<NonceKey, NonceState>,
    counter: AtomicU64,
}

impl XdsNonceTracker {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
            counter: AtomicU64::new(0),
        }
    }

    pub fn issue_nonce(&self, node_id: &str, type_url: &str, version: &str) -> String {
        let sequence = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let nonce = format!("{node_id}|{type_url}|{version}|{sequence}");
        let key = NonceKey {
            node_id: node_id.to_string(),
            type_url: type_url.to_string(),
        };
        let previous_ack = self
            .states
            .get(&key)
            .and_then(|state| state.last_acked_nonce.clone());
        self.states.insert(
            key,
            NonceState {
                last_issued_nonce: nonce.clone(),
                last_acked_nonce: previous_ack,
                last_version: version.to_string(),
                last_error: None,
            },
        );
        nonce
    }

    pub fn record_response(
        &self,
        node_id: &str,
        type_url: &str,
        response_nonce: &str,
        version_info: &str,
        error_message: Option<&str>,
    ) -> AckOutcome {
        if response_nonce.is_empty() {
            return AckOutcome::MissingNonce;
        }

        let key = NonceKey {
            node_id: node_id.to_string(),
            type_url: type_url.to_string(),
        };
        let Some(mut state) = self.states.get_mut(&key) else {
            return AckOutcome::UnknownNonce;
        };

        if state.last_issued_nonce != response_nonce {
            return AckOutcome::StaleNonce {
                expected: state.last_issued_nonce.clone(),
                actual: response_nonce.to_string(),
            };
        }

        if let Some(message) = error_message {
            let message = message.to_string();
            state.last_error = Some(message.clone());
            return AckOutcome::Nacked { message };
        }

        if !version_info.is_empty() && version_info != state.last_version {
            return AckOutcome::VersionDrift {
                expected: state.last_version.clone(),
                actual: version_info.to_string(),
            };
        }

        state.last_acked_nonce = Some(response_nonce.to_string());
        state.last_error = None;
        AckOutcome::Acked
    }

    pub fn last_error(&self, node_id: &str, type_url: &str) -> Option<String> {
        self.states
            .get(&NonceKey {
                node_id: node_id.to_string(),
                type_url: type_url.to_string(),
            })
            .and_then(|state| state.last_error.clone())
    }

    pub fn remove_node(&self, node_id: &str) {
        self.states.retain(|key, _| key.node_id != node_id);
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}
