#![allow(dead_code)]

/// Phase B shell for an xDS-backed mesh config consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsClientConfig {
    pub cp_url: String,
    pub node_id: String,
    pub namespace: String,
}

#[derive(Debug, Clone)]
pub struct XdsConfigConsumer {
    config: XdsClientConfig,
}

impl XdsConfigConsumer {
    pub fn new(config: XdsClientConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &XdsClientConfig {
        &self.config
    }
}
