use serde_json::Value;
use std::collections::HashMap;

use crate::plugins::PluginResult;

pub trait SizeLimiter {
    fn plugin_name(&self) -> &'static str;

    fn max_size_bytes(&self) -> u128;

    fn is_enabled(&self) -> bool {
        self.max_size_bytes() > 0
    }

    fn exceeds_limit(&self, size: u128) -> bool {
        size > self.max_size_bytes()
    }
}

pub fn required_positive_u64(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<u64, String> {
    let value = config[field].as_u64().unwrap_or(0);

    if value == 0 {
        Err(format!(
            "{plugin_name}: '{field}' is required and must be greater than zero"
        ))
    } else {
        Ok(value)
    }
}

pub fn required_positive_usize(
    config: &Value,
    field: &'static str,
    plugin_name: &'static str,
) -> Result<usize, String> {
    let value = config[field].as_u64().unwrap_or(0) as usize;

    if value == 0 {
        Err(format!(
            "{plugin_name}: '{field}' is required and must be greater than zero"
        ))
    } else {
        Ok(value)
    }
}

pub fn content_length_over_limit(
    headers: &HashMap<String, String>,
    max_bytes: u128,
) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|len| (*len as u128) > max_bytes)
}

pub fn rejection_body(error: &str, limit: u128) -> String {
    format!(r#"{{"error":"{error}","limit":{limit}}}"#)
}

pub fn reject_with_limit(status_code: u16, error: &'static str, limit: u128) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body: rejection_body(error, limit),
        headers: HashMap::new(),
    }
}
