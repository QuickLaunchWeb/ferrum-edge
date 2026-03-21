//! Retry logic for failed backend requests.
//!
//! Wraps backend requests with configurable retry policies including
//! max retries, retryable status codes/methods, and backoff strategies.

use crate::config::types::{BackoffStrategy, RetryConfig};
use std::time::Duration;

/// Determine if a request should be retried.
pub fn should_retry(config: &RetryConfig, method: &str, status_code: u16, attempt: u32) -> bool {
    if attempt >= config.max_retries {
        return false;
    }

    if !config
        .retryable_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method))
    {
        return false;
    }

    config.retryable_status_codes.contains(&status_code)
}

/// Calculate the delay before the next retry attempt.
pub fn retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    match &config.backoff {
        BackoffStrategy::Fixed { delay_ms } => Duration::from_millis(*delay_ms),
        BackoffStrategy::Exponential { base_ms, max_ms } => {
            let delay = base_ms.saturating_mul(2u64.saturating_pow(attempt));
            Duration::from_millis(delay.min(*max_ms))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RetryConfig {
        RetryConfig::default()
    }

    #[test]
    fn test_should_retry_on_retryable_status() {
        let config = default_config();
        assert!(should_retry(&config, "GET", 502, 0));
        assert!(should_retry(&config, "GET", 503, 0));
        assert!(should_retry(&config, "GET", 504, 0));
    }

    #[test]
    fn test_should_not_retry_on_success() {
        let config = default_config();
        assert!(!should_retry(&config, "GET", 200, 0));
        assert!(!should_retry(&config, "GET", 404, 0));
    }

    #[test]
    fn test_should_not_retry_post_by_default() {
        let config = default_config();
        assert!(!should_retry(&config, "POST", 502, 0));
        assert!(!should_retry(&config, "PATCH", 502, 0));
    }

    #[test]
    fn test_should_retry_put_and_delete() {
        let config = default_config();
        assert!(should_retry(&config, "PUT", 503, 0));
        assert!(should_retry(&config, "DELETE", 503, 0));
    }

    #[test]
    fn test_max_retries_exceeded() {
        let config = RetryConfig {
            max_retries: 2,
            ..default_config()
        };
        assert!(should_retry(&config, "GET", 502, 0));
        assert!(should_retry(&config, "GET", 502, 1));
        assert!(!should_retry(&config, "GET", 502, 2));
    }

    #[test]
    fn test_fixed_backoff() {
        let config = RetryConfig {
            backoff: BackoffStrategy::Fixed { delay_ms: 100 },
            ..default_config()
        };
        assert_eq!(retry_delay(&config, 0), Duration::from_millis(100));
        assert_eq!(retry_delay(&config, 5), Duration::from_millis(100));
    }

    #[test]
    fn test_exponential_backoff() {
        let config = RetryConfig {
            backoff: BackoffStrategy::Exponential {
                base_ms: 100,
                max_ms: 5000,
            },
            ..default_config()
        };
        assert_eq!(retry_delay(&config, 0), Duration::from_millis(100));
        assert_eq!(retry_delay(&config, 1), Duration::from_millis(200));
        assert_eq!(retry_delay(&config, 2), Duration::from_millis(400));
        assert_eq!(retry_delay(&config, 3), Duration::from_millis(800));
        // Should cap at max
        assert_eq!(retry_delay(&config, 10), Duration::from_millis(5000));
    }

    #[test]
    fn test_case_insensitive_method_matching() {
        let config = default_config();
        assert!(should_retry(&config, "get", 502, 0));
        assert!(should_retry(&config, "Get", 502, 0));
    }
}
