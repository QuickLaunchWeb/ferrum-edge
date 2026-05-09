//! Fault Injection Plugin
//!
//! Injects controlled failures (delays and aborts) into request processing
//! for chaos engineering workflows. Both fault types are probabilistic —
//! each has a `percentage` field (0.0–100.0) checked per-request.
//!
//! Runs in the `authorize` phase so it fires after authentication and
//! rate limiting but before request transformation and backend dispatch.
//!
//! ## Config
//!
//! ```json
//! {
//!   "abort": {
//!     "status_code": 503,
//!     "percentage": 50.0,
//!     "grpc_status": 14,
//!     "body": "service unavailable"
//!   },
//!   "delay": {
//!     "duration_ms": 2000,
//!     "percentage": 25.0
//!   }
//! }
//! ```
//!
//! At least one of `abort` or `delay` must be present. When both are
//! configured and both trigger on the same request, the delay executes
//! first, then the abort fires.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};

static FAULT_COUNTER: AtomicU64 = AtomicU64::new(0);

struct AbortFault {
    status_code: u16,
    percentage: f64,
    body: String,
}

struct DelayFault {
    duration_ms: u64,
    percentage: f64,
}

pub struct FaultInjectionPlugin {
    abort: Option<AbortFault>,
    delay: Option<DelayFault>,
}

impl FaultInjectionPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or("fault_injection: config must be an object")?;

        let abort = match obj.get("abort") {
            Some(Value::Object(abort_obj)) => {
                let status_code = abort_obj
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: abort.status_code is required and must be an integer",
                    )?;

                if !(100..=599).contains(&status_code) {
                    return Err(format!(
                        "fault_injection: abort.status_code must be 100-599, got {status_code}"
                    ));
                }

                let percentage = parse_percentage(abort_obj.get("percentage"), "abort.percentage")?;

                if let Some(grpc_val) = abort_obj.get("grpc_status") {
                    let code = grpc_val
                        .as_u64()
                        .ok_or("fault_injection: abort.grpc_status must be an integer")?;
                    if code > 16 {
                        return Err(format!(
                            "fault_injection: abort.grpc_status must be 0-16, got {code}"
                        ));
                    }
                }

                let body = match abort_obj.get("body") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(_) => {
                        return Err("fault_injection: abort.body must be a string".to_string());
                    }
                };

                Some(AbortFault {
                    status_code: status_code as u16,
                    percentage,
                    body,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'abort' must be an object".to_string()),
        };

        let delay = match obj.get("delay") {
            Some(Value::Object(delay_obj)) => {
                let duration_ms = delay_obj
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: delay.duration_ms is required and must be a positive integer",
                    )?;

                if duration_ms == 0 {
                    return Err(
                        "fault_injection: delay.duration_ms must be greater than 0".to_string()
                    );
                }

                let percentage = parse_percentage(delay_obj.get("percentage"), "delay.percentage")?;

                Some(DelayFault {
                    duration_ms,
                    percentage,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'delay' must be an object".to_string()),
        };

        if abort.is_none() && delay.is_none() {
            return Err(
                "fault_injection: at least one of 'abort' or 'delay' must be configured"
                    .to_string(),
            );
        }

        Ok(Self { abort, delay })
    }
}

fn parse_percentage(val: Option<&Value>, field_name: &str) -> Result<f64, String> {
    let pct = match val {
        Some(Value::Number(n)) => n
            .as_f64()
            .ok_or_else(|| format!("fault_injection: {field_name} must be a number"))?,
        Some(_) => {
            return Err(format!("fault_injection: {field_name} must be a number"));
        }
        None => {
            return Err(format!("fault_injection: {field_name} is required"));
        }
    };

    if !(0.0..=100.0).contains(&pct) {
        return Err(format!(
            "fault_injection: {field_name} must be 0.0-100.0, got {pct}"
        ));
    }

    Ok(pct)
}

fn should_trigger(percentage: f64) -> bool {
    if percentage <= 0.0 {
        return false;
    }
    if percentage >= 100.0 {
        return true;
    }
    let counter = FAULT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let hash = counter.wrapping_mul(0x9E3779B97F4A7C15) >> 54;
    (hash as f64 / 1024.0) * 100.0 < percentage
}

#[async_trait]
impl Plugin for FaultInjectionPlugin {
    fn name(&self) -> &str {
        "fault_injection"
    }

    fn priority(&self) -> u16 {
        super::priority::FAULT_INJECTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let delay_triggered = self
            .delay
            .as_ref()
            .is_some_and(|d| should_trigger(d.percentage));
        let abort_triggered = self
            .abort
            .as_ref()
            .is_some_and(|a| should_trigger(a.percentage));

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.metadata
            .insert("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.metadata
                .insert("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.metadata
                .insert("fault_type".to_string(), fault_type.to_string());
            ctx.metadata
                .insert("fault_abort_status".to_string(), a.status_code.to_string());

            return PluginResult::Reject {
                status_code: a.status_code,
                body: a.body.clone(),
                headers: HashMap::new(),
            };
        }

        ctx.metadata
            .insert("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let delay_triggered = self
            .delay
            .as_ref()
            .is_some_and(|d| should_trigger(d.percentage));
        let abort_triggered = self
            .abort
            .as_ref()
            .is_some_and(|a| should_trigger(a.percentage));

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.insert_metadata("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.insert_metadata("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.insert_metadata("fault_type".to_string(), fault_type.to_string());
            ctx.insert_metadata("fault_abort_status".to_string(), a.status_code.to_string());

            return PluginResult::Reject {
                status_code: a.status_code,
                body: a.body.clone(),
                headers: HashMap::new(),
            };
        }

        ctx.insert_metadata("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }
}
