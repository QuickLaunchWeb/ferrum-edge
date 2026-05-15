//! Reusable, plugin-agnostic notification infrastructure.
//!
//! Provides:
//! - [`Notification`] — generic notification payload (title, body, severity,
//!   k/v fields, lifecycle action). No alert-specific fields.
//! - [`NotificationChannel`] — Slack / Teams / Discord / generic Webhook
//!   transport implementations sharing a uniform `dispatch` surface.
//! - [`channels::parse_channels`] — JSON-driven config parser used by any
//!   subsystem that wants to expose a `channels: { name -> def }` block to
//!   operators.
//! - [`templating`] — `${var}` substitution with dry-run validation.
//! - [`dispatch`] — bounded-concurrency fire-and-forget fan-out.
//!
//! The first consumer is the `proxy_alerts` plugin
//! (`src/plugins/proxy_alerts/`); future consumers (overload manager, mesh
//! policy enforcement, custom plugins) should depend on this module rather
//! than re-implementing channel formatters.

pub mod channels;
pub mod dispatch;
pub mod notification;
pub mod templating;

// Re-exports kept for ergonomic external use (tests, future non-plugin
// callers, custom plugins). Suppress dead-code warnings on the binary
// build where these surfaces aren't currently called from main.rs.
#[allow(unused_imports)]
pub use channels::{NotificationChannel, parse_channels};
#[allow(unused_imports)]
pub use dispatch::dispatch;
#[allow(unused_imports)]
pub use notification::{EventAction, Notification, NotificationField, Severity};
