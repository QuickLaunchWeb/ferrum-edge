# Plugin Execution Order

Ferrum Gateway executes plugins in a deterministic order based on two dimensions: **lifecycle phases** and **priority within each phase**.

## Lifecycle Phases

Every request passes through six phases in strict order. Each phase has a specific purpose, and plugins only run in the phases they implement:

```
Request In
    │
    ▼
┌─────────────────────────┐
│ 1. on_request_received  │  Pre-processing: CORS preflight
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 2. authenticate         │  Identity verification: JWT, OAuth2, API key, Basic
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3. authorize            │  Access control, consumer rate limiting
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 4. before_proxy         │  Request transformation before backend call
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Backend   │  Actual HTTP call to upstream
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 5. after_proxy          │  Response transformation, CORS headers
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 6. log                  │  Logging & observability (fire-and-forget)
└─────────────────────────┘
```

Any plugin can short-circuit the pipeline by returning a `Reject` result. For example, CORS returns a `204` preflight response in phase 1 without ever reaching authentication. Rate limiting returns `429` in the authorize phase (phase 3) after the consumer is identified.

## Priority Bands

Within each lifecycle phase, plugins are sorted by **priority** (lower number runs first). Priority is intrinsic to each plugin — it is not user-configurable. Plugins at the same priority have no guaranteed relative order.

Priority bands are spaced with gaps so future plugins can slot in without renumbering:

| Band | Priority Range | Purpose | Plugins |
|------|---------------|---------|---------|
| **Early** | 0–99 | Pre-processing that must run before auth | `cors` (10) |
| **AuthN** | 100–199 | Authentication / identity verification | `oauth2_auth` (100), `jwt_auth` (110), `key_auth` (120), `basic_auth` (130) |
| **AuthZ** | 200–299 | Authorization & post-auth enforcement | `access_control` (200), `rate_limiting` (299) |
| **Transform** | 300–399 | Request modification before backend call | `request_transformer` (300) |
| **Response** | 400–499 | Response modification after backend call | `response_transformer` (400) |
| **Custom** | 500 | Default for unrecognized/custom plugins | _(future plugins)_ |
| **Logging** | 900–999 | Observability, runs outside the hot path | `stdout_logging` (900), `http_logging` (910), `transaction_debugger` (920) |

## Complete Execution Order

Given all built-in plugins enabled, the execution order is:

| # | Plugin | Priority | Active Phases |
|---|--------|----------|---------------|
| 1 | `cors` | 10 | on_request_received, after_proxy |
| 2 | `oauth2_auth` | 100 | authenticate |
| 3 | `jwt_auth` | 110 | authenticate |
| 4 | `key_auth` | 120 | authenticate |
| 5 | `basic_auth` | 130 | authenticate |
| 6 | `access_control` | 200 | authorize |
| 7 | `rate_limiting` | 299 | on_request_received (IP mode), authorize (consumer mode) |
| 8 | `request_transformer` | 300 | before_proxy |
| 9 | `response_transformer` | 400 | after_proxy |
| 10 | `stdout_logging` | 900 | log |
| 11 | `http_logging` | 910 | log |
| 12 | `transaction_debugger` | 920 | on_request_received, after_proxy, log |

## Why This Order Matters

### CORS runs first (priority 10)

Browser preflight (`OPTIONS`) requests must be answered before authentication. If an auth plugin ran first, it would reject the preflight with `401` and the browser would never complete the CORS handshake. CORS at priority 10 ensures preflight responses are returned immediately.

### Authentication before authorization (100s before 200s)

Authentication plugins identify *who* the caller is (setting `ctx.identified_consumer`). Authorization plugins like `access_control` then decide *whether* that consumer is allowed. Running auth first is required — ACL checks are meaningless without a verified identity.

### Rate limiting runs after auth (priority 299)

Rate limiting sits at the end of the AuthZ band (priority 299) so it can enforce limits by **authenticated consumer identity**, not just by IP address. When `limit_by: "consumer"`, the plugin needs `ctx.identified_consumer` which is only available after the authenticate phase.

**Dual-phase behavior:**
- `limit_by: "ip"` — enforces IP-based limits in `on_request_received` (phase 1, before auth). This protects auth endpoints from brute-force attacks.
- `limit_by: "consumer"` — enforces consumer-based limits in `authorize` (phase 3, after auth). If no consumer is identified (unauthenticated request), falls back to IP-based keying.

### Transforms after auth (300+)

Request transformers run after authentication and authorization, so they only modify requests that are already permitted. This prevents wasted transformation work on requests that will be rejected.

### Logging runs last (900+)

Logging plugins run in phase 6 (`log`) which is fire-and-forget after the response is sent to the client. They are outside the hot path and do not affect request latency. Their relative ordering within the logging band (900–920) does not impact behavior.

## Adding a New Plugin

When implementing a new plugin, choose a priority that places it in the correct band:

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }

    fn priority(&self) -> u16 {
        // Pick a value in the appropriate band:
        // 0-99: pre-processing (before auth)
        // 100-199: authentication
        // 200-299: authorization / post-auth enforcement
        // 300-399: request transformation
        // 400-499: response transformation
        // 900-999: logging
        50  // Example: runs after CORS (10), before auth (100+)
    }
}
```

Add the constant to `src/plugins/mod.rs` in the `priority` module for discoverability:

```rust
pub mod priority {
    pub const MY_PLUGIN: u16 = 50;
    // ...
}
```

The default priority is `500` (the Custom band), which runs after all transforms but before logging. This is a safe default for plugins that don't have strong ordering requirements.
