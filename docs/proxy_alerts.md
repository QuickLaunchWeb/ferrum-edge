# proxy_alerts plugin

Watches proxy traffic and dispatches notifications when configured rules breach their thresholds. Hooks into the `log()` and `on_stream_disconnect()` lifecycle phases (priority `9250`, after every logging sink). Works across all protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP, UDP/DTLS).

The channel layer (Slack, Microsoft Teams, Discord, generic Webhook) lives in [`docs/notifications.md`](notifications.md) and is reusable from any subsystem.

## When to use it

This plugin is a lightweight in-gateway alerting surface — useful when you want each proxy/team to be paged on its own anomalies without having to set up separate Alertmanager / Datadog monitors. It is **not** a substitute for a real metrics-based alerting platform; use `prometheus_metrics` + a dedicated alerting stack for everything else.

## Configuration

```jsonc
{
  "enabled": true,
  "default_cooldown_seconds": 300,
  "default_min_request_count": 50,
  "default_window_seconds": 60,
  "default_resolved_window_seconds": 300,
  "max_concurrent_dispatches": 8,

  "quiet_hours_utc": [
    { "from": "23:00", "to": "06:00", "weekdays": [0, 6] }
  ],

  "channels": {
    "ops_slack": {
      "type": "slack",
      "webhook_url": "https://hooks.slack.com/services/T/B/X",
      "channel_override": "#alerts-prod",
      "username": "ferrum-edge",
      "icon_emoji": ":rotating_light:"
    },
    "ops_teams":   { "type": "teams",   "webhook_url": "https://outlook.office.com/webhook/..." },
    "ops_discord": { "type": "discord", "webhook_url": "https://discord.com/api/webhooks/..." },
    "pagerduty_v2": {
      "type": "webhook",
      "url": "https://events.pagerduty.com/v2/enqueue",
      "method": "POST",
      "headers": { "Content-Type": "application/json" },
      "body_template": "{\"routing_key\":\"$ROUTING_KEY\",\"event_action\":\"${event_action}\",\"payload\":{\"summary\":\"${rule_name}: ${reason}\",\"source\":\"${proxy_name}\",\"severity\":\"${severity}\"}}"
    }
  },

  "rules": [
    {
      "name": "proxy_5xx_spike",
      "enabled": true,
      "type": "error_rate",
      "status_codes": [500, 501, 502, 503, 504],
      "window_seconds": 60,
      "threshold_percent": 5.0,
      "min_request_count": 100,
      "channels": ["ops_slack", "pagerduty_v2"],
      "cooldown_seconds": 300,
      "recovery": { "resolved_window_seconds": 300 },
      "severity": "high"
    }
  ]
}
```

See [docs/notifications.md](notifications.md#channel-json-schema) for the full per-channel field reference (including `*_env` secret-resolver forms).

### Top-level options

| Field | Default | Notes |
|-------|---------|-------|
| `enabled` | `true` | Master runtime switch. |
| `default_cooldown_seconds` | `300` | Per-rule fallback if `cooldown_seconds` is omitted. Applied per `(rule, channel)` so a low-volume audit channel can throttle independently of a high-volume Slack channel. |
| `default_min_request_count` | `50` | Per-rule fallback for `min_request_count` (used by `error_rate` and `latency_percentile`). Avoids noisy alerts from low-traffic windows. |
| `default_window_seconds` | `60` | Per-rule fallback for `window_seconds`. |
| `default_resolved_window_seconds` | `300` | Per-rule fallback for `recovery.resolved_window_seconds`. |
| `max_concurrent_dispatches` | `8` | Bounded-concurrency semaphore for outbound notifications. When exhausted, alerts are dropped with a `warn!` rather than queued. |
| `quiet_hours_utc` | `[]` | Optional UTC time-of-day windows where `Trigger` alerts are suppressed (without consuming the cooldown). `Resolve` events still fire so operators don't miss recovery during off hours. |

### Quiet hours

```json
"quiet_hours_utc": [
  { "from": "23:00", "to": "06:00", "weekdays": [0, 6] }
]
```

- `from` / `to` are `HH:MM` (UTC). `from > to` wraps past midnight.
- `weekdays` is `0..=6` with `0 = Sunday` … `6 = Saturday`. Empty/omitted = every day.

### Rule types

#### `error_rate`

```jsonc
{
  "name": "proxy_5xx_spike",
  "type": "error_rate",
  "status_codes": [500, 501, 502, 503, 504],
  "window_seconds": 60,
  "threshold_percent": 5.0,
  "min_request_count": 100,
  "channels": ["ops_slack"]
}
```

Fires when ≥ `threshold_percent` of the last `window_seconds` of HTTP requests had a status in `status_codes`, provided the window saw at least `min_request_count` requests. HTTP-only.

#### `status_code_count`

```jsonc
{
  "name": "auth_failures_spike",
  "type": "status_code_count",
  "status_codes": [401, 403],
  "window_seconds": 120,
  "threshold_count": 200,
  "channels": ["secops_teams"]
}
```

Fires when at least `threshold_count` requests with a status in `status_codes` occurred within `window_seconds`. HTTP-only. Useful for security signals (4xx auth-failure spikes).

#### `latency_percentile`

```jsonc
{
  "name": "p95_backend_latency",
  "type": "latency_percentile",
  "metric": "backend_total_ms",
  "percentile": 95,
  "threshold_ms": 1500,
  "window_seconds": 60,
  "min_request_count": 50,
  "channels": ["ops_slack"]
}
```

`metric` is one of:
- `backend_total_ms` — HTTP only; `latency_backend_total_ms` from the transaction summary
- `backend_ttfb_ms` — HTTP only
- `total_ms` — HTTP only
- `stream_duration_ms` — TCP/UDP stream summaries

Percentiles are estimated with fixed log-scale buckets (boundaries 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000 ms). Returns the upper bound of the bucket containing the percentile rank — a slight conservative overestimate, which biases toward firing slightly later than the true value. Adequate for alerting; not a substitute for a precise histogram. Negative latency values (sentinel `-1.0` used during streaming responses) are ignored.

#### `error_class`

```jsonc
{
  "name": "backend_connect_errors",
  "type": "error_class",
  "classes": ["connection_refused", "connection_timeout", "dns_lookup_error", "tls_error"],
  "window_seconds": 60,
  "threshold_count": 25,
  "channels": ["ops_slack"]
}
```

Counts transactions whose `error_class` (or HTTP `body_error_class`) matches one of `classes`. Applies to both HTTP/gRPC/WebSocket and stream protocols (TCP/UDP) — both share the same `ErrorClass` enum (`src/retry.rs`). See [docs/error_classification.md](error_classification.md) for the full enum.

#### `stream_disconnect_cause`

```jsonc
{
  "name": "backend_disconnect_burst",
  "type": "stream_disconnect_cause",
  "causes": ["backend_error", "recv_error"],
  "window_seconds": 60,
  "threshold_count": 50,
  "channels": ["infra_discord"]
}
```

Counts stream disconnects whose `disconnect_cause` matches one of `causes`. Stream-only (TCP / UDP / DTLS / WebSocket). Causes: `idle_timeout`, `recv_error`, `backend_error`, `graceful_shutdown`.

### Cooldown and recovery

- **Cooldown** is per `(rule, channel)`. After a `Trigger` dispatch on channel X, subsequent triggers from the same rule to channel X are suppressed for `cooldown_seconds`. Other channels remain free to fire.
- **Recovery** is opt-in via `recovery: { "resolved_window_seconds": N }`. After a rule transitions Active → Recovering (window dropped below threshold), the rule must remain below threshold for `resolved_window_seconds` before a single `Resolve` event is dispatched. A re-breach inside the window quietly returns to Active without re-firing.
- `Resolve` dispatches are NOT subject to cooldown — they are always one-shot.
- Quiet hours suppress `Trigger` events without consuming the cooldown, so the next eligible window re-evaluates fresh. `Resolve` events still fire during quiet hours.

### Webhook template variables

In addition to the [generic notification template variables](notifications.md#template-variables-provided-by-the-notifications-layer), the proxy_alerts plugin exposes these to the webhook channel `body_template`:

| Variable | Value |
|----------|-------|
| `${rule_name}` | The rule's `name`. |
| `${proxy_id}` | Proxy id from the transaction summary. |
| `${proxy_name}` | Human-friendly proxy name. |
| `${namespace}` | Namespace from the transaction summary. |
| `${fired_at}` | RFC 3339 timestamp. |
| `${observed}` | Pre-formatted observed value, e.g. `"6.7%"`, `"1873ms"`, `"204"`. |
| `${threshold}` | Pre-formatted threshold value. |
| `${sample_count}` | Total samples in the window. |
| `${window_seconds}` | Rule window. |
| `${severity}` | `info` / `low` / `medium` / `high` / `critical`. |
| `${reason}` | Concise summary string suitable for a notification body. |
| `${event_action}` | `trigger` or `resolve`. |

Use `$$` for a literal `$`. Unknown placeholders are passed through unchanged.

## Scopes

`proxy_alerts` may be configured at any scope:
- `proxy` — the rule observes only that proxy's traffic.
- `proxy_group` — shared instance observes traffic across the group; per-proxy bucket keys ensure the alert identifies the offending proxy.
- `global` — observes traffic across every proxy; per-proxy bucket keys still apply (a global "5xx > 5%" rule alerts per offending proxy, never as one mashed aggregate).

## Operational notes

- Plugin state (sliding-window counters, cooldown timestamps, recovery state machines) is per-instance and reset on config reload. A reload during an active anomaly may re-fire alerts immediately — this is acceptable today; cross-reload persistence is a v2 follow-up.
- `*_env` channel fields read `std::env::var()` at construction so the gateway's secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`) handles materialization without ever placing secrets in DB/file config.
- Sensitive metadata (`Authorization`, `Cookie`, etc.) is auto-redacted at `TransactionSummary` serialize time per the standard logger redaction. Notification template variables only expose named scalars (`${observed}`, `${rule_name}`, …) — there is no raw `${metadata}` hook, so the redaction layer cannot be bypassed via a template.
- When the dispatch semaphore (`max_concurrent_dispatches`) is exhausted, alerts are dropped with a `warn!` rather than queued. Operators investigating a backpressure event should grep `plugin=proxy_alerts` in their logs.
