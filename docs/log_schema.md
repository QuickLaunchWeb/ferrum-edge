# Customizing Transaction Log Output

Operators can shape the JSON / line-protocol output of every logging plugin
(`stdout_logging`, `http_logging`, `tcp_logging`, `udp_logging`,
`ws_logging`, `kafka_logging`, `loki_logging`, `statsd_logging`,
`access_log`) through a per-plugin `schema:` block. This lets you rename
keys, drop fields, reorder output, add static stamping, and inject a few
derived fields without forking the gateway.

The customization layer is purely a serialization-time wrapper. Existing
deployments are unaffected — when no `schema` / `schema_ref` is set, the
plugin emits native field names exactly as before.

## Quick Start

```yaml
plugin_configs:
  - id: stdout-customized
    plugin_name: stdout_logging
    scope: global
    config:
      schema:
        rename:
          proxy_id: route_id
          response_status_code: status
        omit: [request_user_agent, latency_plugin_external_io_ms]
        static_fields:
          env: production
          service: api-gateway
        derived_fields:
          - { name: status_class, kind: status_class }
          - { name: outcome, kind: outcome }
        metadata:
          mode: flatten
          prefix: "meta_"
        timestamp_format: epoch_ms
```

Output (HTTP request, redacted for brevity):

```json
{
  "namespace": "ferrum",
  "timestamp_received": 1778500800000,
  "client_ip": "10.0.0.1",
  "route_id": "things-api",
  "status": 200,
  "latency_total_ms": 12.5,
  "env": "production",
  "service": "api-gateway",
  "status_class": "2xx",
  "outcome": "ok",
  "meta_trace_id": "abc-123",
  "meta_authorization": "[REDACTED]"
}
```

## Where Schemas Live

Two equivalent forms:

### 1. Inline

Embed the schema directly under each logging plugin's `config:`. Simplest
when only one or two sinks need customization, or when each sink wants a
different schema.

### 2. Named (DRY)

Define a `transaction_log_schema` plugin once, reference it from any
number of logging plugins via `schema_ref:`:

```yaml
plugin_configs:
  - id: shared-log-schema
    plugin_name: transaction_log_schema
    scope: global             # required — schemas are process-global
    config:
      schemas:
        splunk_cim:
          summary_type: both
          rename: { proxy_id: route_id }
          metadata: { mode: flatten, prefix: "fields." }

  - id: my-stdout
    plugin_name: stdout_logging
    scope: global
    config:
      schema_ref: splunk_cim

  - id: my-loki
    plugin_name: loki_logging
    scope: global
    config:
      endpoint_url: http://loki:3100/loki/api/v1/push
      schema_ref: splunk_cim
```

The gateway loader processes `transaction_log_schema` plugins **before**
any plugin that uses `schema_ref:`, so reload ordering is automatic. The
named-schemas registry is fully replaced on every config reload — renamed
or removed schemas do not leak.

`schema:` and `schema_ref:` are mutually exclusive on a single plugin.

## Schema Fields

| Key | Type | Default | Description |
|---|---|---|---|
| `summary_type` | `http` / `stream` / `both` | `both` | Limits the schema to one summary type. Other summary types fall back to native output. |
| `omit` | `[String]` | `[]` | Native field names to drop. |
| `rename` | `{old: new}` | `{}` | Map native field names to output keys. |
| `order` | `[String]` | – | Explicit output order. May contain `"*"` once as a wildcard for "all unlisted entries in natural order." Without `"*"`, every field must be listed. |
| `static_fields` | `{key: value}` | `{}` | Literal JSON values injected at top level. Keys matching sensitive substrings (`authorization`, `cookie`, `password`, `token`, …) are rejected. |
| `derived_fields` | `[{name, kind}]` | `[]` | Computed values; see [Derived Kinds](#derived-kinds). |
| `metadata` | object | `{mode: nested}` | How to render the `metadata` map: `nested` / `omit` / `flatten`. |
| `timestamp_format` | `rfc3339` / `epoch_ms` / `epoch_s` | `rfc3339` | Conversion for timestamp string fields. Parse failures fall back to the raw string. |

### Derived Kinds

| `kind` | HTTP / WS summary | Stream summary |
|---|---|---|
| `status_class` | `"1xx"` / `"2xx"` / `"3xx"` / `"4xx"` / `"5xx"` / `"other"` from `response_status_code` | always `"none"` |
| `backend_host` | hostname from `backend_target_url` (port stripped, IPv6 brackets honored) | hostname from `backend_target` |
| `summary_kind` | `"http"` | `"stream"` |
| `outcome` | `"error"` when `response_status_code >= 500` or any error_class is set; else `"ok"` | `"error"` when `connection_error`, `error_class`, or `disconnect_cause: backend_error` is set; else `"ok"` |

### Metadata Modes

- **`nested`** (default): emits `metadata: { ... }` as a single nested
  object. Sensitive keys are redacted to `"[REDACTED]"`.
- **`omit`**: drops the metadata entirely.
- **`flatten`**: promotes each metadata entry to a top-level key.
  Accepts:
  - `prefix:` (optional string prepended to every flattened key, e.g.
    `"meta_"` → `meta_trace_id`).
  - `on_collision:` — `skip` (default; existing key wins) or
    `overwrite` (metadata entry replaces — implemented as a duplicate
    key, which most JSON parsers resolve as "last wins").

Sensitive keys (`authorization`, `cookie`, credential tokens, etc.) are
**always** redacted, on every path — `nested`, `flatten`, even when the
operator renames the outer `metadata` field via `rename:`. There is no
way to bypass redaction through the schema.

## Per-Plugin Notes

| Plugin | Schema-aware output | Notes |
|---|---|---|
| `stdout_logging` | Full | Emits via `tracing::info!` target `access_log`. |
| `access_log` | Full | Same shape; target `mesh_access_log`. Filter (`status_code_min/max`, `min_latency_ms`, `errors_only`) runs before schema application. |
| `http_logging` | Full | Batched JSON array. |
| `tcp_logging` | Full | NDJSON, one line per entry. |
| `udp_logging` | Full | Batched JSON array per UDP datagram. Operators should keep per-summary size under MTU. |
| `ws_logging` | Full for HTTP / stream summaries; WebSocket disconnect entries are out of scope in v1 | A future release may extend the schema to `WsDisconnectLogEntry`. |
| `kafka_logging` | Full | One JSON message per summary. Partition key (`client_ip` / `proxy_id`) still reads typed fields, so partition keys are NOT affected by `rename:`. |
| `loki_logging` | Full | Schema-customized JSON appears inside the Loki log line. Loki **labels** (`build_http_labels` / `build_stream_labels`) keep reading typed fields, so labels are NOT affected by `rename:`. |
| `statsd_logging` | Tag rename / omit only | Static / derived / flatten / timestamp parts of a schema are no-ops here (statsd is line protocol, not JSON). The schema's `rename` and `omit` operate on the native field names backing the statsd tags. The supported mappings are: HTTP — `http_method`↔`method`, `response_status_code`↔`status`, `proxy_id`↔`proxy`. Stream — `protocol`↔`protocol`, `proxy_id`↔`proxy`, `disconnect_cause`↔`cause`, `disconnect_direction`↔`direction`. Computed statsd tags without native-field backing (`status_class`, `error`) are always emitted with their default names — `omit` and `rename` have no effect on them since they are derived at format time, not read from a summary field. |

`prometheus_metrics`, `api_chargeback`, `transaction_debugger` reject
`schema:` and `schema_ref:` at construction time. Prometheus exposes
metrics with label names baked into the time-series store; chargeback is
an in-memory accounting plugin; transaction_debugger emits debug-only
traces. None of them serialize summaries for shipping, so customization
doesn't apply.

## Validation

`SummarySchema::compile` rejects (with a clear error and Levenshtein
suggestion where applicable):

1. Unknown field names in `omit`, `rename`, `order`, derived `from`.
2. Renaming and omitting the same field.
3. Duplicate output keys (e.g. renaming two fields onto the same target).
4. `order` referencing unknown output keys.
5. `order` without `"*"` missing some fields.
6. `order` containing more than one `"*"`.
7. `summary_type: http` referring to stream-only fields, and vice versa.
8. `static_fields` keys that match sensitive substrings.
9. `static_fields` values containing nested keys with sensitive substrings.
10. `static_fields` values that are `null`.
11. `metadata.prefix` containing control characters.
12. Unknown derived `kind`.
13. Unknown top-level schema keys (typo guard).
14. `schema:` and `schema_ref:` both present on the same plugin.
15. `schema_ref:` pointing at an unregistered name.

For named schemas:

16. `transaction_log_schema` with `scope: proxy` or `scope: proxy_group`
    is rejected by `validate_plugin_references`.
17. Two `transaction_log_schema` plugins in the same config defining the
    same name.

## Performance

- Schema parsing happens once at plugin construction. The compiled
  `Vec<FieldSpec>` lives behind an `Arc` and is shared cheaply.
- At log time, `SchemaView` walks the compiled vec and forwards each
  field through the typed summary. No `serde_json::Value` is built; no
  per-request `HashMap` is allocated. Default-configured plugins (no
  schema) go through the identical pre-existing serde path with zero
  added cost.
- The named-schemas registry is read-only on the hot path; `schema_ref`
  resolution is a one-shot `Arc::clone` at plugin construction.
- The existing hot-path guard `if !plugins.is_empty()` (proxy.rs) still
  decides whether to build the summary at all. No change.

## Operator Cookbook

### Splunk-style "Common Information Model" output

```yaml
schema:
  summary_type: both
  rename:
    timestamp_received: time
    timestamp_connected: time
    proxy_id: route
    response_status_code: status
    client_ip: src
    backend_target_url: dest
    latency_total_ms: duration
  derived_fields:
    - { name: status_class, kind: status_class }
    - { name: outcome,      kind: outcome      }
  metadata: { mode: flatten, prefix: "fields." }
  timestamp_format: epoch_ms
```

### Datadog logs

```yaml
schema:
  summary_type: both
  static_fields:
    service: ferrum-edge
    ddsource: ferrum-edge
    env: production
  derived_fields:
    - { name: status_class, kind: status_class }
  rename:
    namespace: tenant
    response_status_code: http.status_code
    http_method: http.method
    backend_target_url: http.url
    request_path: http.url_details.path
  timestamp_format: rfc3339
```

### Strict JSON shape (minimal allowlist)

```yaml
schema:
  summary_type: http
  order:
    - timestamp_received
    - http_method
    - request_path
    - response_status_code
    - latency_total_ms
    - "*"
  omit:
    - latency_plugin_execution_ms
    - latency_plugin_external_io_ms
    - latency_gateway_overhead_ms
    - latency_gateway_processing_ms
    - latency_backend_ttfb_ms
    - latency_backend_total_ms
    - request_user_agent
    - mirror
```

### statsd tag rename for a Datadog migration

```yaml
schema:
  summary_type: http
  rename:
    http_method: verb
    proxy_id: route_id
    response_status_code: code
  omit:
    - proxy_id   # also valid if you want to drop the proxy tag entirely
```

Output line: `ferrum.request.count:1|c|#verb:GET,code:200,status_class:2xx,route_id:things-api`.

## Extending in Custom Plugins

Custom plugins authored under `custom_plugins/` can opt into the same
behavior by importing:

```rust
use ferrum_edge::plugins::utils::log_schema::{
    SchemaView, SummaryLogEntryView, SummarySchema, resolve_schema,
};
```

Store `Option<Arc<SummarySchema>>` on the plugin struct; call
`resolve_schema(config, "my_plugin")` in `new()`; wrap each
`serde_json::to_string(summary)` call site in a `match self.schema { ... }`
branch identical to the built-in plugins.
