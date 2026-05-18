//! Static registry of native field names for [`TransactionSummary`] and
//! [`StreamTransactionSummary`].
//!
//! The schema customization layer validates operator-supplied field names
//! (in `omit`, `rename`, `order`, derived `from`) against these tables.
//! Drift between this registry and the structs is caught by the integration
//! test in `tests/integration/log_schema_registry_tests.rs`.

use super::SummaryType;

/// Metadata for a single native field on a summary struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMeta {
    pub name: &'static str,
    /// `true` when the field is an RFC3339 timestamp string subject to
    /// [`super::TimestampFormat`] conversion at serialize time.
    pub is_timestamp: bool,
}

/// Fields on [`crate::plugins::TransactionSummary`] in declaration order.
pub const HTTP_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_received",
        is_timestamp: true,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "http_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_path",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_status_code",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_processing_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_ttfb_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_execution_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_external_io_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_overhead_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_user_agent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_streamed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_disconnected",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_completed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "mirror",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Fields on [`crate::plugins::StreamTransactionSummary`] in declaration order.
pub const STREAM_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "connection_error",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_cause",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_connected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "timestamp_disconnected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "sni_hostname",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Look up a field by name for the given summary type.
///
/// For [`SummaryType::Both`] the field must exist on either struct.
pub fn lookup(summary_type: SummaryType, name: &str) -> Option<FieldMeta> {
    match summary_type {
        SummaryType::Http => HTTP_FIELDS.iter().find(|f| f.name == name).copied(),
        SummaryType::Stream => STREAM_FIELDS.iter().find(|f| f.name == name).copied(),
        SummaryType::Both => HTTP_FIELDS
            .iter()
            .chain(STREAM_FIELDS.iter())
            .find(|f| f.name == name)
            .copied(),
    }
}

/// All field names visible for the given summary type, in declaration order,
/// deduplicated for `Both`.
pub fn fields_for(summary_type: SummaryType) -> Vec<FieldMeta> {
    match summary_type {
        SummaryType::Http => HTTP_FIELDS.to_vec(),
        SummaryType::Stream => STREAM_FIELDS.to_vec(),
        SummaryType::Both => {
            let mut out: Vec<FieldMeta> = HTTP_FIELDS.to_vec();
            for stream in STREAM_FIELDS {
                if !out.iter().any(|f| f.name == stream.name) {
                    out.push(*stream);
                }
            }
            out
        }
    }
}

/// Suggest the closest known field name to a misspelling, when the
/// Levenshtein distance is small enough to be useful (≤ 2 for short names,
/// ≤ 3 for long names).
pub fn levenshtein_suggest(summary_type: SummaryType, name: &str) -> Option<&'static str> {
    let candidates: &[&[FieldMeta]] = match summary_type {
        SummaryType::Http => &[HTTP_FIELDS],
        SummaryType::Stream => &[STREAM_FIELDS],
        SummaryType::Both => &[HTTP_FIELDS, STREAM_FIELDS],
    };
    let mut best: Option<(usize, &'static str)> = None;
    for set in candidates {
        for field in *set {
            let d = levenshtein(name, field.name);
            if best.map(|(b, _)| d < b).unwrap_or(true) {
                best = Some((d, field.name));
            }
        }
    }
    let threshold = if name.len() > 8 { 3 } else { 2 };
    best.filter(|(d, _)| *d <= threshold).map(|(_, n)| n)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_http_field() {
        assert_eq!(
            lookup(SummaryType::Http, "proxy_id"),
            Some(FieldMeta {
                name: "proxy_id",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_known_stream_field() {
        assert_eq!(
            lookup(SummaryType::Stream, "bytes_sent"),
            Some(FieldMeta {
                name: "bytes_sent",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup(SummaryType::Http, "not_a_field").is_none());
    }

    #[test]
    fn lookup_http_field_not_on_stream() {
        // request_path is only on TransactionSummary.
        assert!(lookup(SummaryType::Stream, "request_path").is_none());
        assert!(lookup(SummaryType::Http, "request_path").is_some());
        assert!(lookup(SummaryType::Both, "request_path").is_some());
    }

    #[test]
    fn lookup_stream_field_not_on_http() {
        // protocol is only on StreamTransactionSummary.
        assert!(lookup(SummaryType::Http, "protocol").is_none());
        assert!(lookup(SummaryType::Stream, "protocol").is_some());
        assert!(lookup(SummaryType::Both, "protocol").is_some());
    }

    #[test]
    fn timestamp_flag_set_correctly() {
        let f = lookup(SummaryType::Http, "timestamp_received").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, "timestamp_connected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, "timestamp_disconnected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Http, "client_ip").unwrap();
        assert!(!f.is_timestamp);
    }

    #[test]
    fn fields_for_both_unions_and_dedupes() {
        let all = fields_for(SummaryType::Both);
        // namespace, proxy_id, client_ip etc. exist on both — should appear once.
        let namespaces = all.iter().filter(|f| f.name == "namespace").count();
        assert_eq!(namespaces, 1);
        let proxy_ids = all.iter().filter(|f| f.name == "proxy_id").count();
        assert_eq!(proxy_ids, 1);
        // Total = HTTP_FIELDS.len() + (stream fields not in http).
        let stream_only = STREAM_FIELDS
            .iter()
            .filter(|s| !HTTP_FIELDS.iter().any(|h| h.name == s.name))
            .count();
        assert_eq!(all.len(), HTTP_FIELDS.len() + stream_only);
    }

    #[test]
    fn levenshtein_suggests_close_match() {
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, "proxy_idd"),
            Some("proxy_id")
        );
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, "lateny_total_ms"),
            Some("latency_total_ms")
        );
    }

    #[test]
    fn levenshtein_skips_far_matches() {
        assert!(levenshtein_suggest(SummaryType::Http, "completely_unrelated").is_none());
    }

    #[test]
    fn http_fields_match_expected_count() {
        // Drift sentinel — the integration test in
        // tests/integration/log_schema_registry_tests.rs verifies the
        // actual serde output keys match these. This is the cheap
        // unit-test guard against accidental deletions.
        assert_eq!(HTTP_FIELDS.len(), 29);
    }

    #[test]
    fn stream_fields_match_expected_count() {
        assert_eq!(STREAM_FIELDS.len(), 21);
    }
}
