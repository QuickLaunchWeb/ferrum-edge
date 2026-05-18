//! Shared RTDS gate parsing for transformer plugins.
//!
//! `request_transformer` and `response_transformer` each maintain their
//! own gate map (different key prefix, independent state) but share the
//! same scan-and-collect logic over the [`MeshRuntimeOverlay`]. Keeping
//! the parser in one place avoids forking the
//! "strip prefix, strip suffix, accept bools only" recipe.
//!
//! Out-of-spec values (`Number`, `String`, `FractionalPercent`) are
//! silently skipped — gate semantics are strictly boolean.

use std::collections::HashMap;

use crate::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};

/// Walk every `<prefix><scope><suffix>` key in `overlay` and insert the
/// bool value into `dest`. Keys with empty scope or non-bool values are
/// dropped so the resulting map is always safe to consult directly.
pub fn collect_gates(
    overlay: &MeshRuntimeOverlay,
    prefix: &str,
    suffix: &str,
    dest: &mut HashMap<String, bool>,
) {
    for (raw_key, value) in &overlay.fields {
        let Some(rest) = raw_key.strip_prefix(prefix) else {
            continue;
        };
        let Some(scope) = rest.strip_suffix(suffix) else {
            continue;
        };
        if scope.is_empty() {
            continue;
        }
        let RuntimeValue::Bool(enabled) = value else {
            continue;
        };
        dest.insert(scope.to_string(), *enabled);
    }
}
