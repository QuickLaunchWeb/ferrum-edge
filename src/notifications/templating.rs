//! `${var}` template substitution for notification payloads.
//!
//! Simple, allocation-conscious renderer used by the generic webhook channel
//! and any other caller that needs operator-supplied templates with bounded
//! variable injection.
//!
//! Syntax:
//! - `${name}` — replaced with the value of `name` from the supplied map.
//! - `$$`     — literal `$`.
//! - Unknown variables are left as `${name}` in the output (so operators can
//!   spot typos in real payloads). [`validate_template`] reports them up front
//!   at plugin construction time.
//!
//! Errors:
//! - Unbalanced `${` (no matching `}`) is a hard error from
//!   [`render_template`] / [`validate_template`].
//! - An unsupported escape (e.g. `$x` where `x` is not `$` or `{`) is left
//!   as-is — `$` followed by a non-special character is common in templates.

use std::collections::{HashMap, HashSet};

/// Render `template` by substituting `${var}` placeholders from `vars`.
///
/// Returns `Err` only on unbalanced `${`. Unknown variable names are passed
/// through unmodified so misconfigured templates remain auditable.
pub fn render_template(template: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'$' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            if next == b'{' {
                let close = template[i + 2..].find('}').ok_or_else(|| {
                    format!("template: unbalanced '${{' starting at byte offset {}", i)
                })?;
                let var_start = i + 2;
                let var_end = var_start + close;
                let name = &template[var_start..var_end];
                if let Some(value) = vars.get(name) {
                    out.push_str(value);
                } else {
                    out.push_str("${");
                    out.push_str(name);
                    out.push('}');
                }
                i = var_end + 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    Ok(out)
}

/// Inspect `template` and return the set of variable names it references
/// (excluding any in `known`). Useful for warning the operator about typos
/// at plugin construction time without aborting startup.
///
/// Returns `Err` on unbalanced `${`.
#[allow(dead_code)] // Public helper for callers that want a one-shot
// "did the operator typo a placeholder?" check at construction.
pub fn unknown_variables(template: &str, known: &HashSet<&str>) -> Result<Vec<String>, String> {
    let mut unknown = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'$' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'$' {
                i += 2;
                continue;
            }
            if next == b'{' {
                let close = template[i + 2..].find('}').ok_or_else(|| {
                    format!("template: unbalanced '${{' starting at byte offset {}", i)
                })?;
                let var_start = i + 2;
                let var_end = var_start + close;
                let name = &template[var_start..var_end];
                if !known.contains(name) && !unknown.iter().any(|n: &String| n == name) {
                    unknown.push(name.to_string());
                }
                i = var_end + 1;
                continue;
            }
        }
        i += 1;
    }
    Ok(unknown)
}

/// Dry-run `template` against `known` variable names: returns `Ok(())` when
/// the template is well-formed (balanced braces). Unknown variables are NOT
/// errors — collect them with [`unknown_variables`] and warn the operator.
pub fn validate_template(template: &str) -> Result<(), String> {
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'$' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'$' {
                i += 2;
                continue;
            }
            if next == b'{' {
                let close = template[i + 2..].find('}').ok_or_else(|| {
                    format!("template: unbalanced '${{' starting at byte offset {}", i)
                })?;
                i = i + 2 + close + 1;
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}
