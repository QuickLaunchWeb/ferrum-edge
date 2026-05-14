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
use std::fmt::Write as _;

/// Render `template` by substituting `${var}` placeholders from `vars`.
///
/// Returns `Err` only on unbalanced `${`. Unknown variable names are passed
/// through unmodified so misconfigured templates remain auditable.
pub fn render_template(template: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    render_template_with(template, vars, |value, out| out.push_str(value))
}

/// Render `template` while escaping substituted values for placement inside
/// JSON string literals.
///
/// This intentionally emits the escaped string content without surrounding
/// quotes: a template fragment like `"summary":"${reason}"` remains the
/// operator-authored JSON shape while values containing `"`, `\`, newlines, or
/// other control characters cannot break the JSON body.
pub fn render_template_json_string_escaped(
    template: &str,
    vars: &HashMap<String, String>,
) -> Result<String, String> {
    render_template_with(template, vars, push_json_string_content)
}

fn render_template_with<F>(
    template: &str,
    vars: &HashMap<String, String>,
    mut push_value: F,
) -> Result<String, String>
where
    F: FnMut(&str, &mut String),
{
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            out.push('$');
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            let name = &after_open[..close];
            if let Some(value) = vars.get(name) {
                push_value(value, &mut out);
            } else {
                out.push_str("${");
                out.push_str(name);
                out.push('}');
            }
            i += 2 + close + 1;
            continue;
        }
        let ch = rest
            .chars()
            .next()
            .expect("i is always on a character boundary and below len");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

fn push_json_string_content(value: &str, out: &mut String) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                write!(out, "\\u{:04x}", c as u32).expect("writing to String cannot fail");
            }
            c => out.push(c),
        }
    }
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
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            let name = &after_open[..close];
            if !known.contains(name) && !unknown.iter().any(|n: &String| n == name) {
                unknown.push(name.to_string());
            }
            i += 2 + close + 1;
            continue;
        }
        let ch = rest
            .chars()
            .next()
            .expect("i is always on a character boundary and below len");
        i += ch.len_utf8();
    }
    Ok(unknown)
}

/// Dry-run `template` against `known` variable names: returns `Ok(())` when
/// the template is well-formed (balanced braces). Unknown variables are NOT
/// errors — collect them with [`unknown_variables`] and warn the operator.
pub fn validate_template(template: &str) -> Result<(), String> {
    let mut i = 0;
    while i < template.len() {
        let rest = &template[i..];
        if rest.starts_with("$$") {
            i += 2;
            continue;
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            let close = after_open.find('}').ok_or_else(|| {
                format!("template: unbalanced '${{' starting at byte offset {}", i)
            })?;
            i += 2 + close + 1;
            continue;
        }
        let ch = rest
            .chars()
            .next()
            .expect("i is always on a character boundary and below len");
        i += ch.len_utf8();
    }
    Ok(())
}
