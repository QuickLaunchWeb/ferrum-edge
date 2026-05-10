//! Mesh authorization policy evaluation.
//!
//! This is the Layer 5 policy core used by the future `mesh_authz` plugin.
//! It evaluates the Layer 2 `MeshPolicy` model without changing the plugin
//! trait or proxy hot path.
//! Path matching is intentionally literal; callers must pass already-normalized
//! request paths when they want dot-segment, slash, or percent-decoding policy.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{
    ConditionMatch, MeshRule, PolicyAction, PrincipalMatch, RequestMatch,
    normalize_mesh_policy_header_map,
};
use crate::modes::mesh::slice::MeshSlice;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuthzRequest {
    pub source_principal: Option<SpiffeId>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshAuthzDecision {
    Allow,
    Deny { policy: String },
    Audit { policy: String },
}

pub fn evaluate_mesh_authorization(
    slice: &MeshSlice,
    request: &MeshAuthzRequest,
) -> MeshAuthzDecision {
    let mut saw_allow = false;
    let mut matched_allow = false;
    let mut matched_audit = None;

    for policy in &slice.mesh_policies {
        for rule in &policy.rules {
            if !rule_matches(rule, request) {
                continue;
            }
            match rule.action {
                PolicyAction::Deny => {
                    return MeshAuthzDecision::Deny {
                        policy: policy.name.clone(),
                    };
                }
                PolicyAction::Allow => {
                    saw_allow = true;
                    matched_allow = true;
                }
                PolicyAction::Audit => {
                    matched_audit.get_or_insert_with(|| policy.name.clone());
                }
            }
        }
        if policy
            .rules
            .iter()
            .any(|rule| rule.action == PolicyAction::Allow)
        {
            saw_allow = true;
        }
    }

    if saw_allow && !matched_allow {
        return MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string(),
        };
    }
    if let Some(policy) = matched_audit {
        return MeshAuthzDecision::Audit { policy };
    }
    MeshAuthzDecision::Allow
}

fn rule_matches(rule: &MeshRule, request: &MeshAuthzRequest) -> bool {
    if rule.never_matches {
        return false;
    }
    matches_principals(&rule.from, request)
        && matches_requests(&rule.to, request)
        && matches_conditions(&rule.when, request)
}

fn matches_principals(matches: &[PrincipalMatch], request: &MeshAuthzRequest) -> bool {
    if matches.is_empty() {
        return true;
    }
    matches
        .iter()
        .any(|principal| principal_match(principal, request.source_principal.as_ref()))
}

fn principal_match(match_: &PrincipalMatch, source: Option<&SpiffeId>) -> bool {
    let Some(source) = source else {
        return false;
    };
    if let Some(trust_domain) = match_.trust_domain.as_ref()
        && source.trust_domain() != trust_domain
    {
        return false;
    }
    if let Some(pattern) = match_.spiffe_id_pattern.as_ref()
        && !wildcard_match(pattern, source.as_str())
    {
        return false;
    }
    if let Some(pattern) = match_.namespace_pattern.as_ref()
        && !extract_namespace(source.as_str()).is_some_and(|ns| wildcard_match(pattern, ns))
    {
        return false;
    }
    true
}

fn matches_requests(matches: &[RequestMatch], request: &MeshAuthzRequest) -> bool {
    if matches.is_empty() {
        return true;
    }
    matches.iter().any(|match_| request_match(match_, request))
}

fn request_match(match_: &RequestMatch, request: &MeshAuthzRequest) -> bool {
    if !match_.methods.is_empty()
        && !request.method.as_ref().is_some_and(|method| {
            match_
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
        })
    {
        return false;
    }
    if !match_.paths.is_empty()
        && !request.path.as_ref().is_some_and(|path| {
            match_
                .paths
                .iter()
                .any(|pattern| wildcard_match(pattern, path))
        })
    {
        return false;
    }
    let normalized_host = request.host.as_deref().and_then(normalize_match_host);
    if !match_.hosts.is_empty()
        && !normalized_host.as_ref().is_some_and(|host| {
            match_
                .hosts
                .iter()
                .any(|pattern| normalized_host_matches(pattern, host))
        })
    {
        return false;
    }
    if (!match_.ports.is_empty() || !match_.port_patterns.is_empty())
        && !request.port.is_some_and(|port| {
            match_.ports.contains(&port)
                || match_
                    .port_patterns
                    .iter()
                    .any(|pattern| port_pattern_matches(pattern, port))
        })
    {
        return false;
    }
    for (name, pattern) in &match_.headers {
        let Some(value) = request_header_value(&request.headers, name) else {
            return false;
        };
        if !wildcard_match(pattern, value) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedHost {
    name: String,
    authority: String,
}

fn normalized_host_matches(pattern: &str, host: &NormalizedHost) -> bool {
    // Patterns are pre-normalized at config-load time
    // (see `crate::modes::mesh::config::normalize_request_match_host_pattern`),
    // so the hot path can match directly against the request authority's
    // bare name (no port) and full authority (host[:port]) forms.
    wildcard_match(pattern, &host.name) || wildcard_match(pattern, &host.authority)
}

fn request_header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            headers.get(&name.to_ascii_lowercase()).map(String::as_str)
        } else {
            None
        }
    })
}

fn normalize_match_host(host: &str) -> Option<NormalizedHost> {
    let host = host.trim();
    if host.is_empty() || host.contains('@') {
        return None;
    }

    if host.starts_with('[') {
        let end = host.find(']')?;
        let literal = &host[..=end];
        let suffix = &host[end + 1..];
        if suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(is_valid_authority_port)
        {
            let name = literal.to_ascii_lowercase();
            let authority = if suffix.is_empty() {
                name.clone()
            } else {
                format!("{name}{suffix}")
            };
            return Some(NormalizedHost { name, authority });
        }
        return None;
    }

    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && is_valid_authority_port(port) => {
            let name = normalize_hostname(name)?;
            Some(NormalizedHost {
                authority: format!("{name}:{port}"),
                name,
            })
        }
        Some(_) => None,
        None => normalize_hostname(host).map(|name| NormalizedHost {
            authority: name.clone(),
            name,
        }),
    }
}

/// Direct port-pattern match without allocating a port string.
///
/// Istio + Ferrum direct-config validators only allow three pattern shapes
/// (`*`, `<digits>*`, `*<digits>`), so a `starts_with` / `ends_with` /
/// equality check on the digit form of `port` is enough — there is no need
/// to invoke the general glob matcher. Writing the port into a 5-byte stack
/// buffer (max `u16::MAX = 65535`) avoids the per-request `String` allocation
/// the previous implementation paid for every `port_patterns` check.
fn port_pattern_matches(pattern: &str, port: u16) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut buf = [0u8; 5];
    let port_str = format_u16(&mut buf, port);
    if let Some(prefix) = pattern.strip_suffix('*') {
        return port_str.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return port_str.ends_with(suffix);
    }
    pattern == port_str
}

fn format_u16(buf: &mut [u8; 5], port: u16) -> &str {
    let mut idx = 5;
    let mut value = port;
    if value == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while value > 0 {
            idx -= 1;
            buf[idx] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    // SAFETY: only ASCII digits written above, which are valid UTF-8.
    std::str::from_utf8(&buf[idx..]).expect("ASCII digits are valid UTF-8")
}

fn normalize_hostname(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_valid_authority_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn matches_conditions(matches: &[ConditionMatch], request: &MeshAuthzRequest) -> bool {
    matches.iter().all(|match_| {
        let value = request.attributes.get(&match_.key).map(String::as_str);
        if !match_.values.is_empty()
            && !value.is_some_and(|value| match_.values.iter().any(|v| v == value))
        {
            return false;
        }
        if !match_.not_values.is_empty()
            && value.is_some_and(|value| match_.not_values.iter().any(|v| v == value))
        {
            return false;
        }
        true
    })
}

fn extract_namespace(spiffe_id: &str) -> Option<&str> {
    let mut segments = spiffe_id.split('/');
    while let Some(segment) = segments.next() {
        if segment == "ns" {
            return segments.next();
        }
    }
    None
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == value;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .peekable();
    if parts.peek().is_none() {
        return true;
    }

    let mut value_pos = 0usize;
    let mut value_limit = value.len();

    if anchored_start {
        let Some(first) = parts.next() else {
            return true;
        };
        if !value.starts_with(first) {
            return false;
        }
        value_pos = first.len();
    }

    if anchored_end {
        let Some(last) = pattern.rsplit('*').find(|part| !part.is_empty()) else {
            return true;
        };
        if !value.ends_with(last) {
            return false;
        }
        let suffix_start = value.len() - last.len();
        if suffix_start < value_pos {
            return false;
        }
        value_limit = suffix_start;
    }

    while let Some(part) = parts.next() {
        if anchored_end && parts.peek().is_none() {
            break;
        }
        let Some(index) = value[value_pos..value_limit].find(part) else {
            return false;
        };
        value_pos += index + part.len();
    }

    true
}

pub(crate) fn normalize_mesh_policy_header_names(
    policy: &mut crate::modes::mesh::config::MeshPolicy,
) {
    for rule in &mut policy.rules {
        for request in &mut rule.to {
            normalize_mesh_policy_header_map(&mut request.headers);
        }
    }
}

pub(crate) fn mesh_policy_has_header_rules(
    policy: &crate::modes::mesh::config::MeshPolicy,
) -> bool {
    policy
        .rules
        .iter()
        .flat_map(|rule| &rule.to)
        .any(|request| !request.headers.is_empty())
}

pub(crate) fn mesh_policies_have_header_rules(
    policies: &[crate::modes::mesh::config::MeshPolicy],
) -> bool {
    policies.iter().any(mesh_policy_has_header_rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{
        MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
        WorkloadSelector,
    };

    fn policy(name: &str, action: PolicyAction, from: Vec<PrincipalMatch>) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector::default(),
            },
            rules: vec![MeshRule {
                from,
                to: Vec::new(),
                when: Vec::new(),
                never_matches: false,
                action,
            }],
        }
    }

    fn request(source: &str) -> MeshAuthzRequest {
        MeshAuthzRequest {
            source_principal: Some(SpiffeId::new(source).expect("valid spiffe id")),
            ..MeshAuthzRequest::default()
        }
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let slice = MeshSlice {
            mesh_policies: vec![
                policy("allow-all", PolicyAction::Allow, Vec::new()),
                policy("deny-all", PolicyAction::Deny, Vec::new()),
            ],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "deny-all".to_string()
            }
        );
    }

    #[test]
    fn allow_policy_implies_default_deny_when_no_rule_matches() {
        let slice = MeshSlice {
            mesh_policies: vec![policy(
                "allow-client",
                PolicyAction::Allow,
                vec![PrincipalMatch {
                    spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".into()),
                    namespace_pattern: None,
                    trust_domain: None,
                }],
            )],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/other")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_checks_method_path_host_port_and_headers() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-http".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        methods: vec!["GET".to_string()],
                        paths: vec!["/v1/*".to_string()],
                        hosts: vec!["api.*".to_string()],
                        headers: BTreeMap::from([("x-tenant".to_string(), "prod-*".to_string())])
                            .into_iter()
                            .collect(),
                        ports: vec![8080],
                        port_patterns: Vec::new(),
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let mut headers = BTreeMap::new();
        headers.insert("x-tenant".to_string(), "prod-a".to_string());
        let request = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/v1/items".to_string()),
            host: Some("api.default".to_string()),
            port: Some(8080),
            headers,
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn wildcard_match_respects_suffix_anchor_with_repeated_literals() {
        assert!(wildcard_match("*foo", "barfoofoo"));
        assert!(wildcard_match(
            "spiffe://*/sa/admin",
            "spiffe://cluster.local/ns/sa/sa/admin"
        ));
        assert!(!wildcard_match("*foo", "barfoobar"));
        assert!(!wildcard_match("foo*foo", "foo"));
    }

    #[test]
    fn wildcard_match_handles_degenerate_patterns_without_panics() {
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "other"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("**", ""));
        assert!(wildcard_match("***", "anything"));
        assert!(wildcard_match("a**b", "ab"));
        assert!(wildcard_match("a**b", "axxb"));
        assert!(!wildcard_match("a**b", "ac"));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "anything"));
        assert!(!wildcard_match("*suffix", ""));
    }

    #[test]
    fn normalize_mesh_policy_header_names_lowercases_keys_once() {
        let mut policy = MeshPolicy {
            name: "headers".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: BTreeMap::from([("X-Tenant".to_string(), "prod".to_string())])
                        .into_iter()
                        .collect(),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                action: PolicyAction::Allow,
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert!(mesh_policy_has_header_rules(&policy));
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
        assert!(!policy.rules[0].to[0].headers.contains_key("X-Tenant"));
    }

    #[test]
    fn normalize_mesh_policy_header_names_preserves_case_collisions() {
        let mut policy = MeshPolicy {
            name: "headers".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: BTreeMap::from([
                        ("X-Tenant".to_string(), "prod".to_string()),
                        ("x-tenant".to_string(), "dev".to_string()),
                    ])
                    .into_iter()
                    .collect(),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                action: PolicyAction::Allow,
                never_matches: false,
            }],
        };

        normalize_mesh_policy_header_names(&mut policy);

        assert!(policy.rules[0].to[0].headers.contains_key("X-Tenant"));
        assert!(policy.rules[0].to[0].headers.contains_key("x-tenant"));
    }

    #[test]
    fn request_match_normalizes_host_authority_before_matching() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("Api.Default:443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_normalizes_bracketed_ipv6_authority() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["[2001:db8::1]".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("[2001:DB8::1]:443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_preserves_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:8443".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("Api.Default:8443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_rejects_different_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:8443".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("api.default:9443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn never_match_allow_rule_triggers_implicit_deny_without_matching() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-nothing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    never_matches: true,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(
                &slice,
                &request("spiffe://cluster.local/ns/default/sa/client")
            ),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_supports_wildcard_authority_port_for_host_policy() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-any-port-host".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["api.default:*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("api.default:8443".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_match_combines_explicit_ports_and_port_patterns() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-mixed-ports".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        ports: vec![80],
                        port_patterns: vec!["8*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };

        let request_80 = MeshAuthzRequest {
            port: Some(80),
            ..MeshAuthzRequest::default()
        };
        let request_8443 = MeshAuthzRequest {
            port: Some(8443),
            ..MeshAuthzRequest::default()
        };
        let request_9000 = MeshAuthzRequest {
            port: Some(9000),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_80),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_8443),
            MeshAuthzDecision::Allow
        );
        assert_eq!(
            evaluate_mesh_authorization(&slice, &request_9000),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn request_match_normalises_trailing_dot_host_pattern_at_config_load() {
        let mut config = crate::modes::mesh::config::MeshConfig {
            mesh_policies: vec![MeshPolicy {
                name: "allow-trailing-dot".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        hosts: vec!["Example.COM.".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..crate::modes::mesh::config::MeshConfig::default()
        };
        config.normalize();
        let slice = MeshSlice {
            mesh_policies: config.mesh_policies,
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            host: Some("example.com".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn port_pattern_matches_handles_all_three_pattern_shapes() {
        assert!(port_pattern_matches("*", 80));
        assert!(port_pattern_matches("*", 65535));
        assert!(port_pattern_matches("8*", 80));
        assert!(port_pattern_matches("8*", 8443));
        assert!(!port_pattern_matches("8*", 9080));
        assert!(port_pattern_matches("*443", 443));
        assert!(port_pattern_matches("*443", 8443));
        assert!(!port_pattern_matches("*443", 8080));
        assert!(port_pattern_matches("80", 80));
        assert!(!port_pattern_matches("80", 8080));
    }

    #[test]
    fn request_match_checks_istio_port_patterns() {
        let slice = MeshSlice {
            mesh_policies: vec![MeshPolicy {
                name: "allow-port-pattern".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::MeshWide,
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: vec![RequestMatch {
                        port_patterns: vec!["8*".to_string()],
                        ..RequestMatch::default()
                    }],
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            }],
            ..MeshSlice::default()
        };
        let request = MeshAuthzRequest {
            port: Some(8443),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &request),
            MeshAuthzDecision::Allow
        );
    }
}
