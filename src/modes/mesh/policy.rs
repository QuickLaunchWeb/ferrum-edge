//! Mesh authorization policy evaluation.
//!
//! This is the Layer 5 policy core used by the future `mesh_authz` plugin.
//! It evaluates the Layer 2 `MeshPolicy` model without changing the plugin
//! trait or proxy hot path.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::config::mesh::{ConditionMatch, MeshRule, PolicyAction, PrincipalMatch, RequestMatch};
use crate::identity::SpiffeId;
use crate::xds::slice::MeshSlice;

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
    if !match_.hosts.is_empty()
        && !request.host.as_ref().is_some_and(|host| {
            match_
                .hosts
                .iter()
                .any(|pattern| wildcard_match(pattern, host))
        })
    {
        return false;
    }
    if !match_.ports.is_empty()
        && !request
            .port
            .is_some_and(|port| match_.ports.contains(&port))
    {
        return false;
    }
    for (name, pattern) in &match_.headers {
        let key = name.to_ascii_lowercase();
        let Some(value) = request.headers.get(&key).map(String::as_str) else {
            return false;
        };
        if !wildcard_match(pattern, value) {
            return false;
        }
    }
    true
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
    let mut remaining = value;
    let mut parts = pattern.split('*').peekable();
    let first = parts.next().unwrap_or_default();
    if !remaining.starts_with(first) {
        return false;
    }
    remaining = &remaining[first.len()..];

    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
        if parts.peek().is_none() && !pattern.ends_with('*') && !remaining.is_empty() {
            return false;
        }
    }
    pattern.ends_with('*') || remaining.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::mesh::{
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
                    }],
                    when: Vec::new(),
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
}
