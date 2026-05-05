//! Mesh authorization plugin.
//!
//! Evaluates canonical Layer-2 [`MeshPolicy`] rules without changing the
//! plugin trait. Mesh mode can inject this plugin into generated proxy config,
//! and file/admin users can configure it explicitly.

use async_trait::async_trait;
use glob::Pattern;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::warn;

use crate::config::mesh::{
    ConditionMatch, MeshPolicy, MeshRule, MtlsMode, PeerAuthentication, PolicyAction, PolicyScope,
    PrincipalMatch, RequestMatch, WorkloadSelector,
};
use crate::identity::spiffe::SpiffeId;

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};

#[derive(Debug, Default, Deserialize)]
struct MeshAuthzConfig {
    #[serde(default)]
    policies: Vec<MeshPolicy>,
    #[serde(default)]
    peer_authentications: Vec<PeerAuthentication>,
}

pub struct MeshAuthz {
    policies: Vec<MeshPolicy>,
    peer_authentications: Vec<PeerAuthentication>,
}

impl MeshAuthz {
    pub fn new(config: &Value) -> Result<Self, String> {
        let parsed: MeshAuthzConfig =
            serde_json::from_value(config.clone()).map_err(|e| format!("mesh_authz: {e}"))?;
        let errors = crate::config::mesh::validate_mesh_config(
            &[],
            &[],
            &parsed.policies,
            &parsed.peer_authentications,
            &[],
            None,
        );
        if !errors.is_empty() {
            return Err(format!("mesh_authz: {}", errors.join("; ")));
        }
        Ok(Self {
            policies: parsed.policies,
            peer_authentications: parsed.peer_authentications,
        })
    }

    fn evaluate_http(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.policies.is_empty() && self.peer_authentications.is_empty() {
            return PluginResult::Continue;
        }

        ctx.materialize_headers();
        if let Some(id) = ctx.peer_spiffe_id.as_ref() {
            insert_identity_metadata(&mut ctx.metadata, id);
        }

        let request = HttpRequestView {
            method: ctx.method.as_str(),
            path: ctx.path.as_str(),
            host: ctx
                .headers
                .get("host")
                .or_else(|| ctx.headers.get(":authority"))
                .map(String::as_str),
            headers: &ctx.headers,
            destination_namespace: ctx
                .matched_proxy
                .as_ref()
                .map(|proxy| proxy.namespace.as_str()),
            destination_labels: &ctx.metadata,
            port: ctx
                .metadata
                .get("destination_port")
                .and_then(|p| p.parse::<u16>().ok()),
        };

        let peer = ctx.peer_spiffe_id.as_ref();
        if let Some(reason) =
            evaluate_peer_authentications(&self.peer_authentications, peer, &request)
        {
            return reject_with_status(reason, 401);
        }

        match evaluate_policies(&self.policies, peer, &request) {
            PolicyDecision::Allow => PluginResult::Continue,
            PolicyDecision::Audit => {
                ctx.metadata
                    .insert("mesh_authz.audit".to_string(), "true".to_string());
                PluginResult::Continue
            }
            PolicyDecision::Deny(reason) => reject(reason),
        }
    }

    fn evaluate_stream(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        if self.policies.is_empty() && self.peer_authentications.is_empty() {
            return PluginResult::Continue;
        }

        let metadata = ctx.metadata.as_ref();
        let peer = metadata
            .and_then(|m| {
                m.get("peer_spiffe_id")
                    .or_else(|| m.get("source_principal"))
                    .or_else(|| m.get("source_principal_spiffe_id"))
            })
            .and_then(|raw| SpiffeId::new(raw.clone()).ok());
        let headers = HashMap::new();
        let empty_metadata = HashMap::new();
        let destination_namespace =
            metadata.and_then(|m| m.get("destination_namespace").map(String::as_str));
        let request = HttpRequestView {
            method: "CONNECT",
            path: "",
            host: None,
            headers: &headers,
            destination_namespace,
            destination_labels: metadata.unwrap_or(&empty_metadata),
            port: Some(ctx.listen_port),
        };

        if let Some(reason) =
            evaluate_peer_authentications(&self.peer_authentications, peer.as_ref(), &request)
        {
            return reject_with_status(reason, 401);
        }

        match evaluate_policies(&self.policies, peer.as_ref(), &request) {
            PolicyDecision::Allow | PolicyDecision::Audit => PluginResult::Continue,
            PolicyDecision::Deny(reason) => reject(reason),
        }
    }
}

#[async_trait]
impl Plugin for MeshAuthz {
    fn name(&self) -> &str {
        "mesh_authz"
    }

    fn priority(&self) -> u16 {
        super::priority::MESH_AUTHZ
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        self.evaluate_http(ctx)
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.evaluate_stream(ctx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyDecision {
    Allow,
    Audit,
    Deny(&'static str),
}

struct HttpRequestView<'a> {
    method: &'a str,
    path: &'a str,
    host: Option<&'a str>,
    headers: &'a HashMap<String, String>,
    destination_namespace: Option<&'a str>,
    destination_labels: &'a HashMap<String, String>,
    port: Option<u16>,
}

fn evaluate_policies(
    policies: &[MeshPolicy],
    peer: Option<&SpiffeId>,
    request: &HttpRequestView<'_>,
) -> PolicyDecision {
    let mut allow_policy_in_scope = false;
    let mut allow_matched = false;
    let mut audit_matched = false;

    for policy in policies {
        if !policy_scope_matches(policy, request) {
            continue;
        }

        let policy_has_allow = policy
            .rules
            .iter()
            .any(|rule| rule.action == PolicyAction::Allow);
        allow_policy_in_scope |= policy_has_allow;

        for rule in &policy.rules {
            if !rule_matches(rule, peer, request) {
                continue;
            }
            match rule.action {
                PolicyAction::Deny => return PolicyDecision::Deny("mesh_policy_denied"),
                PolicyAction::Allow => allow_matched = true,
                PolicyAction::Audit => audit_matched = true,
            }
        }
    }

    if allow_policy_in_scope && !allow_matched {
        return PolicyDecision::Deny("mesh_policy_no_allow_match");
    }
    if audit_matched {
        return PolicyDecision::Audit;
    }
    PolicyDecision::Allow
}

fn evaluate_peer_authentications(
    peer_auths: &[PeerAuthentication],
    peer: Option<&SpiffeId>,
    request: &HttpRequestView<'_>,
) -> Option<&'static str> {
    if !matches!(
        effective_peer_authentication_mode(peer_auths, request),
        Some(MtlsMode::Strict)
    ) {
        return None;
    }
    peer.is_none()
        .then_some("peer_authentication_strict_mtls_required")
}

fn effective_peer_authentication_mode(
    peer_auths: &[PeerAuthentication],
    request: &HttpRequestView<'_>,
) -> Option<MtlsMode> {
    let mut best: Option<(u8, usize, MtlsMode)> = None;
    for (index, peer_auth) in peer_auths.iter().enumerate() {
        let Some(specificity) = peer_auth_specificity(peer_auth, request) else {
            continue;
        };
        let mode = request
            .port
            .and_then(|port| peer_auth.port_overrides.get(&port).copied())
            .unwrap_or(peer_auth.mtls_mode);
        if best.is_none_or(|(best_specificity, best_index, _)| {
            specificity > best_specificity
                || (specificity == best_specificity && index >= best_index)
        }) {
            best = Some((specificity, index, mode));
        }
    }
    best.map(|(_, _, mode)| mode)
}

fn peer_auth_specificity(
    peer_auth: &PeerAuthentication,
    request: &HttpRequestView<'_>,
) -> Option<u8> {
    match peer_auth.selector.as_ref() {
        Some(selector) => {
            if selector.namespace.is_none()
                && request
                    .destination_namespace
                    .is_none_or(|dest| dest != peer_auth.namespace)
            {
                return None;
            }
            selector_matches(selector, request).then_some(2)
        }
        None => request
            .destination_namespace
            .is_some_and(|dest| dest == peer_auth.namespace)
            .then_some(1),
    }
}

fn policy_scope_matches(policy: &MeshPolicy, request: &HttpRequestView<'_>) -> bool {
    match &policy.scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace { namespace } => request
            .destination_namespace
            .is_some_and(|dest| dest == namespace),
        PolicyScope::WorkloadSelector { selector } => selector_matches(selector, request),
    }
}

fn selector_matches(selector: &WorkloadSelector, request: &HttpRequestView<'_>) -> bool {
    if let Some(ns) = selector.namespace.as_deref() {
        match request.destination_namespace {
            Some(destination_namespace) if destination_namespace == ns => {}
            _ => return false,
        }
    }
    selector.labels.iter().all(|(key, expected)| {
        let metadata_key = format!("destination.label.{key}");
        request
            .destination_labels
            .get(&metadata_key)
            .is_some_and(|actual| actual == expected)
    })
}

fn rule_matches(rule: &MeshRule, peer: Option<&SpiffeId>, request: &HttpRequestView<'_>) -> bool {
    let principal_ok = rule.from.is_empty()
        || rule
            .from
            .iter()
            .any(|principal| principal_matches(principal, peer));
    let request_ok = rule.to.is_empty()
        || rule
            .to
            .iter()
            .any(|request_match| request_matches(request_match, request));
    let conditions_ok = rule
        .when
        .iter()
        .all(|condition| condition_matches(condition, request.destination_labels));

    principal_ok && request_ok && conditions_ok
}

fn principal_matches(principal: &PrincipalMatch, peer: Option<&SpiffeId>) -> bool {
    let Some(peer) = peer else {
        return false;
    };

    if let Some(td) = principal.trust_domain.as_ref()
        && peer.trust_domain() != td
    {
        return false;
    }
    if let Some(pattern) = principal.spiffe_id_pattern.as_ref()
        && !glob_matches(pattern, peer.as_str())
    {
        return false;
    }
    if let Some(pattern) = principal.namespace_pattern.as_ref() {
        let Some(namespace) = namespace_from_spiffe(peer) else {
            return false;
        };
        if !glob_matches(pattern, namespace) {
            return false;
        }
    }
    true
}

fn request_matches(rule: &RequestMatch, request: &HttpRequestView<'_>) -> bool {
    if !rule.methods.is_empty()
        && !rule
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(request.method))
    {
        return false;
    }
    if !rule.paths.is_empty()
        && !rule
            .paths
            .iter()
            .any(|pattern| glob_matches(pattern, request.path))
    {
        return false;
    }
    if !rule.hosts.is_empty() {
        let Some(host) = request.host else {
            return false;
        };
        if !rule.hosts.iter().any(|pattern| glob_matches(pattern, host)) {
            return false;
        }
    }
    if !rule.headers.is_empty()
        && !rule.headers.iter().all(|(name, pattern)| {
            request
                .headers
                .get(&name.to_ascii_lowercase())
                .or_else(|| request.headers.get(name))
                .is_some_and(|value| glob_matches(pattern, value))
        })
    {
        return false;
    }
    if !rule.ports.is_empty() && !request.port.is_some_and(|port| rule.ports.contains(&port)) {
        return false;
    }
    true
}

fn condition_matches(condition: &ConditionMatch, metadata: &HashMap<String, String>) -> bool {
    let Some(value) = metadata.get(&condition.key) else {
        return condition.values.is_empty();
    };
    if !condition.values.is_empty()
        && !condition
            .values
            .iter()
            .any(|pattern| glob_matches(pattern, value))
    {
        return false;
    }
    !condition
        .not_values
        .iter()
        .any(|pattern| glob_matches(pattern, value))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    Pattern::new(pattern).is_ok_and(|pattern| pattern.matches(value))
}

fn namespace_from_spiffe(id: &SpiffeId) -> Option<&str> {
    let mut segments = id.path_segments();
    while let Some(segment) = segments.next() {
        if segment == "ns" {
            return segments.next();
        }
    }
    None
}

fn insert_identity_metadata(metadata: &mut HashMap<String, String>, id: &SpiffeId) {
    metadata
        .entry("source_principal".to_string())
        .or_insert_with(|| id.to_string());
    if let Some(namespace) = namespace_from_spiffe(id) {
        metadata
            .entry("source_namespace".to_string())
            .or_insert_with(|| namespace.to_string());
    }
}

fn reject(reason: &'static str) -> PluginResult {
    reject_with_status(reason, 403)
}

fn reject_with_status(reason: &'static str, status_code: u16) -> PluginResult {
    warn!(
        plugin = "mesh_authz",
        reason, "Mesh authorization rejected request"
    );
    PluginResult::Reject {
        status_code,
        body: format!(r#"{{"error":"{reason}"}}"#),
        headers: HashMap::new(),
    }
}
