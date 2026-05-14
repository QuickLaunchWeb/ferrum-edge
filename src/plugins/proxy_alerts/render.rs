//! Build a generic [`Notification`] (and webhook template-variable map) from
//! a fired rule observation.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::notifications::{EventAction, Notification, NotificationField};

use super::rules::{Rule, RuleObservation, SampleInput};

pub fn build_notification(
    rule: &Rule,
    observation: &RuleObservation,
    sample: SampleInput<'_>,
    event_action: EventAction,
    now: DateTime<Utc>,
) -> Notification {
    let common = rule.common();
    let proxy_label = sample
        .proxy_name()
        .or(sample.proxy_id())
        .unwrap_or("(unknown proxy)");
    let title = match event_action {
        EventAction::Trigger => format!("[ALERT] {} on {}", common.name, proxy_label),
        EventAction::Resolve => format!("[RESOLVED] {} on {}", common.name, proxy_label),
        EventAction::Info => format!("{} on {}", common.name, proxy_label),
    };
    let mut fields: Vec<NotificationField> = vec![
        NotificationField::new("Rule", common.name.to_string()),
        NotificationField::new("Type", rule.type_str().to_string()),
        NotificationField::new("Severity", common.severity.as_str().to_string()),
        NotificationField::new("Proxy", proxy_label.to_string()),
        NotificationField::new("Observed", observation.observed.clone()),
        NotificationField::new("Threshold", observation.threshold.clone()),
        NotificationField::new("Window", format!("{}s", common.window_seconds)),
        NotificationField::new("Samples", observation.sample_count.to_string()),
    ];
    let ns = sample.namespace();
    if !ns.is_empty() {
        fields.push(NotificationField::new("Namespace", ns.to_string()));
    }
    if !common.channel_names.is_empty() {
        let names: Vec<&str> = common.channel_names.iter().map(|n| n.as_ref()).collect();
        fields.push(NotificationField::full_width("Channels", names.join(", ")));
    }
    let body = match event_action {
        EventAction::Resolve => format!(
            "Rule '{}' has recovered: {}",
            common.name, observation.reason
        ),
        _ => observation.reason.clone(),
    };
    let source: Arc<str> = Arc::from(format!("proxy_alerts:{}", common.name).as_str());
    let mut builder = Notification::builder(title)
        .body(body)
        .severity(common.severity)
        .event_action(event_action)
        .source(source)
        .fired_at(now)
        .fields(fields);
    if let Some(name) = sample.proxy_name() {
        builder = builder.subject_id(Arc::from(name));
    } else if let Some(id) = sample.proxy_id() {
        builder = builder.subject_id(Arc::from(id));
    }
    if !ns.is_empty() {
        builder = builder.namespace(Arc::from(ns));
    }
    builder.build()
}

pub fn build_webhook_vars(
    rule: &Rule,
    observation: &RuleObservation,
    sample: SampleInput<'_>,
    event_action: EventAction,
    now: DateTime<Utc>,
) -> HashMap<String, String> {
    let common = rule.common();
    let mut vars = HashMap::with_capacity(12);
    vars.insert("rule_name".to_string(), common.name.to_string());
    vars.insert(
        "proxy_id".to_string(),
        sample.proxy_id().unwrap_or("").to_string(),
    );
    vars.insert(
        "proxy_name".to_string(),
        sample.proxy_name().unwrap_or("").to_string(),
    );
    vars.insert("namespace".to_string(), sample.namespace().to_string());
    vars.insert("fired_at".to_string(), now.to_rfc3339());
    vars.insert("observed".to_string(), observation.observed.clone());
    vars.insert("threshold".to_string(), observation.threshold.clone());
    vars.insert(
        "sample_count".to_string(),
        observation.sample_count.to_string(),
    );
    vars.insert(
        "window_seconds".to_string(),
        common.window_seconds.to_string(),
    );
    vars.insert("severity".to_string(), common.severity.as_str().to_string());
    vars.insert("reason".to_string(), observation.reason.clone());
    vars.insert(
        "event_action".to_string(),
        event_action.as_str().to_string(),
    );
    vars
}
