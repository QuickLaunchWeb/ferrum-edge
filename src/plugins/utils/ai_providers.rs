use serde_json::Value;

/// Shared AI provider identifiers for response parsing helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProvider {
    OpenAi,
    Anthropic,
    Google,
    Cohere,
    Mistral,
    Bedrock,
}

impl AiProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::Cohere => "cohere",
            Self::Mistral => "mistral",
            Self::Bedrock => "bedrock",
        }
    }
}

/// Token/model metadata extracted from an AI provider response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiTokenUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub model: Option<String>,
    pub provider: Option<AiProvider>,
}

impl AiTokenUsage {
    pub fn total_for_mode(&self, count_mode: &str) -> Option<u64> {
        match count_mode {
            "prompt_tokens" => self.prompt_tokens.or(Some(0)),
            "completion_tokens" => self.completion_tokens.or(Some(0)),
            _ => self
                .total_tokens
                .or_else(|| match (self.prompt_tokens, self.completion_tokens) {
                    (Some(prompt), Some(completion)) => Some(prompt.saturating_add(completion)),
                    (Some(prompt), None) => Some(prompt),
                    (None, Some(completion)) => Some(completion),
                    _ => None,
                }),
        }
    }
}

pub fn parse_ai_provider(provider: &str) -> Option<AiProvider> {
    match provider {
        "openai" => Some(AiProvider::OpenAi),
        "anthropic" => Some(AiProvider::Anthropic),
        "google" => Some(AiProvider::Google),
        "cohere" => Some(AiProvider::Cohere),
        "mistral" => Some(AiProvider::Mistral),
        "bedrock" => Some(AiProvider::Bedrock),
        _ => None,
    }
}

pub fn detect_response_provider(json: &Value) -> Option<AiProvider> {
    if json
        .get("usageMetadata")
        .and_then(|usage| usage.get("promptTokenCount"))
        .is_some()
    {
        return Some(AiProvider::Google);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("input_tokens"))
        .is_some()
    {
        return Some(AiProvider::Anthropic);
    }

    // Cohere v2 (`/v2/chat`, the format `ai_federation` uses by default)
    // reports `{"usage": {"tokens": {"input_tokens": ..., "output_tokens": ...}}}`.
    // Cohere v1 (`/v1/generate`) reported it under `meta.tokens.*`. Accept
    // both — place this above the OpenAI / Bedrock branches so any future
    // broadening of those checks (which also key off `usage.*`) can't
    // accidentally claim a v2 response. Canonical shapes are disjoint today.
    if json
        .get("usage")
        .and_then(|usage| usage.get("tokens"))
        .and_then(|tokens| tokens.get("input_tokens"))
        .is_some()
    {
        return Some(AiProvider::Cohere);
    }

    if json
        .get("meta")
        .and_then(|meta| meta.get("tokens"))
        .is_some()
    {
        return Some(AiProvider::Cohere);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("inputTokens"))
        .is_some()
    {
        return Some(AiProvider::Bedrock);
    }

    if json
        .get("usage")
        .and_then(|usage| usage.get("prompt_tokens"))
        .is_some()
    {
        return Some(AiProvider::OpenAi);
    }

    None
}

pub fn detect_sse_provider(json: &Value) -> Option<AiProvider> {
    // Check streaming-specific provider shapes before the buffered-response
    // fallback below. Anthropic uses underscore-separated event types
    // (`message_start` / `message_delta` / `message_stop` /
    // `content_block_start` / `content_block_delta` / `content_block_stop` /
    // `ping`); Cohere v2 uses hyphen-separated types (`message-start` /
    // `message-end` / `content-start` / `content-delta` / `content-end`).
    // Match on the exact separator so v2 streams don't get mis-classified as
    // Anthropic (the previous `starts_with("message")` swallowed both).
    if json
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|t| {
            t.starts_with("message_") || t.starts_with("content_block_") || t == "ping"
        })
    {
        return Some(AiProvider::Anthropic);
    }

    if json
        .get("type")
        .and_then(|value| value.as_str())
        .is_some_and(|t| t.starts_with("message-") || t.starts_with("content-"))
    {
        return Some(AiProvider::Cohere);
    }

    if json
        .get("object")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value.contains("chat.completion"))
    {
        return Some(AiProvider::OpenAi);
    }

    if json.get("candidates").is_some() {
        return Some(AiProvider::Google);
    }

    detect_response_provider(json)
}

pub fn extract_response_usage(json: &Value, provider: AiProvider) -> AiTokenUsage {
    match provider {
        AiProvider::OpenAi | AiProvider::Mistral => extract_openai_usage(json, provider),
        AiProvider::Anthropic => extract_anthropic_usage(json),
        AiProvider::Google => extract_google_usage(json),
        AiProvider::Cohere => extract_cohere_usage(json),
        AiProvider::Bedrock => extract_bedrock_usage(json),
    }
}

#[cfg(test)]
fn extract_response_texts(json: &Value) -> Vec<&str> {
    let mut texts = Vec::new();

    if let Some(choices) = json.get("choices").and_then(|value| value.as_array()) {
        for choice in choices {
            if let Some(content) = choice
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(|value| value.as_str())
            {
                texts.push(content);
            }
            if let Some(content) = choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(|value| value.as_str())
            {
                texts.push(content);
            }
        }
    }

    if let Some(content) = json.get("content").and_then(|value| value.as_array()) {
        for block in content {
            if block.get("type").and_then(|value| value.as_str()) == Some("text")
                && let Some(text) = block.get("text").and_then(|value| value.as_str())
            {
                texts.push(text);
            }
        }
    }

    if let Some(candidates) = json.get("candidates").and_then(|value| value.as_array()) {
        for candidate in candidates {
            if let Some(parts) = candidate
                .get("content")
                .and_then(|content| content.get("parts"))
                .and_then(|value| value.as_array())
            {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(|value| value.as_str()) {
                        texts.push(text);
                    }
                }
            }
        }
    }

    if let Some(content) = json
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|value| value.as_array())
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(|value| value.as_str()) {
                texts.push(text);
            }
        }
    }

    if let Some(content) = json
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|value| value.as_array())
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(|value| value.as_str()) {
                texts.push(text);
            }
        }
    }

    texts
}

#[cfg(test)]
fn for_each_response_text_mut(json: &mut Value, mut apply: impl FnMut(&mut String)) {
    if let Some(choices) = json
        .get_mut("choices")
        .and_then(|value| value.as_array_mut())
    {
        for choice in choices {
            if let Some(message) = choice
                .get_mut("message")
                .and_then(|value| value.as_object_mut())
                && let Some(Value::String(content)) = message.get_mut("content")
            {
                apply(content);
            }
            if let Some(delta) = choice
                .get_mut("delta")
                .and_then(|value| value.as_object_mut())
                && let Some(Value::String(content)) = delta.get_mut("content")
            {
                apply(content);
            }
        }
    }

    if let Some(content) = json
        .get_mut("content")
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            let is_text = block.get("type").and_then(|value| value.as_str()) == Some("text");
            if is_text
                && let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }

    if let Some(candidates) = json
        .get_mut("candidates")
        .and_then(|value| value.as_array_mut())
    {
        for candidate in candidates {
            if let Some(parts) = candidate
                .get_mut("content")
                .and_then(|content| content.get_mut("parts"))
                .and_then(|value| value.as_array_mut())
            {
                for part in parts {
                    if let Some(part) = part.as_object_mut()
                        && let Some(Value::String(text)) = part.get_mut("text")
                    {
                        apply(text);
                    }
                }
            }
        }
    }

    if let Some(content) = json
        .get_mut("message")
        .and_then(|message| message.get_mut("content"))
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            if let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }

    if let Some(content) = json
        .get_mut("output")
        .and_then(|output| output.get_mut("message"))
        .and_then(|message| message.get_mut("content"))
        .and_then(|value| value.as_array_mut())
    {
        for block in content {
            if let Some(block) = block.as_object_mut()
                && let Some(Value::String(text)) = block.get_mut("text")
            {
                apply(text);
            }
        }
    }
}

fn extract_openai_usage(json: &Value, provider: AiProvider) -> AiTokenUsage {
    let usage = json.get("usage");
    let prompt = usage
        .and_then(|value| value.get("prompt_tokens"))
        .and_then(|value| value.as_u64());
    let completion = usage
        .and_then(|value| value.get("completion_tokens"))
        .and_then(|value| value.as_u64());

    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: usage
            .and_then(|value| value.get("total_tokens"))
            .and_then(|value| value.as_u64())
            .or_else(|| sum_pair(prompt, completion)),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(provider),
    }
}

fn extract_anthropic_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usage");
    let prompt = usage
        .and_then(|value| value.get("input_tokens"))
        .and_then(|value| value.as_u64());
    let completion = usage
        .and_then(|value| value.get("output_tokens"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Anthropic),
    }
}

fn extract_google_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usageMetadata");
    let prompt = usage
        .and_then(|value| value.get("promptTokenCount"))
        .and_then(|value| value.as_u64());
    let completion = usage
        .and_then(|value| value.get("candidatesTokenCount"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: usage
            .and_then(|value| value.get("totalTokenCount"))
            .and_then(|value| value.as_u64())
            .or_else(|| sum_pair(prompt, completion)),
        model: json
            .get("modelVersion")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Google),
    }
}

fn extract_cohere_usage(json: &Value) -> AiTokenUsage {
    // Cohere v2 buffered (`/v2/chat`) returns counts at `usage.tokens.*`.
    // Cohere v2 streaming nests them under the `message-end` event's
    // `delta.usage.tokens.*`. Cohere v1 (`/v1/generate`) returned them at
    // `meta.tokens.*`. Try buffered v2 first, then streaming v2, then v1 so
    // legacy deployments continue to report usage.
    let tokens = json
        .get("usage")
        .and_then(|value| value.get("tokens"))
        .or_else(|| {
            json.get("delta")
                .and_then(|delta| delta.get("usage"))
                .and_then(|usage| usage.get("tokens"))
        })
        .or_else(|| json.get("meta").and_then(|value| value.get("tokens")));
    let prompt = tokens
        .and_then(|value| value.get("input_tokens"))
        .and_then(|value| value.as_u64());
    let completion = tokens
        .and_then(|value| value.get("output_tokens"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: sum_pair(prompt, completion),
        model: json
            .get("model")
            .and_then(|value| value.as_str())
            .map(String::from),
        provider: Some(AiProvider::Cohere),
    }
}

fn extract_bedrock_usage(json: &Value) -> AiTokenUsage {
    let usage = json.get("usage");
    let prompt = usage
        .and_then(|value| value.get("inputTokens"))
        .and_then(|value| value.as_u64());
    let completion = usage
        .and_then(|value| value.get("outputTokens"))
        .and_then(|value| value.as_u64());
    AiTokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: usage
            .and_then(|value| value.get("totalTokens"))
            .and_then(|value| value.as_u64())
            .or_else(|| sum_pair(prompt, completion)),
        model: None,
        provider: Some(AiProvider::Bedrock),
    }
}

fn sum_pair(prompt: Option<u64>, completion: Option<u64>) -> Option<u64> {
    match (prompt, completion) {
        (Some(prompt), Some(completion)) => Some(prompt.saturating_add(completion)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AiProvider, detect_response_provider, detect_sse_provider, extract_response_texts,
        extract_response_usage, for_each_response_text_mut,
    };
    use serde_json::json;

    #[test]
    fn detects_supported_provider_shapes() {
        assert_eq!(
            detect_response_provider(&json!({"usageMetadata": {"promptTokenCount": 1}})),
            Some(AiProvider::Google)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"input_tokens": 1}})),
            Some(AiProvider::Anthropic)
        );
        // Cohere v1 (`/v1/generate`)
        assert_eq!(
            detect_response_provider(&json!({"meta": {"tokens": {"input_tokens": 1}}})),
            Some(AiProvider::Cohere)
        );
        // Cohere v2 (`/v2/chat` — what `ai_federation` uses by default)
        assert_eq!(
            detect_response_provider(
                &json!({"usage": {"tokens": {"input_tokens": 1, "output_tokens": 2}}})
            ),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"inputTokens": 1}})),
            Some(AiProvider::Bedrock)
        );
        assert_eq!(
            detect_response_provider(&json!({"usage": {"prompt_tokens": 1}})),
            Some(AiProvider::OpenAi)
        );
    }

    #[test]
    fn extracts_cohere_v2_usage_from_usage_tokens_path() {
        // Canonical Cohere v2 `/v2/chat` body — model identity is returned via
        // HTTP response headers, not the body, so `model` is absent here.
        let usage = extract_response_usage(
            &json!({
                "id": "abc-123",
                "finish_reason": "COMPLETE",
                "usage": {
                    "tokens": {
                        "input_tokens": 17,
                        "output_tokens": 9
                    }
                }
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(17));
        assert_eq!(usage.completion_tokens, Some(9));
        assert_eq!(usage.total_tokens, Some(26));
        assert!(usage.model.is_none());
    }

    #[test]
    fn extracts_cohere_v2_model_when_body_includes_it() {
        // Some OpenAI-compatible wrappers in front of Cohere v2 echo `model`
        // into the body. The extractor is intentionally tolerant — if the
        // field is present, surface it.
        let usage = extract_response_usage(
            &json!({
                "usage": {
                    "tokens": {
                        "input_tokens": 17,
                        "output_tokens": 9
                    }
                },
                "model": "command-r-plus"
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.model.as_deref(), Some("command-r-plus"));
    }

    #[test]
    fn extracts_cohere_v2_streaming_usage_from_message_end() {
        // Cohere v2 streaming `message-end` event nests counts under
        // `delta.usage.tokens.*` instead of root `usage`.
        let usage = extract_response_usage(
            &json!({
                "type": "message-end",
                "delta": {
                    "finish_reason": "COMPLETE",
                    "usage": {
                        "tokens": {
                            "input_tokens": 23,
                            "output_tokens": 41
                        }
                    }
                }
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(23));
        assert_eq!(usage.completion_tokens, Some(41));
        assert_eq!(usage.total_tokens, Some(64));
        assert!(usage.model.is_none());
    }

    #[test]
    fn sse_detection_distinguishes_anthropic_underscores_from_cohere_v2_hyphens() {
        // Anthropic SSE event types use underscore separators.
        assert_eq!(
            detect_sse_provider(&json!({"type": "message_start"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "message_delta"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "content_block_delta"})),
            Some(AiProvider::Anthropic)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "ping"})),
            Some(AiProvider::Anthropic)
        );

        // Cohere v2 SSE event types use hyphen separators. Regression guard
        // for the previous `starts_with("message")` check that swallowed
        // `message-start` / `message-end` as Anthropic.
        assert_eq!(
            detect_sse_provider(&json!({"type": "message-start"})),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "message-end"})),
            Some(AiProvider::Cohere)
        );
        assert_eq!(
            detect_sse_provider(&json!({"type": "content-delta"})),
            Some(AiProvider::Cohere)
        );
    }

    #[test]
    fn extracts_cohere_v1_usage_from_meta_tokens_path() {
        // Backwards compatibility: legacy `/v1/generate` callers.
        let usage = extract_response_usage(
            &json!({
                "meta": {
                    "tokens": {
                        "input_tokens": 3,
                        "output_tokens": 4
                    }
                },
                "model": "command-light"
            }),
            AiProvider::Cohere,
        );

        assert_eq!(usage.prompt_tokens, Some(3));
        assert_eq!(usage.completion_tokens, Some(4));
        assert_eq!(usage.total_tokens, Some(7));
        assert_eq!(usage.model.as_deref(), Some("command-light"));
    }

    #[test]
    fn extracts_usage_and_model_fallbacks() {
        let usage = extract_response_usage(
            &json!({
                "usageMetadata": {
                    "promptTokenCount": 11,
                    "candidatesTokenCount": 7
                },
                "modelVersion": "gemini-2.5-pro"
            }),
            AiProvider::Google,
        );

        assert_eq!(usage.prompt_tokens, Some(11));
        assert_eq!(usage.completion_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(18));
        assert_eq!(usage.model.as_deref(), Some("gemini-2.5-pro"));
    }

    #[test]
    fn collects_and_mutates_supported_response_text_shapes() {
        let mut json = json!({
            "choices": [{"message": {"content": "openai"}}],
            "content": [{"type": "text", "text": "anthropic"}],
            "candidates": [{"content": {"parts": [{"text": "google"}]}}],
            "message": {"content": [{"text": "cohere"}]},
            "output": {"message": {"content": [{"text": "bedrock"}]}}
        });

        assert_eq!(
            extract_response_texts(&json),
            vec!["openai", "anthropic", "google", "cohere", "bedrock"]
        );

        for_each_response_text_mut(&mut json, |text| text.make_ascii_uppercase());

        assert_eq!(
            extract_response_texts(&json),
            vec!["OPENAI", "ANTHROPIC", "GOOGLE", "COHERE", "BEDROCK"]
        );
    }
}
