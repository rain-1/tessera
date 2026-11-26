//! Optional JSON request-body policy (security review 2026-11-26, S-1/S-2).
//!
//! **Defence in depth that depends on provider API shapes.** The route
//! allowlist decides *which endpoint* the sandbox may call; this policy
//! looks inside the request body for fields that make the *provider* act on
//! the agent's behalf beyond generating text:
//!
//! * top-level keys such as Anthropic `mcp_servers` (the provider connects
//!   to an arbitrary MCP server URL) are refused;
//! * `tools[].type` must be absent (a client-side tool) or in an allowlist
//!   (default `custom`, `function`), which refuses server-side tools such
//!   as Anthropic `web_search_*` / `web_fetch_*` / `code_execution_*` and
//!   OpenAI Responses `mcp` (`server_url`) / `web_search`;
//! * optionally, an output token cap and a model allowlist.
//!
//! The body is parsed once, bounded by `max_request_body`, with duplicate
//! object keys refused (a provider parser that keeps the first value would
//! otherwise see a different request from the one checked). The policy only
//! knows the field names providers document today; a new provider feature
//! with a different shape is not caught. Documented in `docs/compat.md`.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::config::BodyPolicyConfig;
use crate::policy::Denial;

/// Compiled body policy.
#[derive(Clone, Debug)]
pub struct BodyPolicy {
    deny_keys: Vec<String>,
    tool_types: HashSet<String>,
    max_tokens: Option<u64>,
    max_tokens_fields: Vec<String>,
    models: Option<HashSet<String>>,
}

impl BodyPolicy {
    /// Compile from configuration.
    pub fn new(cfg: &BodyPolicyConfig) -> Self {
        Self {
            deny_keys: cfg.deny_keys.clone(),
            tool_types: cfg.allowed_tool_types.iter().cloned().collect(),
            max_tokens: cfg.max_tokens,
            max_tokens_fields: cfg.max_tokens_fields.clone(),
            models: cfg.models.as_ref().map(|m| m.iter().cloned().collect()),
        }
    }

    /// Check a request body. Empty bodies (e.g. `GET`) are not inspected.
    /// `token_cap` says whether the route is subject to `max_tokens`.
    pub fn check(&self, body: &[u8], token_cap: bool) -> Result<(), Denial> {
        if body.is_empty() {
            return Ok(());
        }
        let Ok(Strict(Value::Object(obj))) = serde_json::from_slice::<Strict>(body) else {
            return Err(Denial::BodyNotJson);
        };
        if self.deny_keys.iter().any(|k| obj.contains_key(k)) {
            // Static reason for the audit line: the only default key.
            return Err(Denial::BodyPolicy(if obj.contains_key("mcp_servers") {
                "mcp_servers"
            } else {
                "denied_key"
            }));
        }
        self.check_tools(&obj)?;
        if let Some(models) = &self.models {
            match obj.get("model") {
                Some(Value::String(m)) if models.contains(m) => {}
                Some(Value::String(_)) => return Err(Denial::BodyPolicy("model_not_allowed")),
                _ => return Err(Denial::BodyPolicy("model_missing")),
            }
        }
        if let (Some(cap), true) = (self.max_tokens, token_cap) {
            let mut found = false;
            for f in &self.max_tokens_fields {
                match obj.get(f) {
                    None => {}
                    Some(v) => match v.as_u64() {
                        Some(n) if n <= cap => found = true,
                        Some(_) => return Err(Denial::BodyPolicy("max_tokens_over_cap")),
                        None => return Err(Denial::BodyPolicy("max_tokens_invalid")),
                    },
                }
            }
            if !found {
                return Err(Denial::BodyPolicy("max_tokens_missing"));
            }
        }
        Ok(())
    }

    fn check_tools(&self, obj: &Map<String, Value>) -> Result<(), Denial> {
        let Some(tools) = obj.get("tools") else {
            return Ok(());
        };
        let Value::Array(tools) = tools else {
            return Err(Denial::BodyPolicy("tools_shape"));
        };
        for t in tools {
            let Value::Object(t) = t else {
                return Err(Denial::BodyPolicy("tools_shape"));
            };
            match t.get("type") {
                None => {}
                Some(Value::String(ty)) if self.tool_types.contains(ty) => {}
                Some(_) => return Err(Denial::BodyPolicy("tool_type")),
            }
        }
        Ok(())
    }
}

/// A JSON value parsed with duplicate object keys refused.
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let Strict(v) = map.next_value()?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> BodyPolicy {
        BodyPolicy::new(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn strict_parse() {
        assert!(serde_json::from_str::<Strict>(r#"{"a":1,"b":{"a":2}}"#).is_ok());
        assert!(serde_json::from_str::<Strict>(r#"{"a":1,"a":2}"#).is_err());
        assert!(serde_json::from_str::<Strict>(r#"{"x":{"a":1,"a":2}}"#).is_err());
        assert!(serde_json::from_str::<Strict>(r#"[{"a":1,"a":2}]"#).is_err());
        // Deep nesting is bounded by serde_json's recursion limit.
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(serde_json::from_str::<Strict>(&deep).is_err());
    }

    #[test]
    fn tools_and_keys() {
        let p = policy("{}");
        let ok = [
            r#"{"tools":[]}"#,
            r#"{"tools":[{"name":"x"}]}"#,
            r#"{"tools":[{"type":"custom"},{"type":"function"}]}"#,
            r#"{"model":"anything"}"#,
        ];
        for b in ok {
            assert_eq!(p.check(b.as_bytes(), true), Ok(()), "{b}");
        }
        let bad = [
            (r#"{"mcp_servers":[]}"#, "mcp_servers"),
            (r#"{"tools":[{"type":"web_search_20250305"}]}"#, "tool_type"),
            (
                r#"{"tools":[{"type":"mcp","server_url":"x"}]}"#,
                "tool_type",
            ),
            (r#"{"tools":[{"type":null}]}"#, "tool_type"),
            (r#"{"tools":"x"}"#, "tools_shape"),
            (r#"{"tools":[1]}"#, "tools_shape"),
        ];
        for (b, why) in bad {
            assert_eq!(
                p.check(b.as_bytes(), true),
                Err(Denial::BodyPolicy(why)),
                "{b}"
            );
        }
        assert_eq!(p.check(b"null", true), Err(Denial::BodyNotJson));
        assert_eq!(p.check(b"", true), Ok(()));
        let extra = policy(r#"{"deny_keys":["prompt"]}"#);
        assert_eq!(
            extra.check(br#"{"prompt":{"id":"p"}}"#, true),
            Err(Denial::BodyPolicy("denied_key"))
        );
    }

    #[test]
    fn caps() {
        let p = policy(r#"{"max_tokens":100,"models":["a"]}"#);
        assert_eq!(p.check(br#"{"model":"a","max_tokens":100}"#, true), Ok(()));
        assert_eq!(p.check(br#"{"model":"a"}"#, false), Ok(()));
        assert_eq!(
            p.check(br#"{"model":"a"}"#, true),
            Err(Denial::BodyPolicy("max_tokens_missing"))
        );
        assert_eq!(
            p.check(br#"{"model":"a","max_output_tokens":101}"#, true),
            Err(Denial::BodyPolicy("max_tokens_over_cap"))
        );
        assert_eq!(
            p.check(br#"{"model":"a","max_tokens":1e2}"#, true),
            Err(Denial::BodyPolicy("max_tokens_invalid"))
        );
        assert_eq!(
            p.check(br#"{"model":["a"],"max_tokens":1}"#, true),
            Err(Denial::BodyPolicy("model_missing"))
        );
    }
}
