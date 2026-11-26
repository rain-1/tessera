//! Proxy configuration (JSON, trusted, written by the operator).
//!
//! See `examples/compat/*.json` and `docs/compat.md` for complete examples.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::Method;
use serde::Deserialize;

use crate::policy::{Route, clean_path};

/// How the credential is presented to the upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Injection {
    /// `x-api-key: <secret>` (Anthropic API).
    XApiKey,
    /// `authorization: Bearer <secret>` (OpenAI API and most others).
    Bearer,
}

impl Injection {
    /// Header name used for this injection.
    pub fn header_name(self) -> &'static str {
        match self {
            Self::XApiKey => "x-api-key",
            Self::Bearer => "authorization",
        }
    }
}

/// Credential source.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    /// Host file holding the secret (one line; trailing newline stripped).
    pub file: PathBuf,
    /// How to inject it.
    pub inject: Injection,
}

/// The single upstream the proxy may contact.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// DNS name used for resolution, SNI, certificate validation and `Host`.
    pub host: String,
    /// TCP port (default 443).
    #[serde(default = "default_port")]
    pub port: u16,
    /// PEM file with private CA certificates. When absent the Mozilla root
    /// program (`webpki-roots`) is used. The system trust store is never read.
    #[serde(default)]
    pub ca_pem_file: Option<PathBuf>,
    /// Admin-pinned addresses; when set, DNS is not consulted.
    #[serde(default)]
    pub pinned_addrs: Option<Vec<IpAddr>>,
    /// Permit non-global destination addresses (tests / internal gateways).
    #[serde(default)]
    pub allow_private: bool,
    /// Resolution + TCP connect + TLS handshake deadline.
    #[serde(default = "default_connect_ms")]
    pub connect_timeout_ms: u64,
    /// Deadline for the upstream response head after the request was sent.
    #[serde(default = "default_header_ms")]
    pub response_header_timeout_ms: u64,
    /// Longest silence allowed between response body chunks.
    #[serde(default = "default_idle_ms")]
    pub idle_timeout_ms: u64,
    /// Hard cap on one exchange, including a streamed body.
    #[serde(default = "default_max_duration_ms")]
    pub max_duration_ms: u64,
}

/// One allowed request shape.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// HTTP method (exact, upper case).
    pub method: String,
    /// Origin-form path without query.
    pub path: String,
    /// `exact` (default) or `prefix` (the path itself or anything below
    /// `path/`).
    #[serde(default, rename = "match")]
    pub match_kind: MatchKind,
    /// Whether a query string may be present (default true).
    #[serde(default = "yes")]
    pub allow_query: bool,
    /// When a [`BodyPolicyConfig`] is configured, a non-empty request body
    /// on this route must be a JSON object that passes it (default true).
    #[serde(default = "yes")]
    pub json_body: bool,
    /// Whether the body policy's `max_tokens` cap applies on this route
    /// (default true). Set false for routes that generate no output, such
    /// as `/v1/messages/count_tokens`.
    #[serde(default = "yes")]
    pub token_cap: bool,
}

/// Route path matching mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Path must equal the configured path.
    #[default]
    Exact,
    /// Path equals the configured path or lies below `path/`.
    Prefix,
}

/// Size and header limits applied to every sandbox.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest request body accepted from the sandbox (default 4 MiB). A
    /// body is read only after the request holds one of the sandbox's
    /// `max_concurrent` in-flight slots, so at most
    /// `max_concurrent * max_request_body` bytes are buffered per sandbox.
    #[serde(default = "default_max_request_body")]
    pub max_request_body: u64,
    /// Largest response body streamed back for one request.
    #[serde(default = "default_max_response_body")]
    pub max_response_body: u64,
    /// Largest request head (request line + headers) accepted.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Most request headers accepted.
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    /// Deadline for the first byte of a connection and for the whole
    /// request body (measured from the end of the head).
    #[serde(default = "default_request_read_ms")]
    pub request_read_timeout_ms: u64,
    /// Deadline for a complete request head, including the idle time
    /// before it on a keep-alive connection (default 30 s).
    #[serde(default = "default_request_header_ms")]
    pub request_header_timeout_ms: u64,
    /// Sustained rate of audit lines for refused connections and requests
    /// denied before reaching the upstream, per sandbox (default 5/s).
    /// Lines over the limit are counted and written as `suppressed:<outcome>`
    /// summaries.
    #[serde(default = "default_audit_denials_rate")]
    pub audit_denials_per_second: u32,
    /// Burst for `audit_denials_per_second` (default 20).
    #[serde(default = "default_audit_denials_burst")]
    pub audit_denials_burst: u32,
    /// How often suppressed-line summaries are written (default 10 s).
    #[serde(default = "default_audit_summary_ms")]
    pub audit_summary_interval_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body: default_max_request_body(),
            max_response_body: default_max_response_body(),
            max_header_bytes: default_max_header_bytes(),
            max_headers: default_max_headers(),
            request_read_timeout_ms: default_request_read_ms(),
            request_header_timeout_ms: default_request_header_ms(),
            audit_denials_per_second: default_audit_denials_rate(),
            audit_denials_burst: default_audit_denials_burst(),
            audit_summary_interval_ms: default_audit_summary_ms(),
        }
    }
}

/// Per-sandbox rate and byte budget. All totals are for the lifetime of the
/// proxy process (one sandbox session). `None` means unlimited.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    /// Sustained request rate (token bucket refill).
    #[serde(default = "default_rpm")]
    pub requests_per_minute: u32,
    /// Token bucket capacity.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Requests in flight at once (including streaming responses).
    #[serde(default = "default_concurrent")]
    pub max_concurrent: u32,
    /// Total requests.
    #[serde(default)]
    pub max_requests: Option<u64>,
    /// Total request body bytes sent upstream.
    #[serde(default)]
    pub max_request_bytes: Option<u64>,
    /// Total response body bytes returned to the sandbox.
    #[serde(default)]
    pub max_response_bytes: Option<u64>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: default_rpm(),
            burst: default_burst(),
            max_concurrent: default_concurrent(),
            max_requests: None,
            max_request_bytes: None,
            max_response_bytes: None,
        }
    }
}

/// Optional JSON request-body policy (defence in depth, see
/// `docs/compat.md`). It depends on the provider's API shapes: it inspects
/// field names the provider documents today and cannot know about fields a
/// provider adds later.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyPolicyConfig {
    /// Top-level keys that are refused outright (default `["mcp_servers"]`,
    /// Anthropic's MCP connector, which makes the provider connect to an
    /// arbitrary URL).
    #[serde(default = "default_deny_keys")]
    pub deny_keys: Vec<String>,
    /// Allowed values of `tools[].type`. A tool object without `type` is a
    /// client-side tool and always allowed. Default `["custom", "function"]`:
    /// server-side tools such as `web_search_*`, `web_fetch_*`,
    /// `code_execution_*` and OpenAI `mcp` / `web_search` are refused.
    #[serde(default = "default_tool_types")]
    pub allowed_tool_types: Vec<String>,
    /// Per-request output token cap. When set, a request on a route with
    /// `token_cap` must carry at least one of `max_tokens_fields`, each an
    /// integer `<=` this value.
    #[serde(default)]
    pub max_tokens: Option<u64>,
    /// Field names that carry the output token limit (default
    /// `max_tokens`, `max_output_tokens`, `max_completion_tokens`).
    #[serde(default = "default_max_tokens_fields")]
    pub max_tokens_fields: Vec<String>,
    /// When set, a request body must carry a string `model` from this list.
    #[serde(default)]
    pub models: Option<Vec<String>>,
}

/// One sandbox's listening socket.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Label written to every audit line (e.g. the launcher agent label).
    pub label: String,
    /// Host path of the Unix socket to create; bind-mount it into the
    /// sandbox. Its parent directory should be private (mode 0700).
    pub socket: PathBuf,
    /// Peer uids allowed to connect (checked with `SO_PEERCRED`). Default:
    /// only the proxy's own uid.
    #[serde(default)]
    pub peer_uids: Option<Vec<u32>>,
    /// Rate and byte budget.
    #[serde(default)]
    pub budget: BudgetConfig,
}

/// Complete proxy configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// The only upstream.
    pub upstream: UpstreamConfig,
    /// Credential injected into every forwarded request.
    pub credential: CredentialConfig,
    /// Allowed method + path combinations. Everything else is refused.
    pub routes: Vec<RouteConfig>,
    /// Size limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Extra request header names to strip (in addition to the built-in
    /// list of credential, hop-by-hop and forwarding headers).
    #[serde(default)]
    pub strip_request_headers: Vec<String>,
    /// Request headers forwarded upstream (after stripping); everything
    /// else is dropped. Default: [`crate::policy::DEFAULT_FORWARD_REQUEST`]
    /// (`content-type`, `accept`, `user-agent`, `anthropic-version`,
    /// `anthropic-beta`).
    #[serde(default)]
    pub forward_request_headers: Option<Vec<String>>,
    /// Allowed `anthropic-beta` values; other values are removed from the
    /// header (default: none, so the header is dropped). Betas can enable
    /// server-side tools.
    #[serde(default)]
    pub anthropic_beta_allow: Vec<String>,
    /// Optional JSON request-body policy (off when absent).
    #[serde(default)]
    pub body_policy: Option<BodyPolicyConfig>,
    /// Extra response header names to strip.
    #[serde(default)]
    pub strip_response_headers: Vec<String>,
    /// Append JSON audit lines here; default is standard error.
    #[serde(default)]
    pub audit_log: Option<PathBuf>,
    /// One entry per sandbox.
    pub sandboxes: Vec<SandboxConfig>,
}

fn yes() -> bool {
    true
}
fn default_port() -> u16 {
    443
}
fn default_connect_ms() -> u64 {
    10_000
}
fn default_header_ms() -> u64 {
    300_000
}
fn default_idle_ms() -> u64 {
    300_000
}
fn default_max_duration_ms() -> u64 {
    30 * 60_000
}
fn default_max_request_body() -> u64 {
    4 << 20
}
fn default_max_response_body() -> u64 {
    64 << 20
}
fn default_max_header_bytes() -> usize {
    64 * 1024
}
fn default_max_headers() -> usize {
    100
}
fn default_request_read_ms() -> u64 {
    60_000
}
fn default_request_header_ms() -> u64 {
    30_000
}
fn default_audit_denials_rate() -> u32 {
    5
}
fn default_audit_denials_burst() -> u32 {
    20
}
fn default_audit_summary_ms() -> u64 {
    10_000
}
fn default_deny_keys() -> Vec<String> {
    vec!["mcp_servers".into()]
}
fn default_tool_types() -> Vec<String> {
    vec!["custom".into(), "function".into()]
}
fn default_max_tokens_fields() -> Vec<String> {
    vec![
        "max_tokens".into(),
        "max_output_tokens".into(),
        "max_completion_tokens".into(),
    ]
}
fn default_rpm() -> u32 {
    120
}
fn default_burst() -> u32 {
    20
}
fn default_concurrent() -> u32 {
    8
}

/// Configuration error.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

impl ProxyConfig {
    /// Parse a JSON configuration file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Self::from_json(&text)
    }

    /// Parse JSON text.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|e| ConfigError(e.to_string()))
    }

    /// Validate and compile the route list.
    pub(crate) fn compile_routes(&self) -> Result<Vec<Route>, ConfigError> {
        if self.routes.is_empty() {
            return err("at least one route is required");
        }
        let mut out = Vec::new();
        for r in &self.routes {
            let method = Method::from_bytes(r.method.as_bytes())
                .map_err(|_| ConfigError(format!("bad method {:?}", r.method)))?;
            if method == Method::CONNECT || r.method != r.method.to_ascii_uppercase() {
                return err(format!("method {:?} not permitted", r.method));
            }
            if !clean_path(&r.path) || r.path.contains(['?', '#', '%']) || r.path.len() > 512 {
                return err(format!("bad route path {:?}", r.path));
            }
            out.push(Route {
                method,
                path: r.path.clone(),
                prefix: r.match_kind == MatchKind::Prefix,
                allow_query: r.allow_query,
                json_body: r.json_body,
                token_cap: r.token_cap,
            });
        }
        Ok(out)
    }

    /// Basic sanity checks independent of the file system.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.compile_routes()?;
        if self.sandboxes.is_empty() {
            return err("at least one sandbox is required");
        }
        let mut labels = std::collections::HashSet::new();
        let mut sockets = std::collections::HashSet::new();
        for s in &self.sandboxes {
            if s.label.is_empty()
                || s.label.len() > 64
                || !s
                    .label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return err(format!("bad sandbox label {:?}", s.label));
            }
            if !labels.insert(&s.label) || !sockets.insert(&s.socket) {
                return err(format!("duplicate sandbox label or socket {:?}", s.label));
            }
            if !s.socket.is_absolute() {
                return err("sandbox socket paths must be absolute");
            }
            if s.budget.requests_per_minute == 0 || s.budget.burst == 0 {
                return err("requests_per_minute and burst must be positive");
            }
            if s.budget.max_concurrent == 0 {
                return err("max_concurrent must be positive");
            }
        }
        let l = &self.limits;
        if l.max_header_bytes < 1024 || l.max_headers == 0 {
            return err("header limits too small");
        }
        if l.max_request_body == 0
            || l.request_read_timeout_ms == 0
            || l.request_header_timeout_ms == 0
            || l.audit_denials_per_second == 0
            || l.audit_denials_burst == 0
            || l.audit_summary_interval_ms == 0
        {
            return err("limits must be positive");
        }
        if let Some(b) = &self.body_policy {
            if b.max_tokens == Some(0) || b.max_tokens_fields.is_empty() {
                return err("body_policy: max_tokens and max_tokens_fields must be non-empty");
            }
            if b.models.as_ref().is_some_and(Vec::is_empty) {
                return err("body_policy: models must not be empty when set");
            }
        }
        for v in &self.anthropic_beta_allow {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic() && b != b',') {
                return err(format!("bad anthropic_beta_allow value {v:?}"));
            }
        }
        let u = &self.upstream;
        if u.connect_timeout_ms == 0
            || u.response_header_timeout_ms == 0
            || u.idle_timeout_ms == 0
            || u.max_duration_ms == 0
        {
            return err("timeouts must be positive");
        }
        Ok(())
    }
}

pub(crate) fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"{
      "upstream": {"host": "api.anthropic.com"},
      "credential": {"file": "/etc/tessera/key", "inject": "x-api-key"},
      "routes": [{"method": "POST", "path": "/v1/messages"}],
      "sandboxes": [{"label": "a1", "socket": "/run/t/a1.sock"}]
    }"#;

    #[test]
    fn minimal_config_defaults() {
        let c = ProxyConfig::from_json(MIN).unwrap();
        c.validate().unwrap();
        assert_eq!(c.upstream.port, 443);
        assert!(!c.upstream.allow_private);
        assert_eq!(c.credential.inject, Injection::XApiKey);
        assert_eq!(c.routes[0].match_kind, MatchKind::Exact);
        assert!(c.routes[0].allow_query);
        assert_eq!(c.sandboxes[0].budget.requests_per_minute, 120);
        // Review 2026-11-26 F-1: bounded request body by default.
        assert_eq!(c.limits.max_request_body, 4 << 20);
        assert_eq!(c.limits.request_header_timeout_ms, 30_000);
        assert!(c.body_policy.is_none());
        assert!(c.anthropic_beta_allow.is_empty());
        assert!(c.routes[0].json_body && c.routes[0].token_cap);
    }

    #[test]
    fn body_policy_defaults() {
        let c = ProxyConfig::from_json(
            &MIN.replace("\"sandboxes\"", "\"body_policy\": {}, \"sandboxes\""),
        )
        .unwrap();
        c.validate().unwrap();
        let b = c.body_policy.unwrap();
        assert_eq!(b.deny_keys, ["mcp_servers"]);
        assert_eq!(b.allowed_tool_types, ["custom", "function"]);
        assert!(b.max_tokens.is_none() && b.models.is_none());
    }

    #[test]
    fn rejects_bad_configs() {
        let bad = [
            MIN.replace("\"POST\"", "\"CONNECT\""),
            MIN.replace("\"POST\"", "\"post\""),
            MIN.replace("/v1/messages", "/v1/../admin"),
            MIN.replace("/v1/messages", "/v1/%2e%2e"),
            MIN.replace("/v1/messages", "v1"),
            MIN.replace("\"a1\"", "\"a 1\""),
            MIN.replace("/run/t/a1.sock", "rel.sock"),
            MIN.replace("\"x-api-key\"", "\"cookie\""),
            MIN.replace("\"host\"", "\"hots\""),
        ];
        for b in bad {
            let r = ProxyConfig::from_json(&b).and_then(|c| c.validate());
            assert!(r.is_err(), "{b}");
        }
    }
}
