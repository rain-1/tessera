//! Request admission: route matching and header filtering.

use std::collections::HashSet;

use http::header::{HeaderMap, HeaderName};
use http::{Method, Uri};

/// Hard cap on the request path (without query).
pub const MAX_PATH_LEN: usize = 2048;
/// Hard cap on the query string.
pub const MAX_QUERY_LEN: usize = 2048;

/// Request headers that are never forwarded: credentials the sandbox might
/// try to substitute, hop-by-hop and framing headers (the proxy re-frames),
/// forwarding metadata, and `accept-encoding` (the proxy forces `identity`
/// so it can scan the response body for the credential).
pub const ALWAYS_STRIP_REQUEST: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "proxy-authorization",
    "proxy-authenticate",
    "cookie",
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "expect",
    "forwarded",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "accept-encoding",
    "http2-settings",
    // Requests with a non-identity encoding are refused (F-5); `identity`
    // is dropped.
    "content-encoding",
];

/// Request headers forwarded when `forward_request_headers` is not
/// configured. Everything else (for example `openai-organization`,
/// `openai-project`, which select the billed account) is dropped.
/// `anthropic-beta` values are further filtered by `anthropic_beta_allow`,
/// which is empty by default.
pub const DEFAULT_FORWARD_REQUEST: &[&str] = &[
    "content-type",
    "accept",
    "user-agent",
    "anthropic-version",
    "anthropic-beta",
];

/// Header whose comma-separated values are filtered by `anthropic_beta_allow`.
pub const ANTHROPIC_BETA: &str = "anthropic-beta";

/// Response headers that are never returned: credential-shaped headers,
/// cookies, hop-by-hop and framing headers (the proxy re-frames the body,
/// which may change its length when redacting), and protocol upgrade hints.
pub const ALWAYS_STRIP_RESPONSE: &[&str] = &[
    "authorization",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "proxy-authenticate",
    "set-cookie",
    "set-cookie2",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "alt-svc",
];

/// A compiled route.
#[derive(Clone, Debug)]
pub struct Route {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) prefix: bool,
    pub(crate) allow_query: bool,
    pub(crate) json_body: bool,
    pub(crate) token_cap: bool,
}

/// Why a request was refused before contacting the upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Request target is not origin-form (absolute-form, authority-form,
    /// asterisk) or is malformed.
    BadTarget,
    /// No route allows this method + path.
    RouteNotAllowed,
    /// Upgrade / CONNECT / tunnelling requested.
    UpgradeNotAllowed,
    /// Request body exceeds the limit.
    BodyTooLarge,
    /// Request body not received in time or unreadable.
    BodyReadFailed,
    /// Token bucket empty.
    RateLimited,
    /// Concurrency limit reached.
    TooManyInFlight,
    /// A lifetime budget is exhausted.
    BudgetExhausted(&'static str),
    /// The request body is compressed or otherwise encoded.
    ContentEncoding,
    /// The request body is not a JSON object (body policy).
    BodyNotJson,
    /// The JSON body policy refused the request.
    BodyPolicy(&'static str),
}

impl Denial {
    /// HTTP status returned to the sandbox.
    pub fn status(&self) -> u16 {
        match self {
            Self::BadTarget | Self::BodyReadFailed | Self::BodyNotJson => 400,
            // Lifetime budgets do not refill: 403 so harnesses stop retrying.
            Self::RouteNotAllowed
            | Self::UpgradeNotAllowed
            | Self::BudgetExhausted(_)
            | Self::BodyPolicy(_) => 403,
            Self::BodyTooLarge => 413,
            Self::ContentEncoding => 415,
            Self::RateLimited | Self::TooManyInFlight => 429,
        }
    }

    /// Short machine-readable reason (audit + error body).
    pub fn reason(&self) -> String {
        match self {
            Self::BadTarget => "bad_target".into(),
            Self::RouteNotAllowed => "route_not_allowed".into(),
            Self::UpgradeNotAllowed => "upgrade_not_allowed".into(),
            Self::BodyTooLarge => "body_too_large".into(),
            Self::BodyReadFailed => "body_read_failed".into(),
            Self::RateLimited => "rate_limited".into(),
            Self::TooManyInFlight => "too_many_in_flight".into(),
            Self::BudgetExhausted(what) => format!("budget_exhausted:{what}"),
            Self::ContentEncoding => "content_encoding_not_allowed".into(),
            Self::BodyNotJson => "body_not_json_object".into(),
            Self::BodyPolicy(what) => format!("body_policy:{what}"),
        }
    }
}

/// Validate an origin-form path (no query) with the HTTPS adapter's rules
/// ([`tessera_adapter_https::clean_path`]): no dot segments, no empty
/// segments other than a trailing slash, no `;` path parameters, no
/// percent-encoded dot, slash, backslash or NUL, no malformed escapes, and
/// no segment that is still escaped or is a dot segment after one round of
/// decoding (`%252e%252e`, `%25%32%65`). An upstream might normalise any of
/// these differently from the route match.
pub fn clean_path(path: &str) -> bool {
    tessera_adapter_https::clean_path(path)
}

/// Split and validate the request target. Returns `(path, query)`.
pub fn origin_form(uri: &Uri) -> Result<(String, Option<String>), Denial> {
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(Denial::BadTarget);
    }
    let pq = uri.path_and_query().ok_or(Denial::BadTarget)?;
    let path = pq.path();
    let query = pq.query();
    let visible = |s: &str| {
        s.bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'#' && b != b'\\')
    };
    if path.is_empty() || path.len() > MAX_PATH_LEN || !visible(path) || !clean_path(path) {
        return Err(Denial::BadTarget);
    }
    if let Some(q) = query
        && (q.len() > MAX_QUERY_LEN || !visible(q))
    {
        return Err(Denial::BadTarget);
    }
    Ok((path.to_owned(), query.map(str::to_owned)))
}

/// Whether some route admits `method` + `path` (+ query presence).
pub fn route_allows(routes: &[Route], method: &Method, path: &str, has_query: bool) -> bool {
    find_route(routes, method, path, has_query).is_some()
}

/// The first route admitting `method` + `path` (+ query presence).
pub fn find_route<'a>(
    routes: &'a [Route],
    method: &Method,
    path: &str,
    has_query: bool,
) -> Option<&'a Route> {
    routes.iter().find(|r| {
        if r.method != *method || (has_query && !r.allow_query) {
            return false;
        }
        if path == r.path {
            return true;
        }
        r.prefix
            && path
                .strip_prefix(r.path.as_str())
                .is_some_and(|rest| r.path.ends_with('/') || rest.starts_with('/'))
    })
}

/// Header filter compiled from configuration.
#[derive(Clone, Debug)]
pub struct HeaderPolicy {
    strip_request: HashSet<HeaderName>,
    forward_only: HashSet<HeaderName>,
    beta_allow: HashSet<String>,
    strip_response: HashSet<HeaderName>,
}

fn names(list: &[&str], extra: &[String]) -> Result<HashSet<HeaderName>, String> {
    let mut set = HashSet::new();
    for n in list.iter().copied().chain(extra.iter().map(String::as_str)) {
        set.insert(HeaderName::from_bytes(n.as_bytes()).map_err(|_| format!("bad header {n:?}"))?);
    }
    Ok(set)
}

impl HeaderPolicy {
    /// Compile. `credential_header` is always stripped in both directions.
    /// `forward_only` is the request header allowlist; `None` selects
    /// [`DEFAULT_FORWARD_REQUEST`]. `beta_allow` lists the `anthropic-beta`
    /// values that may be forwarded.
    pub fn new(
        credential_header: &str,
        strip_request: &[String],
        forward_only: Option<&[String]>,
        strip_response: &[String],
        beta_allow: &[String],
    ) -> Result<Self, String> {
        let cred = [credential_header.to_owned()];
        let mut req = names(ALWAYS_STRIP_REQUEST, strip_request)?;
        req.extend(names(&[], &cred)?);
        let mut resp = names(ALWAYS_STRIP_RESPONSE, strip_response)?;
        resp.extend(names(&[], &cred)?);
        let forward_only = match forward_only {
            Some(list) => names(&[], list)?,
            None => names(DEFAULT_FORWARD_REQUEST, &[])?,
        };
        Ok(Self {
            strip_request: req,
            forward_only,
            beta_allow: beta_allow.iter().cloned().collect(),
            strip_response: resp,
        })
    }

    /// Headers named in `Connection:` are hop-by-hop too.
    fn connection_named(headers: &HeaderMap) -> HashSet<HeaderName> {
        headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
            .collect()
    }

    /// Request headers to forward upstream.
    pub fn filter_request(&self, headers: &HeaderMap) -> HeaderMap {
        let hop = Self::connection_named(headers);
        let mut out = HeaderMap::new();
        for (name, value) in headers {
            if self.strip_request.contains(name)
                || hop.contains(name)
                || !self.forward_only.contains(name)
                || name == ANTHROPIC_BETA
            {
                continue;
            }
            out.append(name.clone(), value.clone());
        }
        // `anthropic-beta`: keep only allowlisted values, merged into one
        // header; drop it when none remain.
        let beta = HeaderName::from_static(ANTHROPIC_BETA);
        if self.forward_only.contains(&beta) && !hop.contains(&beta) {
            let mut kept: Vec<&str> = Vec::new();
            for v in headers.get_all(ANTHROPIC_BETA) {
                let Ok(v) = v.to_str() else { continue };
                for item in v.split(',').map(str::trim) {
                    if self.beta_allow.contains(item) && !kept.contains(&item) {
                        kept.push(item);
                    }
                }
            }
            if !kept.is_empty()
                && let Ok(v) = kept.join(",").parse()
            {
                out.insert(ANTHROPIC_BETA, v);
            }
        }
        out
    }

    /// Response headers to return to the sandbox. Any header whose value
    /// contains `secret` is dropped as well.
    pub fn filter_response(&self, headers: &HeaderMap, secret: &[u8]) -> HeaderMap {
        let hop = Self::connection_named(headers);
        let mut out = HeaderMap::new();
        for (name, value) in headers {
            if self.strip_response.contains(name)
                || hop.contains(name)
                || crate::secret::contains(value.as_bytes(), secret)
            {
                continue;
            }
            out.append(name.clone(), value.clone());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(m: &str, p: &str, prefix: bool) -> Route {
        Route {
            method: Method::from_bytes(m.as_bytes()).unwrap(),
            path: p.into(),
            prefix,
            allow_query: true,
            json_body: true,
            token_cap: true,
        }
    }

    #[test]
    fn route_matching() {
        let routes = vec![
            route("POST", "/v1/messages", false),
            route("POST", "/v1/messages/count_tokens", false),
            route("GET", "/v1/models", true),
        ];
        assert!(route_allows(&routes, &Method::POST, "/v1/messages", true));
        assert!(route_allows(
            &routes,
            &Method::POST,
            "/v1/messages/count_tokens",
            false
        ));
        assert!(!route_allows(
            &routes,
            &Method::POST,
            "/v1/messages/batches",
            false
        ));
        assert!(!route_allows(&routes, &Method::GET, "/v1/messages", false));
        assert!(route_allows(&routes, &Method::GET, "/v1/models", false));
        assert!(route_allows(&routes, &Method::GET, "/v1/models/x", false));
        assert!(!route_allows(&routes, &Method::GET, "/v1/modelsx", false));
        assert!(!route_allows(
            &routes,
            &Method::DELETE,
            "/v1/models/x",
            false
        ));
        let mut no_q = route("POST", "/v1/messages", false);
        no_q.allow_query = false;
        assert!(!route_allows(&[no_q], &Method::POST, "/v1/messages", true));
    }

    #[test]
    fn targets() {
        let ok = ["/v1/messages", "/v1/messages?beta=true", "/"];
        for t in ok {
            assert!(origin_form(&t.parse().unwrap()).is_ok(), "{t}");
        }
        let bad = [
            "http://evil.example/v1/messages",
            "https://api.anthropic.com/v1/messages",
            "evil.example:443",
            "*",
            "/v1/../admin",
            "/v1/./messages",
            "/v1//messages",
            "//evil.example/v1",
            "/v1/%2e%2e/admin",
            "/v1/x%2Fy",
            // Review 2026-11-26 F-4.
            "/v1/models/..;/messages",
            "/v1/x;a=b",
            "/v1/%252e%252e/files",
            "/v1/%25%32%65%25%32%65",
            "/v1/%zz",
            "/v1/%2",
        ];
        for t in bad {
            let parsed: Result<Uri, _> = t.parse();
            if let Ok(u) = parsed {
                assert!(origin_form(&u).is_err(), "{t}");
            }
        }
    }

    #[test]
    fn header_filtering() {
        let p = HeaderPolicy::new("x-api-key", &["x-extra".into()], None, &[], &[]).unwrap();
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("authorization", "Bearer sandbox"),
            ("x-api-key", "sandbox"),
            ("cookie", "a=b"),
            ("host", "evil.example"),
            ("accept-encoding", "gzip"),
            ("connection", "x-hop"),
            ("x-hop", "1"),
            ("x-extra", "1"),
            ("anthropic-version", "2023-06-01"),
            ("content-type", "application/json"),
        ] {
            h.append(HeaderName::from_static(k), v.parse().unwrap());
        }
        let out = p.filter_request(&h);
        let kept: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(out.contains_key("anthropic-version"));
        assert!(out.contains_key("content-type"));

        let only =
            HeaderPolicy::new("x-api-key", &[], Some(&["content-type".into()]), &[], &[]).unwrap();
        let out = only.filter_request(&h);
        assert_eq!(out.len(), 1);

        // Default allowlist drops account selection headers and unlisted
        // `anthropic-beta` values; the explicit allowlist cannot re-enable
        // a stripped header.
        let mut sel = HeaderMap::new();
        for (k, v) in [
            ("openai-organization", "org-x"),
            ("openai-project", "proj-x"),
            ("anthropic-beta", "a, b"),
            ("anthropic-beta", "c"),
            ("content-encoding", "gzip"),
        ] {
            sel.append(HeaderName::from_static(k), v.parse().unwrap());
        }
        assert!(p.filter_request(&sel).is_empty());
        let beta = HeaderPolicy::new(
            "x-api-key",
            &[],
            Some(&["anthropic-beta".into(), "x-api-key".into()]),
            &[],
            &["c".into(), "a".into()],
        )
        .unwrap();
        let out = beta.filter_request(&sel);
        assert_eq!(out.len(), 1);
        assert_eq!(out["anthropic-beta"], "a,c");

        let mut r = HeaderMap::new();
        r.append("x-echo", "key=sk-SECRET-1".parse().unwrap());
        r.append("x-api-key", "whatever".parse().unwrap());
        r.append("set-cookie", "s=1".parse().unwrap());
        r.append("content-type", "text/event-stream".parse().unwrap());
        let out = p.filter_response(&r, b"sk-SECRET-1");
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("content-type"));
    }
}
