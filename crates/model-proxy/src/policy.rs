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
];

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
}

impl Denial {
    /// HTTP status returned to the sandbox.
    pub fn status(&self) -> u16 {
        match self {
            Self::BadTarget | Self::BodyReadFailed => 400,
            // Lifetime budgets do not refill: 403 so harnesses stop retrying.
            Self::RouteNotAllowed | Self::UpgradeNotAllowed | Self::BudgetExhausted(_) => 403,
            Self::BodyTooLarge => 413,
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
        }
    }
}

/// Validate an origin-form path (no query). Rejects dot segments, empty
/// segments other than a trailing slash, and percent-encoded dot, slash,
/// backslash or NUL (which an upstream might normalise differently).
pub fn clean_path(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|p| lower.contains(p))
    {
        return false;
    }
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    !segments
        .iter()
        .enumerate()
        .any(|(i, seg)| *seg == "." || *seg == ".." || (seg.is_empty() && i != last))
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
    routes.iter().any(|r| {
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
    forward_only: Option<HashSet<HeaderName>>,
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
    pub fn new(
        credential_header: &str,
        strip_request: &[String],
        forward_only: Option<&[String]>,
        strip_response: &[String],
    ) -> Result<Self, String> {
        let cred = [credential_header.to_owned()];
        let mut req = names(ALWAYS_STRIP_REQUEST, strip_request)?;
        req.extend(names(&[], &cred)?);
        let mut resp = names(ALWAYS_STRIP_RESPONSE, strip_response)?;
        resp.extend(names(&[], &cred)?);
        let forward_only = match forward_only {
            Some(list) => Some(names(&[], list)?),
            None => None,
        };
        Ok(Self {
            strip_request: req,
            forward_only,
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
            if self.strip_request.contains(name) || hop.contains(name) {
                continue;
            }
            if let Some(allow) = &self.forward_only
                && !allow.contains(name)
            {
                continue;
            }
            out.append(name.clone(), value.clone());
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
        assert!(!route_allows(&routes, &Method::DELETE, "/v1/models/x", false));
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
        let p = HeaderPolicy::new("x-api-key", &["x-extra".into()], None, &[]).unwrap();
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

        let only = HeaderPolicy::new("x-api-key", &[], Some(&["content-type".into()]), &[]).unwrap();
        let out = only.filter_request(&h);
        assert_eq!(out.len(), 1);

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
