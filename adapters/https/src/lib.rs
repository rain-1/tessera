//! Tessera trusted HTTPS adapter (specification §9.4).
//!
//! An administrator registers *endpoints* ([`EndpointConfig`]): a TLS host
//! name, port, allowed path prefix, allowed methods, header allowlists, size
//! limits and optionally a broker-held secret header. Agents never name hosts,
//! IPs, proxies or TLS settings; a grant names an [`EndpointId`], and after
//! the broker has durably committed a reservation it hands the adapter a
//! [`Reservation`] describing exactly one HTTP request attempt.
//!
//! # Unit of authority
//!
//! One reservation authorizes **one outbound HTTP/1.1 request attempt** on one
//! fresh TLS connection. There are no redirects (3xx responses are returned to
//! the caller as ordinary responses), no retries, no connection pooling, no
//! proxies and no CONNECT tunnelling.
//!
//! # Client choice
//!
//! The adapter uses hyper's *low-level connection API*
//! (`hyper::client::conn::http1`) over a TCP stream that the adapter itself
//! connects and wraps with `tokio-rustls`. That layer contains only HTTP/1.1
//! framing: redirect following, retry, pooling, proxy discovery
//! (`HTTPS_PROXY`, `ALL_PROXY`, ...) and DNS resolution simply do not exist in
//! it, so there is no default to forget to turn off. By contrast high-level
//! clients (reqwest, ureq) enable env-proxy discovery and/or redirects by
//! default and resolve names internally. The adapter therefore:
//!
//! * resolves the registered host itself (or uses admin-pinned addresses),
//! * rejects the request if **any** resolved address is loopback, link-local,
//!   private, CGNAT, ULA, multicast, unspecified, documentation/benchmark or
//!   otherwise non-global, unless the endpoint was registered with
//!   `allow_private` (intended for tests and deliberately approved internal
//!   services; unspecified/multicast/broadcast stay forbidden even then),
//! * connects to the checked IP and validates the server certificate for the
//!   *registered* host name with rustls (webpki roots or an admin-supplied CA),
//! * sends exactly one request and reads a bounded response.
//!
//! # At-most-once dispatch
//!
//! The adapter keeps an in-memory set of reservation ids. The first call with
//! an id claims it whatever the outcome (including pre-network denial); every
//! later call fails with [`HttpsError::AlreadyDispatched`]. The set is not
//! durable: durable de-duplication across restarts is the broker/journal's
//! job (§5.2, §11), and unresolved reservations must never be replayed.
//!
//! # Secrets and audit
//!
//! An optional secret header is injected by the adapter and marked sensitive.
//! Agents cannot set or read it: its name may not appear in either header
//! allowlist, and it never appears in [`HttpsEffect`], errors or `Debug`
//! output. Effects record endpoint, method, path, peer address, request body
//! length/digest and response status/length/digest — never bodies or header
//! values.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Hard cap on the size of request/response header sections.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Hard cap on the number of response headers parsed.
const MAX_RESPONSE_HEADERS: usize = 64;
/// Hard cap on agent-supplied request headers.
const MAX_REQUEST_HEADERS: usize = 32;
/// Hard cap on agent-supplied path length.
const MAX_PATH_LEN: usize = 2048;

/// Headers that agents may never set, whatever the allowlist says. They are
/// either managed by the adapter or alter connection semantics.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
];

/// Opaque reservation identifier issued by the broker.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReservationId(pub u128);

impl fmt::Debug for ReservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReservationId({:032x})", self.0)
    }
}

/// Identifier of a registered endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub u128);

impl fmt::Debug for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointId({:032x})", self.0)
    }
}

/// One HTTP request attempt, exactly as authorized.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsOperation {
    /// Request method; must be allowed by the endpoint.
    pub method: Method,
    /// Origin-form path with optional query (`/a/b?c=d`); must lie under the
    /// endpoint's prefix.
    pub path: String,
    /// Extra request headers; names must be in the endpoint allowlist.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Request body; at most the endpoint's request body limit.
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpsOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("HttpsOperation")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("header_names", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A committed reservation for one request attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Broker-issued id; at most one dispatch per id.
    pub id: ReservationId,
    /// Target endpoint.
    pub endpoint: EndpointId,
    /// Exact request.
    pub operation: HttpsOperation,
}

/// Broker-held credential injected as a request header.
#[derive(Clone)]
pub struct SecretHeader {
    name: HeaderName,
    value: HeaderValue,
}

impl SecretHeader {
    /// Build a secret header. The value is marked sensitive.
    pub fn new(name: &str, value: &[u8]) -> Result<Self, ConfigError> {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ConfigError::InvalidHeader(name.to_owned()))?;
        let mut value = HeaderValue::from_bytes(value)
            .map_err(|_| ConfigError::InvalidHeader(name.to_string()))?;
        value.set_sensitive(true);
        Ok(Self { name, value })
    }
}

impl fmt::Debug for SecretHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Which certificate authorities validate the endpoint.
#[derive(Clone, Debug)]
pub enum TlsTrust {
    /// Mozilla root program via `webpki-roots`.
    WebPki,
    /// Only these DER-encoded CA certificates (private CAs, tests).
    CustomRoots(Vec<CertificateDer<'static>>),
}

/// Administrator configuration for one endpoint.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    /// DNS name (or IP literal) used for resolution, SNI, certificate
    /// validation and the `Host` header.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Allowed path prefix (origin-form, starts with `/`). A prefix not ending
    /// in `/` matches itself and anything below `prefix/`.
    pub path_prefix: String,
    /// Allowed methods. `CONNECT` is never allowed.
    pub methods: Vec<Method>,
    /// Request header names agents may set.
    pub request_headers: Vec<String>,
    /// Response header names returned to agents; everything else is dropped.
    pub response_headers: Vec<String>,
    /// Largest request body accepted.
    pub max_request_body: u64,
    /// Largest response body accepted; larger responses are discarded.
    pub max_response_body: u64,
    /// Overall deadline for resolution, connect, TLS, request and response.
    pub timeout: Duration,
    /// Optional broker-held credential header.
    pub secret_header: Option<SecretHeader>,
    /// Permit non-global destination addresses (tests / approved internal).
    pub allow_private: bool,
    /// Admin-pinned destination addresses; when set, DNS is not consulted.
    pub pinned_addrs: Option<Vec<IpAddr>>,
    /// Certificate trust.
    pub tls: TlsTrust,
}

impl EndpointConfig {
    /// A conservative configuration: GET only, 64 KiB request, 1 MiB
    /// response, 30 s deadline, webpki roots, global addresses only.
    pub fn new(host: &str, port: u16, path_prefix: &str) -> Self {
        Self {
            host: host.to_owned(),
            port,
            path_prefix: path_prefix.to_owned(),
            methods: vec![Method::GET],
            request_headers: Vec::new(),
            response_headers: vec!["content-type".to_owned()],
            max_request_body: 64 * 1024,
            max_response_body: 1024 * 1024,
            timeout: Duration::from_secs(30),
            secret_header: None,
            allow_private: false,
            pinned_addrs: None,
            tls: TlsTrust::WebPki,
        }
    }
}

/// Endpoint registration failure.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Host is not a valid DNS name or IP address.
    InvalidHost,
    /// Prefix is not a clean origin-form path.
    InvalidPrefix,
    /// Method set empty or contains CONNECT.
    InvalidMethods,
    /// Header name invalid, forbidden, or collides with the secret header.
    InvalidHeader(String),
    /// Endpoint id already registered.
    AlreadyRegistered(EndpointId),
    /// TLS configuration could not be built.
    Tls(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

/// Reason a request was refused before any connection to the endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// No endpoint with this id.
    UnknownEndpoint(EndpointId),
    /// Method not allowed for the endpoint.
    MethodNotAllowed,
    /// Path malformed or outside the allowed prefix.
    PathNotAllowed,
    /// Header not allowlisted, forbidden, malformed or too many.
    HeaderNotAllowed(String),
    /// Request body exceeds the limit.
    BodyTooLarge {
        /// Limit.
        limit: u64,
        /// Requested size.
        size: u64,
    },
    /// Host did not resolve.
    ResolutionFailed,
    /// A resolved/pinned address is of a forbidden class.
    DestinationForbidden(IpAddr),
}

/// How a dispatched attempt ended (recorded in the effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectOutcome {
    /// A complete response within limits.
    Response {
        /// HTTP status.
        status: u16,
        /// Response body length.
        body_len: u64,
        /// SHA-256 of the response body.
        body_sha256: [u8; 32],
    },
    /// The server answered but the body exceeded the limit; body discarded.
    ResponseTooLarge {
        /// HTTP status.
        status: u16,
        /// Response limit.
        limit: u64,
    },
    /// TCP connect failed; no request bytes were sent.
    ConnectFailed(String),
    /// TLS handshake or certificate validation failed; no request bytes were
    /// sent.
    TlsFailed(String),
    /// HTTP-level failure; the request may or may not have reached the server.
    ProtocolError(String),
    /// Deadline expired; the request may or may not have reached the server.
    TimedOut,
}

impl EffectOutcome {
    /// Whether request bytes may have reached the remote server.
    pub fn may_have_reached_server(&self) -> bool {
        !matches!(self, Self::ConnectFailed(_) | Self::TlsFailed(_))
    }
}

/// Audit record of one dispatched request attempt. Contains no header
/// values or bodies.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsEffect {
    /// Reservation that authorized the attempt.
    pub reservation: ReservationId,
    /// Target endpoint.
    pub endpoint: EndpointId,
    /// Registered host name.
    pub host: String,
    /// Peer address actually connected to (if a connection was made).
    pub peer: Option<SocketAddr>,
    /// Method.
    pub method: Method,
    /// Path and query.
    pub path: String,
    /// Request body length.
    pub request_body_len: u64,
    /// SHA-256 of the request body.
    pub request_body_sha256: [u8; 32],
    /// Outcome.
    pub outcome: EffectOutcome,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl fmt::Debug for HttpsEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsEffect")
            .field("reservation", &self.reservation)
            .field("endpoint", &self.endpoint)
            .field("host", &self.host)
            .field("peer", &self.peer)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("request_body_len", &self.request_body_len)
            .field("request_body_sha256", &hex(&self.request_body_sha256))
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Bounded response returned to the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsResponse {
    /// HTTP status (3xx are returned, never followed).
    pub status: u16,
    /// Allowlisted response headers only.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body (≤ endpoint response limit).
    pub body: Bytes,
}

impl fmt::Debug for HttpsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("HttpsResponse")
            .field("status", &self.status)
            .field("header_names", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Successful attempt: effect record plus bounded response.
#[derive(Debug, Clone)]
pub struct HttpsDispatch {
    /// Audit record.
    pub effect: HttpsEffect,
    /// Response for the caller.
    pub response: HttpsResponse,
}

/// Dispatch failure. Every failure consumes the reservation id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsError {
    /// This reservation id was already dispatched or attempted.
    AlreadyDispatched(ReservationId),
    /// Refused before connecting to the endpoint; no request was sent.
    Denied(Denial),
    /// An attempt was made but did not yield an acceptable response; see
    /// `effect.outcome`.
    Failed(Box<HttpsEffect>),
}

impl fmt::Display for HttpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for HttpsError {}

struct Endpoint {
    host: String,
    server_name: ServerName<'static>,
    port: u16,
    prefix: String,
    methods: Vec<Method>,
    request_headers: HashSet<HeaderName>,
    response_headers: HashSet<HeaderName>,
    max_request_body: u64,
    max_response_body: u64,
    timeout: Duration,
    secret: Option<SecretHeader>,
    allow_private: bool,
    pinned: Option<Vec<IpAddr>>,
    tls: TlsConnector,
}

/// The trusted HTTPS adapter. See the crate documentation.
#[derive(Default)]
pub struct HttpsAdapter {
    endpoints: RwLock<HashMap<EndpointId, Arc<Endpoint>>>,
    dispatched: Mutex<HashSet<ReservationId>>,
}

impl fmt::Debug for HttpsAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsAdapter").finish_non_exhaustive()
    }
}

fn header_set(
    names: &[String],
    secret: Option<&HeaderName>,
) -> Result<HashSet<HeaderName>, ConfigError> {
    let mut set = HashSet::new();
    for n in names {
        let name = HeaderName::from_bytes(n.as_bytes())
            .map_err(|_| ConfigError::InvalidHeader(n.clone()))?;
        if FORBIDDEN_HEADERS.contains(&name.as_str()) || Some(&name) == secret {
            return Err(ConfigError::InvalidHeader(n.clone()));
        }
        set.insert(name);
    }
    Ok(set)
}

/// Validate an origin-form path (no query) used as a prefix, or the path part
/// of a request.
fn clean_path(path: &str) -> bool {
    if !path.starts_with('/') || path.starts_with("//") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    // Encoded dot, slash, backslash or NUL could be re-interpreted downstream.
    if ["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|p| lower.contains(p))
    {
        return false;
    }
    // No dot segments; empty segments only as a trailing slash.
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    !segments
        .iter()
        .enumerate()
        .any(|(i, seg)| *seg == "." || *seg == ".." || (seg.is_empty() && i != last))
}

fn path_allowed(path: &str, prefix: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return false;
    }
    // Visible ASCII only: no spaces, controls, non-ASCII, fragments or
    // backslashes.
    if !path
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && b != b'#' && b != b'\\')
    {
        return false;
    }
    if path.parse::<http::uri::PathAndQuery>().is_err() {
        return false;
    }
    let path_part = path.split('?').next().unwrap_or_default();
    if !clean_path(path_part) {
        return false;
    }
    if path_part == prefix {
        return true;
    }
    match path_part.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
}

/// Whether `ip` is a destination the adapter refuses by default (anything not
/// globally routable unicast). With `allow_private`, only unspecified,
/// multicast and broadcast remain forbidden.
pub fn is_forbidden(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_forbidden(v4, allow_private),
        IpAddr::V6(v6) => v6_forbidden(v6, allow_private),
    }
}

fn v4_forbidden(ip: Ipv4Addr, allow_private: bool) -> bool {
    let o = ip.octets();
    let always = ip.is_unspecified() || o[0] == 0 || ip.is_multicast() || ip.is_broadcast();
    if always {
        return true;
    }
    if allow_private {
        return false;
    }
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_documentation()
        || o[0] >= 240 // reserved
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay anycast
}

fn v6_forbidden(ip: Ipv6Addr, allow_private: bool) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_forbidden(v4, allow_private);
    }
    let s = ip.segments();
    let always = ip.is_unspecified() || ip.is_multicast();
    if always {
        return true;
    }
    if allow_private {
        return false;
    }
    ip.is_loopback()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23 IETF special (incl. Teredo)
        || s[0] == 0x2002 // 6to4: embeds an arbitrary IPv4 address
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64: embeds IPv4
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard-only
        || s[0..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible (deprecated)
        || (s[0] & 0xe000) != 0x2000 // outside 2000::/3 global unicast
}

fn build_tls(trust: &TlsTrust) -> Result<TlsConnector, ConfigError> {
    let mut roots = rustls::RootCertStore::empty();
    match trust {
        TlsTrust::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        TlsTrust::CustomRoots(certs) => {
            for c in certs {
                roots
                    .add(c.clone())
                    .map_err(|e| ConfigError::Tls(e.to_string()))?;
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ConfigError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

impl HttpsAdapter {
    /// Empty adapter with no endpoints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an endpoint after validating its configuration.
    pub fn register(&self, id: EndpointId, cfg: EndpointConfig) -> Result<(), ConfigError> {
        let server_name =
            ServerName::try_from(cfg.host.clone()).map_err(|_| ConfigError::InvalidHost)?;
        if !clean_path(&cfg.path_prefix) || cfg.path_prefix.contains(['?', '#']) {
            return Err(ConfigError::InvalidPrefix);
        }
        if cfg.methods.is_empty() || cfg.methods.contains(&Method::CONNECT) {
            return Err(ConfigError::InvalidMethods);
        }
        let secret_name = cfg.secret_header.as_ref().map(|s| &s.name);
        if let Some(name) = secret_name
            && FORBIDDEN_HEADERS.contains(&name.as_str())
        {
            return Err(ConfigError::InvalidHeader(name.to_string()));
        }
        let request_headers = header_set(&cfg.request_headers, secret_name)?;
        let response_headers = header_set(&cfg.response_headers, secret_name)?;
        let endpoint = Endpoint {
            host: cfg.host,
            server_name,
            port: cfg.port,
            prefix: cfg.path_prefix,
            methods: cfg.methods,
            request_headers,
            response_headers,
            max_request_body: cfg.max_request_body,
            max_response_body: cfg.max_response_body,
            timeout: cfg.timeout,
            secret: cfg.secret_header,
            allow_private: cfg.allow_private,
            pinned: cfg.pinned_addrs,
            tls: build_tls(&cfg.tls)?,
        };
        let mut map = self
            .endpoints
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if map.contains_key(&id) {
            return Err(ConfigError::AlreadyRegistered(id));
        }
        map.insert(id, Arc::new(endpoint));
        Ok(())
    }

    /// Remove an endpoint. In-flight dispatches finish.
    pub fn unregister(&self, id: EndpointId) -> bool {
        self.endpoints
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)
            .is_some()
    }

    /// Whether this instance has claimed the reservation id.
    pub fn was_dispatched(&self, id: ReservationId) -> bool {
        self.dispatched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&id)
    }

    /// Execute at most one request attempt for `reservation`. Must be called
    /// within a Tokio runtime (the connection task is spawned on it).
    pub async fn dispatch(&self, reservation: &Reservation) -> Result<HttpsDispatch, HttpsError> {
        if !self
            .dispatched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(reservation.id)
        {
            return Err(HttpsError::AlreadyDispatched(reservation.id));
        }
        let ep = self
            .endpoints
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&reservation.endpoint)
            .cloned()
            .ok_or(HttpsError::Denied(Denial::UnknownEndpoint(
                reservation.endpoint,
            )))?;
        let op = &reservation.operation;
        let request = build_request(&ep, op).map_err(HttpsError::Denied)?;

        let mut effect = HttpsEffect {
            reservation: reservation.id,
            endpoint: reservation.endpoint,
            host: ep.host.clone(),
            peer: None,
            method: op.method.clone(),
            path: op.path.clone(),
            request_body_len: op.body.len() as u64,
            request_body_sha256: Sha256::digest(&op.body).into(),
            outcome: EffectOutcome::TimedOut,
        };

        let deadline = tokio::time::Instant::now() + ep.timeout;
        let addrs = tokio::time::timeout_at(deadline, resolve(&ep))
            .await
            .map_err(|_| HttpsError::Denied(Denial::ResolutionFailed))?
            .map_err(HttpsError::Denied)?;

        let attempt = attempt(&ep, addrs, request, &mut effect.peer);
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(Ok((outcome, response))) => {
                effect.outcome = outcome;
                match response {
                    Some(response) => Ok(HttpsDispatch { effect, response }),
                    None => Err(HttpsError::Failed(Box::new(effect))),
                }
            }
            Ok(Err(outcome)) => {
                effect.outcome = outcome;
                Err(HttpsError::Failed(Box::new(effect)))
            }
            Err(_) => {
                effect.outcome = EffectOutcome::TimedOut;
                Err(HttpsError::Failed(Box::new(effect)))
            }
        }
    }
}

fn build_request(ep: &Endpoint, op: &HttpsOperation) -> Result<Request<Full<Bytes>>, Denial> {
    if !ep.methods.contains(&op.method) {
        return Err(Denial::MethodNotAllowed);
    }
    if !path_allowed(&op.path, &ep.prefix) {
        return Err(Denial::PathNotAllowed);
    }
    let size = op.body.len() as u64;
    if size > ep.max_request_body {
        return Err(Denial::BodyTooLarge {
            limit: ep.max_request_body,
            size,
        });
    }
    if op.headers.len() > MAX_REQUEST_HEADERS {
        return Err(Denial::HeaderNotAllowed("too many headers".to_owned()));
    }
    let header_bytes: usize = op.headers.iter().map(|(n, v)| n.len() + v.len()).sum();
    if header_bytes > MAX_HEADER_BYTES {
        return Err(Denial::HeaderNotAllowed("headers too large".to_owned()));
    }
    let host_header = if ep.port == 443 {
        ep.host.clone()
    } else if ep.host.contains(':') {
        format!("[{}]:{}", ep.host, ep.port)
    } else {
        format!("{}:{}", ep.host, ep.port)
    };
    let mut builder = Request::builder()
        .method(op.method.clone())
        .uri(op.path.as_str())
        .header(http::header::HOST, host_header);
    for (name, value) in &op.headers {
        let hn = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Denial::HeaderNotAllowed(name.clone()))?;
        if !ep.request_headers.contains(&hn) {
            return Err(Denial::HeaderNotAllowed(name.clone()));
        }
        let hv =
            HeaderValue::from_bytes(value).map_err(|_| Denial::HeaderNotAllowed(name.clone()))?;
        builder = builder.header(hn, hv);
    }
    if let Some(secret) = &ep.secret {
        builder = builder.header(secret.name.clone(), secret.value.clone());
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(&op.body)))
        .map_err(|_| Denial::PathNotAllowed)
}

async fn resolve(ep: &Endpoint) -> Result<Vec<SocketAddr>, Denial> {
    let ips: Vec<IpAddr> = if let Some(pinned) = &ep.pinned {
        pinned.clone()
    } else if let Ok(ip) = ep.host.parse::<IpAddr>() {
        vec![ip]
    } else {
        tokio::net::lookup_host((ep.host.as_str(), ep.port))
            .await
            .map_err(|_| Denial::ResolutionFailed)?
            .map(|sa| sa.ip())
            .collect()
    };
    let mut out: Vec<SocketAddr> = Vec::new();
    for ip in ips {
        // Reject if *any* candidate is forbidden: a mixed answer indicates a
        // rebinding attempt or misconfiguration.
        if is_forbidden(ip, ep.allow_private) {
            return Err(Denial::DestinationForbidden(ip));
        }
        let sa = SocketAddr::new(ip, ep.port);
        if !out.contains(&sa) {
            out.push(sa);
        }
    }
    if out.is_empty() {
        return Err(Denial::ResolutionFailed);
    }
    Ok(out)
}

/// Connect, handshake and perform the single request. `Ok((outcome, None))`
/// means the server answered but the response was rejected.
async fn attempt(
    ep: &Endpoint,
    addrs: Vec<SocketAddr>,
    request: Request<Full<Bytes>>,
    peer: &mut Option<SocketAddr>,
) -> Result<(EffectOutcome, Option<HttpsResponse>), EffectOutcome> {
    // Trying further addresses is safe: no request bytes have been sent
    // until a TCP connection exists.
    let mut last_err = String::from("no address");
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => {
                *peer = Some(addr);
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = e.kind().to_string(),
        }
    }
    let tcp = tcp.ok_or(EffectOutcome::ConnectFailed(last_err))?;
    let _ = tcp.set_nodelay(true);
    let tls = ep
        .tls
        .connect(ep.server_name.clone(), tcp)
        .await
        .map_err(|e| EffectOutcome::TlsFailed(e.to_string()))?;

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(MAX_HEADER_BYTES.max(8192))
        .max_headers(MAX_RESPONSE_HEADERS)
        .handshake(TokioIo::new(tls))
        .await
        .map_err(|e| EffectOutcome::ProtocolError(e.to_string()))?;
    // Abort the connection task however this future ends (including being
    // dropped by the deadline), so no connection outlives the attempt.
    let _conn = AbortOnDrop(tokio::spawn(conn));
    exchange(ep, &mut sender, request).await
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn exchange(
    ep: &Endpoint,
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> Result<(EffectOutcome, Option<HttpsResponse>), EffectOutcome> {
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| EffectOutcome::ProtocolError(e.to_string()))?;
    let status = response.status().as_u16();
    let limit = ep.max_response_body;
    let too_large = EffectOutcome::ResponseTooLarge { status, limit };
    let declared = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit) {
        return Ok((too_large, None));
    }
    let headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .filter(|(n, _)| ep.response_headers.contains(*n))
        .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect();
    let mut body = response.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| EffectOutcome::ProtocolError(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if (buf.len() as u64).saturating_add(data.len() as u64) > limit {
                return Ok((too_large, None));
            }
            buf.extend_from_slice(&data);
        }
    }
    let body = Bytes::from(buf);
    let outcome = EffectOutcome::Response {
        status,
        body_len: body.len() as u64,
        body_sha256: Sha256::digest(&body).into(),
    };
    Ok((
        outcome,
        Some(HttpsResponse {
            status,
            headers,
            body,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_classes() {
        let forbidden = [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:7f00:1::1",
            "64:ff9b::7f00:1",
            "100::1",
        ];
        for a in forbidden {
            assert!(is_forbidden(a.parse().unwrap(), false), "{a}");
        }
        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
            "::ffff:1.1.1.1",
            "2606:4700::1111",
            "2a00:1450::1",
        ];
        for a in allowed {
            assert!(!is_forbidden(a.parse().unwrap(), false), "{a}");
        }
        // allow_private opens internal ranges but never unspecified/multicast.
        assert!(!is_forbidden("127.0.0.1".parse().unwrap(), true));
        assert!(!is_forbidden("::1".parse().unwrap(), true));
        assert!(!is_forbidden("10.0.0.1".parse().unwrap(), true));
        for a in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
            assert!(is_forbidden(a.parse().unwrap(), true), "{a}");
        }
    }

    #[test]
    fn path_rules() {
        let ok = [
            ("/api/v1/x", "/api"),
            ("/api", "/api"),
            ("/api/", "/api/"),
            ("/api/x?y=1&z=%20", "/api/"),
            ("/api?q=1", "/api"),
            ("/anything", "/"),
        ];
        for (p, pre) in ok {
            assert!(path_allowed(p, pre), "{p} under {pre}");
        }
        let bad = [
            ("/apix", "/api"),
            ("/other", "/api"),
            ("api/x", "/api"),
            ("//api/x", "/api"),
            ("/api//x", "/api"),
            ("/api/../admin", "/api"),
            ("/api/./x", "/api"),
            ("/api/%2e%2e/admin", "/api"),
            ("/api/%2E%2E/admin", "/api"),
            ("/api/x%2fy", "/api"),
            ("/api/x%5cy", "/api"),
            ("/api/x\\y", "/api"),
            ("/api/x#frag", "/api"),
            ("/api/a b", "/api"),
            ("/api/\u{e9}", "/api"),
            ("/api/x\r\nHost: evil", "/api"),
            ("https://evil.example/api/x", "/api"),
            ("*", "/"),
            ("", "/"),
        ];
        for (p, pre) in bad {
            assert!(!path_allowed(p, pre), "{p:?} under {pre}");
        }
        assert!(!path_allowed(&format!("/api/{}", "a".repeat(5000)), "/api"));
    }
}
