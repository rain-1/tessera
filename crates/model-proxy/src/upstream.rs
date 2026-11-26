//! The single upstream: own DNS resolution, address-class filtering, TLS
//! validation and one fresh HTTP/1.1 connection per request.
//!
//! Mirrors the approach of `tessera-adapter-https` (ADR-0007): hyper's
//! low-level `client::conn::http1` API has no redirect following, retries,
//! pooling, proxy discovery or DNS, so none of those can be enabled by
//! accident. Address classes are checked with
//! [`tessera_adapter_https::is_forbidden`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::{ConfigError, UpstreamConfig, err, ms};

/// Largest upstream response head accepted.
const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Most upstream response headers accepted.
const MAX_RESPONSE_HEADERS: usize = 100;

/// Why the upstream could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    /// Name did not resolve.
    ResolutionFailed,
    /// A resolved or pinned address is not an allowed destination.
    DestinationForbidden(IpAddr),
    /// TCP connect failed.
    ConnectFailed,
    /// TLS handshake or certificate validation failed.
    TlsFailed,
    /// HTTP-level failure.
    Protocol,
    /// A deadline expired.
    Timeout,
}

impl UpstreamError {
    /// Status returned to the sandbox.
    pub fn status(&self) -> u16 {
        if *self == Self::Timeout { 504 } else { 502 }
    }

    /// Reason returned to the sandbox. Unlike [`Self::reason`] it never
    /// carries the resolved address (review 2026-11-26, S-3).
    pub fn client_reason(&self) -> String {
        match self {
            Self::DestinationForbidden(_) => "destination_forbidden".into(),
            other => other.reason(),
        }
    }

    /// Machine-readable reason for the host audit log (may include the
    /// resolved address).
    pub fn reason(&self) -> String {
        match self {
            Self::ResolutionFailed => "resolution_failed".into(),
            Self::DestinationForbidden(ip) => format!("destination_forbidden:{ip}"),
            Self::ConnectFailed => "connect_failed".into(),
            Self::TlsFailed => "tls_failed".into(),
            Self::Protocol => "protocol_error".into(),
            Self::Timeout => "timeout".into(),
        }
    }
}

/// Aborts a spawned task when dropped.
pub(crate) struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An open upstream connection for exactly one request.
pub(crate) struct Connection {
    pub sender: SendRequest<Full<Bytes>>,
    pub driver: AbortOnDrop,
    pub peer: SocketAddr,
}

/// Compiled upstream.
pub struct Upstream {
    pub(crate) host: String,
    pub(crate) host_header: String,
    server_name: ServerName<'static>,
    port: u16,
    pinned: Option<Vec<IpAddr>>,
    allow_private: bool,
    tls: TlsConnector,
    pub(crate) connect_timeout: Duration,
    pub(crate) header_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_duration: Duration,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Compile from configuration (reads `ca_pem_file` if set).
    pub fn new(cfg: &UpstreamConfig) -> Result<Self, ConfigError> {
        let roots = match &cfg.ca_pem_file {
            Some(p) => {
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(p)
                    .map_err(|e| ConfigError(format!("{}: {e}", p.display())))?
                    .collect::<Result<_, _>>()
                    .map_err(|e| ConfigError(format!("{}: {e}", p.display())))?;
                if certs.is_empty() {
                    return err(format!("{}: no certificates", p.display()));
                }
                Some(certs)
            }
            None => None,
        };
        Self::with_roots(cfg, roots)
    }

    /// Compile with explicit DER roots (`None` = webpki roots).
    pub fn with_roots(
        cfg: &UpstreamConfig,
        roots: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ConfigError> {
        let server_name = ServerName::try_from(cfg.host.clone())
            .map_err(|_| ConfigError(format!("bad upstream host {:?}", cfg.host)))?;
        if cfg.host.is_empty() || cfg.host.contains(['/', '@', ' ']) {
            return err("bad upstream host");
        }
        let mut store = rustls::RootCertStore::empty();
        match roots {
            None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Some(certs) => {
                for c in certs {
                    store
                        .add(c)
                        .map_err(|e| ConfigError(format!("bad CA certificate: {e}")))?;
                }
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ConfigError(e.to_string()))?
            .with_root_certificates(store)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let host_header = if cfg.port == 443 {
            cfg.host.clone()
        } else if cfg.host.contains(':') {
            format!("[{}]:{}", cfg.host, cfg.port)
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        };
        Ok(Self {
            host: cfg.host.clone(),
            host_header,
            server_name,
            port: cfg.port,
            pinned: cfg.pinned_addrs.clone(),
            allow_private: cfg.allow_private,
            tls: TlsConnector::from(Arc::new(tls)),
            connect_timeout: ms(cfg.connect_timeout_ms),
            header_timeout: ms(cfg.response_header_timeout_ms),
            idle_timeout: ms(cfg.idle_timeout_ms),
            max_duration: ms(cfg.max_duration_ms),
        })
    }

    async fn resolve(&self) -> Result<Vec<SocketAddr>, UpstreamError> {
        let ips: Vec<IpAddr> = if let Some(p) = &self.pinned {
            p.clone()
        } else if let Ok(ip) = self.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            tokio::net::lookup_host((self.host.as_str(), self.port))
                .await
                .map_err(|_| UpstreamError::ResolutionFailed)?
                .map(|sa| sa.ip())
                .collect()
        };
        let mut out = Vec::new();
        for ip in ips {
            // Any forbidden candidate rejects the whole answer (rebinding).
            if tessera_adapter_https::is_forbidden(ip, self.allow_private) {
                return Err(UpstreamError::DestinationForbidden(ip));
            }
            let sa = SocketAddr::new(ip, self.port);
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
        if out.is_empty() {
            return Err(UpstreamError::ResolutionFailed);
        }
        Ok(out)
    }

    /// Resolve, connect, validate TLS and complete the HTTP/1.1 handshake,
    /// all within the connect deadline.
    pub(crate) async fn connect(&self) -> Result<Connection, UpstreamError> {
        tokio::time::timeout(self.connect_timeout, self.connect_inner())
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }

    async fn connect_inner(&self) -> Result<Connection, UpstreamError> {
        let addrs = self.resolve().await?;
        let mut tcp = None;
        for addr in addrs {
            if let Ok(s) = TcpStream::connect(addr).await {
                tcp = Some((s, addr));
                break;
            }
        }
        let (tcp, peer) = tcp.ok_or(UpstreamError::ConnectFailed)?;
        let _ = tcp.set_nodelay(true);
        let tls = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|_| UpstreamError::TlsFailed)?;
        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(MAX_RESPONSE_HEAD.max(8192))
            .max_headers(MAX_RESPONSE_HEADERS)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| UpstreamError::Protocol)?;
        let driver = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));
        Ok(Connection {
            sender,
            driver,
            peer,
        })
    }
}
