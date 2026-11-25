//! Adapter dispatch, outside the single writer (ADR-0001).
//!
//! The reactor hands a [`DispatchJob`] to a worker only after both the
//! `Consume` record and the `Dispatched` marker are durable. A worker calls
//! [`Executor::execute`] exactly once per job and reports the result back to
//! the reactor, which journals the outcome before releasing anything to the
//! agent.

use std::sync::Arc;
use std::time::Duration;

use tessera_adapter_file as fa;
use tessera_adapter_https as ha;
use tessera_capability_core::{EndpointId, ObjectId, Reservation, ReservationId};
use tessera_protocol::bounded::{BoundedBytes, BoundedString, BoundedVec};
use tessera_protocol::{ErrorCode, WireHeader, WireHttpsRequest, WireOperationResult};

use crate::convert::hex;
use crate::entry::{EndpointSpec, FileIdentityRec};

/// Largest file snapshot / HTTP response body / replacement carried inline in
/// one agent channel datagram. `SOCK_SEQPACKET` datagrams are bounded by the
/// socket send buffer, so content is kept well below the default
/// `wmem_default`.
pub const MAX_INLINE_CONTENT: u64 = 96 * 1024;

/// Exact adapter operation of a reservation.
#[derive(Clone, PartialEq, Eq)]
pub enum JobOperation {
    /// One bounded snapshot.
    FileRead {
        /// Object.
        object: ObjectId,
        /// Requested bound (already clamped).
        max_bytes: u64,
    },
    /// One atomic replacement.
    FileReplace {
        /// Object.
        object: ObjectId,
        /// New content (never logged).
        bytes: Vec<u8>,
    },
    /// One HTTPS request attempt.
    Https {
        /// Endpoint.
        endpoint: EndpointId,
        /// Request.
        request: WireHttpsRequest,
    },
}

impl std::fmt::Debug for JobOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobOperation::FileRead { object, max_bytes } => {
                write!(f, "FileRead({}, max {max_bytes})", object.to_raw())
            }
            JobOperation::FileReplace { object, bytes } => {
                write!(f, "FileReplace({}, {} bytes)", object.to_raw(), bytes.len())
            }
            JobOperation::Https { endpoint, request } => write!(
                f,
                "Https({}, {:?} {} bytes)",
                endpoint.to_raw(),
                request.method,
                request.body.len()
            ),
        }
    }
}

/// One single-dispatch authorization handed to a worker. Owns the core
/// [`Reservation`] (not `Clone`): the job *is* the token.
#[derive(Debug)]
pub struct DispatchJob {
    /// Core reservation (single-dispatch token).
    pub reservation: Reservation,
    /// Exact adapter operation.
    pub operation: JobOperation,
}

impl DispatchJob {
    /// Reservation id.
    pub fn id(&self) -> ReservationId {
        self.reservation.id()
    }
}

/// Result of one dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecResult {
    /// The effect happened.
    Completed {
        /// Result for the agent.
        result: WireOperationResult,
        /// Content-free audit summary.
        summary: String,
        /// New slot identity after a replacement.
        new_identity: Option<(ObjectId, FileIdentityRec)>,
    },
    /// Definitely no effect.
    Failed {
        /// Code for the agent.
        code: ErrorCode,
        /// Content-free audit summary.
        summary: String,
    },
    /// The effect may or may not have happened. Never retried.
    Unknown {
        /// Content-free audit summary.
        summary: String,
    },
}

/// Something that performs adapter effects.
pub trait Executor: Send + Sync + 'static {
    /// Register (or, with `expected`, re-register after restart) a file
    /// slot.
    fn register_file(
        &self,
        object: ObjectId,
        name: &str,
        max_read_bytes: u64,
        max_write_bytes: u64,
        expected: Option<FileIdentityRec>,
    ) -> Result<FileIdentityRec, String>;
    /// Register an HTTPS endpoint.
    fn register_endpoint(
        &self,
        id: EndpointId,
        spec: &EndpointSpec,
        secret: Option<(String, Vec<u8>)>,
    ) -> Result<(), String>;
    /// Perform exactly one dispatch.
    fn execute(&self, job: &DispatchJob) -> ExecResult;
}

/// The real adapters.
pub struct AdapterExecutor {
    files: Option<fa::FileAdapter>,
    https: ha::HttpsAdapter,
}

impl AdapterExecutor {
    /// `file_root` is the trusted root directory (administrator path).
    pub fn new(file_root: Option<&std::path::Path>) -> Result<Self, String> {
        let files = match file_root {
            Some(p) => Some(
                fa::FileAdapter::open_root(p, fa::RootConfig::default())
                    .map_err(|e| format!("file root {}: {e}", p.display()))?,
            ),
            None => None,
        };
        Ok(AdapterExecutor {
            files,
            https: ha::HttpsAdapter::new(),
        })
    }

    /// Shared handle.
    pub fn shared(self) -> Arc<dyn Executor> {
        Arc::new(self)
    }
}

fn id_rec(i: fa::FileIdentity) -> FileIdentityRec {
    FileIdentityRec {
        dev: i.dev,
        ino: i.ino,
        uid: i.uid,
        fs_type: i.fs_type,
    }
}

fn id_adapter(i: FileIdentityRec) -> fa::FileIdentity {
    fa::FileIdentity {
        dev: i.dev,
        ino: i.ino,
        uid: i.uid,
        fs_type: i.fs_type,
    }
}

fn method(m: tessera_protocol::HttpMethod) -> http::Method {
    use tessera_protocol::HttpMethod as W;
    match m {
        W::Get => http::Method::GET,
        W::Head => http::Method::HEAD,
        W::Post => http::Method::POST,
        W::Put => http::Method::PUT,
        W::Patch => http::Method::PATCH,
        W::Delete => http::Method::DELETE,
    }
}

fn parse_method(s: &str) -> Result<http::Method, String> {
    match s.to_ascii_uppercase().as_str() {
        "GET" => Ok(http::Method::GET),
        "HEAD" => Ok(http::Method::HEAD),
        "POST" => Ok(http::Method::POST),
        "PUT" => Ok(http::Method::PUT),
        "PATCH" => Ok(http::Method::PATCH),
        "DELETE" => Ok(http::Method::DELETE),
        other => Err(format!("unsupported method {other}")),
    }
}

fn content(bytes: Vec<u8>) -> Option<tessera_protocol::ContentBytes> {
    BoundedBytes::new(bytes).ok()
}

impl Executor for AdapterExecutor {
    fn register_file(
        &self,
        object: ObjectId,
        name: &str,
        max_read_bytes: u64,
        max_write_bytes: u64,
        expected: Option<FileIdentityRec>,
    ) -> Result<FileIdentityRec, String> {
        let files = self
            .files
            .as_ref()
            .ok_or("no trusted file root configured")?;
        let policy = fa::SlotPolicy {
            max_read_bytes: max_read_bytes.min(MAX_INLINE_CONTENT),
            max_write_bytes: max_write_bytes.min(MAX_INLINE_CONTENT),
        };
        let oid = fa::ObjectId(u128::from(object.to_raw()));
        let r = match expected {
            None => files.register(oid, name, policy),
            Some(e) => files.register_with_identity(oid, name, policy, id_adapter(e)),
        };
        r.map(id_rec).map_err(|e| e.to_string())
    }

    fn register_endpoint(
        &self,
        id: EndpointId,
        spec: &EndpointSpec,
        secret: Option<(String, Vec<u8>)>,
    ) -> Result<(), String> {
        if spec.max_response_body > MAX_INLINE_CONTENT || spec.max_request_body > MAX_INLINE_CONTENT
        {
            return Err(format!(
                "endpoint body limits must not exceed {MAX_INLINE_CONTENT} bytes"
            ));
        }
        let mut cfg = ha::EndpointConfig::new(&spec.host, spec.port, &spec.path_prefix);
        cfg.methods = spec
            .methods
            .iter()
            .map(|m| parse_method(m))
            .collect::<Result<_, _>>()?;
        cfg.request_headers = spec.request_headers.clone();
        cfg.response_headers = spec.response_headers.clone();
        cfg.max_request_body = spec.max_request_body;
        cfg.max_response_body = spec.max_response_body;
        cfg.timeout = Duration::from_millis(spec.timeout_ms.max(1));
        cfg.allow_private = spec.allow_private;
        cfg.pinned_addrs = spec.pinned_addrs.clone();
        if let Some(cas) = &spec.ca_der {
            cfg.tls = ha::TlsTrust::CustomRoots(
                cas.iter()
                    .map(|d| rustls_pki_types::CertificateDer::from(d.clone()))
                    .collect(),
            );
        }
        if let Some((name, value)) = secret {
            cfg.secret_header =
                Some(ha::SecretHeader::new(&name, &value).map_err(|e| e.to_string())?);
        }
        self.https
            .register(ha::EndpointId(u128::from(id.to_raw())), cfg)
            .map_err(|e| e.to_string())
    }

    fn execute(&self, job: &DispatchJob) -> ExecResult {
        let rid = u128::from(job.id().to_raw());
        match &job.operation {
            JobOperation::FileRead { object, max_bytes } => self.file(
                rid,
                *object,
                fa::FileOperation::ReadSnapshot {
                    max_bytes: (*max_bytes).min(MAX_INLINE_CONTENT),
                },
            ),
            JobOperation::FileReplace { object, bytes } => self.file(
                rid,
                *object,
                fa::FileOperation::ReplaceContent {
                    bytes: bytes.clone(),
                },
            ),
            JobOperation::Https { endpoint, request } => self.http(rid, *endpoint, request),
        }
    }
}

impl AdapterExecutor {
    fn file(&self, rid: u128, object: ObjectId, op: fa::FileOperation) -> ExecResult {
        let Some(files) = self.files.as_ref() else {
            return ExecResult::Failed {
                code: ErrorCode::AdapterFailed,
                summary: "no file root".into(),
            };
        };
        let is_replace = matches!(op, fa::FileOperation::ReplaceContent { .. });
        let res = fa::Reservation {
            id: fa::ReservationId(rid),
            object: fa::ObjectId(u128::from(object.to_raw())),
            operation: op,
        };
        match files.dispatch(&res) {
            Ok(fa::FileOutcome::Snapshot { effect, bytes }) => {
                let summary = format!(
                    "file read object={} target={} bytes={} sha256={}",
                    object.to_raw(),
                    effect.target,
                    effect.byte_count,
                    effect.sha256_hex()
                );
                match content(bytes) {
                    Some(bytes) => ExecResult::Completed {
                        result: WireOperationResult::FileSnapshot {
                            bytes,
                            truncated: false,
                        },
                        summary,
                        new_identity: None,
                    },
                    // Bytes were read but cannot be carried; the read
                    // happened (no refund) but nothing is released.
                    None => ExecResult::Failed {
                        code: ErrorCode::LimitExceeded,
                        summary,
                    },
                }
            }
            Ok(fa::FileOutcome::Replaced { effect }) => ExecResult::Completed {
                result: WireOperationResult::FileReplaced {
                    bytes_written: effect.byte_count,
                },
                summary: format!(
                    "file replace object={} target={} bytes={} sha256={}",
                    object.to_raw(),
                    effect.target,
                    effect.byte_count,
                    effect.sha256_hex()
                ),
                new_identity: Some((object, id_rec(effect.identity_after))),
            },
            Err(fa::FileError::Io { stage, errno }) if is_replace => ExecResult::Unknown {
                summary: format!("file replace i/o failure at {stage}: {errno:?}"),
            },
            Err(e) => ExecResult::Failed {
                code: ErrorCode::AdapterFailed,
                summary: format!("file adapter: {e}"),
            },
        }
    }

    fn http(&self, rid: u128, endpoint: EndpointId, req: &WireHttpsRequest) -> ExecResult {
        let op = ha::HttpsOperation {
            method: method(req.method),
            path: req.path.as_str().to_owned(),
            headers: req
                .headers
                .as_slice()
                .iter()
                .map(|h| (h.name.as_str().to_owned(), h.value.as_slice().to_vec()))
                .collect(),
            body: req.body.as_slice().to_vec(),
        };
        let res = ha::Reservation {
            id: ha::ReservationId(rid),
            endpoint: ha::EndpointId(u128::from(endpoint.to_raw())),
            operation: op,
        };
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return ExecResult::Failed {
                    code: ErrorCode::Internal,
                    summary: format!("runtime: {e}"),
                };
            }
        };
        match rt.block_on(self.https.dispatch(&res)) {
            Ok(d) => {
                let summary = format!(
                    "https endpoint={} host={} {} {} req_body={}B req_sha256={} outcome={:?}",
                    endpoint.to_raw(),
                    d.effect.host,
                    d.effect.method,
                    d.effect.path,
                    d.effect.request_body_len,
                    hex(&d.effect.request_body_sha256),
                    redact_outcome(&d.effect.outcome),
                );
                let headers: Vec<WireHeader> = d
                    .response
                    .headers
                    .into_iter()
                    .filter_map(|(n, v)| {
                        Some(WireHeader {
                            name: BoundedString::new(n).ok()?,
                            value: BoundedBytes::new(v).ok()?,
                        })
                    })
                    .take(tessera_protocol::MAX_HTTP_HEADERS)
                    .collect();
                let headers = BoundedVec::new(headers).unwrap_or_default();
                match content(d.response.body.to_vec()) {
                    Some(body) => ExecResult::Completed {
                        result: WireOperationResult::Https {
                            status: d.response.status,
                            headers,
                            body,
                            truncated: false,
                        },
                        summary,
                        new_identity: None,
                    },
                    None => ExecResult::Failed {
                        code: ErrorCode::LimitExceeded,
                        summary,
                    },
                }
            }
            Err(ha::HttpsError::Denied(d)) => ExecResult::Failed {
                code: ErrorCode::AdapterFailed,
                summary: format!("https denied before connecting: {d:?}"),
            },
            Err(ha::HttpsError::AlreadyDispatched(_)) => ExecResult::Failed {
                code: ErrorCode::Internal,
                summary: "adapter refused duplicate dispatch".into(),
            },
            Err(ha::HttpsError::Failed(effect)) => {
                let summary = format!(
                    "https endpoint={} outcome={}",
                    endpoint.to_raw(),
                    redact_outcome(&effect.outcome)
                );
                if effect.outcome.may_have_reached_server() {
                    ExecResult::Unknown { summary }
                } else {
                    ExecResult::Failed {
                        code: ErrorCode::AdapterFailed,
                        summary,
                    }
                }
            }
        }
    }
}

fn redact_outcome(o: &ha::EffectOutcome) -> String {
    match o {
        ha::EffectOutcome::Response {
            status,
            body_len,
            body_sha256,
        } => format!(
            "status={status} body={body_len}B sha256={}",
            hex(body_sha256)
        ),
        other => format!("{other:?}"),
    }
}
