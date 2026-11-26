//! Tessera compatibility mode: model API connectivity for unmodified agent
//! harnesses (specification §3.1, §10.1, WP6; ADR-0020, ADR-0030).
//!
//! A harness such as Claude Code or Codex runs inside a Tessera sandbox with
//! an empty network namespace. Its only route out is a Unix socket,
//! bind-mounted from the host, served by the trusted **model proxy** in this
//! crate (`tessera-model-proxy`):
//!
//! * the sandbox speaks plain HTTP/1.1 on the socket; the proxy forwards to
//!   exactly one configured upstream (e.g. `https://api.anthropic.com`) over
//!   a fresh TLS connection per request, validating the certificate for the
//!   configured name, resolving the name itself and refusing non-global
//!   addresses ([`tessera_adapter_https::is_forbidden`]);
//! * only allowlisted method + path routes are forwarded; absolute-form,
//!   CONNECT and upgrade requests are refused; redirects are returned, never
//!   followed;
//! * request headers are an allowlist (`anthropic-beta` values too);
//!   client-supplied credentials (`authorization`, `x-api-key`, cookies,
//!   ...) are always stripped and the host-held credential is injected
//!   (`x-api-key` or `authorization: Bearer`); it never enters the sandbox;
//! * an optional JSON body policy ([`body`]) refuses provider-side tools
//!   that would make the provider reach other hosts (`mcp_servers`,
//!   server-side `tools[].type`) and can cap `max_tokens` and the model;
//! * response headers carrying the credential are dropped and the body is
//!   scanned (with `accept-encoding: identity` forced upstream) so that a
//!   verbatim echo of the credential is replaced by
//!   [`secret::REDACTED`]; transformed echoes are a documented residual risk;
//! * responses, including server-sent events, are streamed;
//! * request size, response size, request rate, concurrency and lifetime
//!   byte/request budgets are bounded per sandbox; the concurrency slot is
//!   taken before a request body is read;
//! * JSON audit lines (method, path, sizes, digests, status, sandbox label):
//!   a `forwarded` record before contacting the upstream and a completion
//!   record after it; locally refused connections and requests are rate
//!   limited and summarised. Never bodies, header values, query strings or
//!   the credential.
//!
//! # This is an unlimited-use baseline channel
//!
//! The route is an *unmediated baseline effect*: it costs no capability
//! units, needs no approval and is available for the whole life of the
//! sandbox (the budgets above are operator resource limits, not authority).
//! **Model context is a disclosure channel** (threat model R-2): anything
//! the workload can read can be sent to the model provider in a prompt.
//! Endpoint restriction does not prevent this.
//!
//! For harnesses that cannot use a Unix socket directly, [`shim`]
//! (`tessera-netshim`) exposes the socket on a loopback TCP port inside the
//! sandbox. See `docs/compat.md`.

#![forbid(unsafe_code)]

pub mod audit;
pub mod body;
pub mod budget;
pub mod config;
pub mod policy;
pub mod secret;
mod server;
pub mod shim;
pub mod upstream;

pub use audit::{AuditRecord, AuditSink};
pub use config::{ConfigError, Injection, ProxyConfig};
pub use secret::Credential;
pub use server::{ModelProxy, ProxyBody, SandboxListener};
pub use upstream::Upstream;
