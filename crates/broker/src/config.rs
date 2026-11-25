//! `tesserad` configuration file (JSON).
//!
//! ```json
//! {
//!   "state_dir": "/var/lib/tessera",
//!   "admin_socket": "/run/tessera/admin.sock",
//!   "file_root": "/srv/tessera/files",
//!   "require_user_verification": false,
//!   "endpoints": [
//!     { "id": 1,
//!       "spec": { "host": "api.example.com", "port": 443, "path_prefix": "/v1",
//!                 "methods": ["GET"], "max_request_body": 4096,
//!                 "max_response_body": 65536, "timeout_ms": 10000 },
//!       "secret_header": { "name": "x-api-key", "value_file": "/etc/tessera/api-key" },
//!       "ca_pem_file": null }
//!   ],
//!   "profiles": { "shell": { "program": "/bin/sh", "args": ["-c", "..."] } },
//!   "launcher": { "init_path": "/usr/libexec/tessera/tessera-sandbox-init",
//!                 "cgroup_opt_out_reason": null, "landlock": "required" }
//! }
//! ```
//!
//! Secrets are read from files named here and are never journaled or
//! audited.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::entry::EndpointSpec;
use crate::spawner::ProfileSpec;

/// Secret header source.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretHeaderConfig {
    /// Header name.
    pub name: String,
    /// File holding the value (trailing newline stripped).
    pub value_file: PathBuf,
}

/// Configured endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointConfig {
    /// Endpoint id agents name.
    pub id: u64,
    /// Description.
    pub spec: EndpointSpec,
    /// Optional broker-held credential header.
    #[serde(default)]
    pub secret_header: Option<SecretHeaderConfig>,
    /// Optional PEM file with private CA certificates.
    #[serde(default)]
    pub ca_pem_file: Option<PathBuf>,
}

/// Launcher settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LauncherSection {
    /// bubblewrap path.
    #[serde(default)]
    pub bwrap_path: Option<PathBuf>,
    /// `tessera-sandbox-init` path.
    #[serde(default)]
    pub init_path: Option<PathBuf>,
    /// Opt out of mandatory cgroup delegation (reason recorded).
    #[serde(default)]
    pub cgroup_opt_out_reason: Option<String>,
    /// `required` (default), `best_effort` or `disabled`.
    #[serde(default)]
    pub landlock: Option<String>,
}

/// Daemon configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    /// Broker-owned directory (journal, audit log). Never mounted into a
    /// sandbox.
    pub state_dir: PathBuf,
    /// Operator socket path.
    pub admin_socket: PathBuf,
    /// Trusted file root.
    #[serde(default)]
    pub file_root: Option<PathBuf>,
    /// Require UV on every mint.
    #[serde(default)]
    pub require_user_verification: bool,
    /// Endpoints.
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    /// Trusted launch profiles.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileSpec>,
    /// Launcher.
    #[serde(default)]
    pub launcher: LauncherSection,
}

impl DaemonConfig {
    /// Load from a JSON file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Resolve endpoints (reads secrets and CA files).
    pub fn resolved_endpoints(
        &self,
    ) -> Result<Vec<(u64, EndpointSpec, Option<(String, Vec<u8>)>)>, String> {
        let mut out = Vec::new();
        for e in &self.endpoints {
            let mut spec = e.spec.clone();
            if let Some(p) = &e.ca_pem_file {
                let pem =
                    std::fs::read_to_string(p).map_err(|x| format!("{}: {x}", p.display()))?;
                spec.ca_der = Some(pem_certs(&pem)?);
            }
            let secret = match &e.secret_header {
                Some(s) => {
                    let mut v = std::fs::read(&s.value_file)
                        .map_err(|x| format!("{}: {x}", s.value_file.display()))?;
                    while v.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                        v.pop();
                    }
                    Some((s.name.clone(), v))
                }
                None => None,
            };
            out.push((e.id, spec, secret));
        }
        Ok(out)
    }
}

/// Extract DER certificates from PEM text.
pub fn pem_certs(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    use base64ct::{Base64, Encoding};
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            let b64 = cur.take().ok_or("unbalanced PEM")?;
            out.push(Base64::decode_vec(&b64).map_err(|e| format!("PEM: {e}"))?);
        } else if let Some(c) = cur.as_mut() {
            c.push_str(line);
        }
    }
    if out.is_empty() {
        return Err("no certificates in PEM".into());
    }
    Ok(out)
}
