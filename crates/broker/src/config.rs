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
//!   "profiles": { "shell": { "program": "/bin/sh", "args": ["-c", "..."] },
//!                 "claude": { "program": "/opt/claude/claude", "args": ["-p", "..."],
//!                             "env": [["ANTHROPIC_UNIX_SOCKET", "/.tessera/model.sock"]],
//!                             "model_route": { "socket": "/run/user/1000/tessera/claude/model.sock" } } },
//!   "agent_spawn_profiles": { "1": { "profile": "shell", "baseline": [] } },
//!   "limits": { "max_children_per_agent": 8, "max_spawn_depth": 2,
//!               "max_domain_agents": 16, "max_in_flight_per_agent": 64,
//!               "agent_rate_per_sec": 100, "agent_rate_burst": 200,
//!               "approval_queue": 16, "max_pending_approvals_per_domain": 2,
//!               "approval_max_per_window": 30, "max_dispatch_per_domain": 2,
//!               "ledger_quotas": { "derived_per_domain": 2048,
//!                                  "reservations_per_domain": 16384 } },
//!   "audit_fsync": "every-event",
//!   "launcher": { "init_path": "/usr/libexec/tessera/tessera-sandbox-init",
//!                 "protected_paths": ["/etc/tessera/anthropic-api-key"],
//!                 "cgroup_group": "tesserad",
//!                 "model_socket_dir": "/run/user/1000/tessera",
//!                 "cgroup_opt_out_reason": null, "landlock": "required" }
//! }
//! ```
//!
//! `audit_fsync`: `every-event` (default), `every:N` or `never`.
//! `agent_spawn_profiles` maps the `LaunchProfileId` agents send in `Spawn`
//! to a trusted profile name and the child's baseline grants; absent means
//! agents cannot spawn. The launcher's `cgroup_group` must be private to
//! this broker: on start every leftover sandbox cgroup in it is killed and
//! removed (refusing to start if that fails).
//!
//! Secrets are read from files named here and are never journaled or
//! audited.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::entry::EndpointSpec;
use crate::spawner::{AgentSpawnProfile, ProfileSpec};

/// Secret header source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretHeaderConfig {
    /// Header name.
    pub name: String,
    /// File holding the value (trailing newline stripped).
    pub value_file: PathBuf,
}

/// Configured endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// cgroup group (directory under the delegation root) private to this
    /// broker; default `tesserad`.
    #[serde(default)]
    pub cgroup_group: Option<String>,
    /// Further host paths no sandbox workspace, bind or model route may
    /// overlap (be, contain or lie inside), e.g. the model proxy's
    /// credential files and audit log. `state_dir`, `file_root`, the admin
    /// socket and its directory, and every endpoint secret/CA file are
    /// always protected.
    #[serde(default)]
    pub protected_paths: Vec<PathBuf>,
    /// Private directory (owned by the broker's uid, mode 0700, not
    /// `$XDG_RUNTIME_DIR` or `$HOME` itself) holding the model proxy
    /// sockets. Every profile `model_route.socket` must lie inside it;
    /// required when any profile has a model route.
    #[serde(default)]
    pub model_socket_dir: Option<PathBuf>,
}

/// Optional broker limits (defaults from `BrokerConfig`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Children one principal may spawn per epoch.
    pub max_children_per_agent: Option<u32>,
    /// Spawn depth below an operator-created principal.
    pub max_spawn_depth: Option<u32>,
    /// Principals per orchestration domain.
    pub max_domain_agents: Option<u32>,
    /// Requests in flight per principal.
    pub max_in_flight_per_agent: Option<usize>,
    /// Sustained requests per second per principal.
    pub agent_rate_per_sec: Option<u32>,
    /// Burst per principal.
    pub agent_rate_burst: Option<u32>,
    /// Grant requests queued behind the active approval.
    pub approval_queue: Option<usize>,
    /// Active and queued approval requests per orchestration domain.
    pub max_pending_approvals_per_domain: Option<usize>,
    /// Approval prompts per orchestration domain per rate window.
    pub approval_max_per_window: Option<u32>,
    /// Adapter jobs one orchestration domain may have on the workers.
    pub max_dispatch_per_domain: Option<usize>,
    /// Limits on ledger records allocated by agents.
    #[serde(default)]
    pub ledger_quotas: crate::LedgerQuotas,
}

/// Daemon configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Profiles agents may spawn, by `LaunchProfileId`.
    #[serde(default)]
    pub agent_spawn_profiles: BTreeMap<u64, AgentSpawnProfile>,
    /// Broker admission limits.
    #[serde(default)]
    pub limits: LimitsSection,
    /// Audit log fsync policy (`every-event`, `every:N`, `never`).
    #[serde(default)]
    pub audit_fsync: Option<String>,
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

    /// Check that every agent spawn profile names a configured profile and
    /// that model routes have a model socket directory.
    pub fn check(&self) -> Result<(), String> {
        if self.launcher.model_socket_dir.is_none()
            && let Some((name, _)) = self.profiles.iter().find(|(_, p)| p.model_route.is_some())
        {
            return Err(format!(
                "profile {name:?} has a model_route but launcher.model_socket_dir is not set"
            ));
        }
        for (id, p) in &self.agent_spawn_profiles {
            if !self.profiles.contains_key(&p.profile) {
                return Err(format!(
                    "agent_spawn_profiles.{id}: unknown profile {:?}",
                    p.profile
                ));
            }
        }
        Ok(())
    }

    /// Resolve endpoints (reads secrets and CA files).
    pub fn resolved_endpoints(&self) -> Result<Vec<crate::entry::ConfiguredEndpoint>, String> {
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

#[cfg(test)]
mod tests {
    use super::DaemonConfig;

    fn parse(s: &str) -> Result<DaemonConfig, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    #[test]
    fn unknown_keys_are_rejected_at_every_level() {
        let base = r#"{"state_dir": "/s", "admin_socket": "/a"}"#;
        assert!(parse(base).is_ok());
        for bad in [
            r#"{"state_dir": "/s", "admin_socket": "/a", "audit_fsyn": "never"}"#,
            r#"{"state_dir": "/s", "admin_socket": "/a", "launcher": {"landlok": "disabled"}}"#,
            r#"{"state_dir": "/s", "admin_socket": "/a", "limits": {"max_childs": 1}}"#,
            r#"{"state_dir": "/s", "admin_socket": "/a", "limits": {"ledger_quotas": {"derived_per_user": 1}}}"#,
            r#"{"state_dir": "/s", "admin_socket": "/a",
                "profiles": {"p": {"program": "/bin/sh", "argz": []}}}"#,
            r#"{"state_dir": "/s", "admin_socket": "/a",
                "agent_spawn_profiles": {"1": {"profile": "p", "baselin": []}}}"#,
        ] {
            assert!(parse(bad).is_err(), "accepted: {bad}");
        }
        // An agent profile must name a configured launch profile.
        let c = parse(
            r#"{"state_dir": "/s", "admin_socket": "/a",
                "agent_spawn_profiles": {"1": {"profile": "nope"}}}"#,
        )
        .unwrap();
        assert!(c.check().is_err());
    }

    #[test]
    fn ledger_quota_overrides_keep_other_defaults() {
        let c = parse(
            r#"{"state_dir": "/s", "admin_socket": "/a",
            "limits": {"ledger_quotas": {"derived_per_root": 12}}}"#,
        )
        .unwrap();
        assert_eq!(c.limits.ledger_quotas.derived_per_root, 12);
        assert_eq!(
            c.limits.ledger_quotas.reservations_per_root,
            crate::LedgerQuotas::default().reservations_per_root
        );
    }

    #[test]
    fn domain_limits_parse() {
        let c = parse(
            r#"{"state_dir": "/s", "admin_socket": "/a",
            "limits": {"max_pending_approvals_per_domain": 3, "max_dispatch_per_domain": 1,
                       "ledger_quotas": {"derived_per_domain": 7}}}"#,
        )
        .unwrap();
        assert_eq!(c.limits.max_pending_approvals_per_domain, Some(3));
        assert_eq!(c.limits.max_dispatch_per_domain, Some(1));
        assert_eq!(c.limits.ledger_quotas.derived_per_domain, 7);
        assert_eq!(
            c.limits.ledger_quotas.reservations_per_domain,
            crate::LedgerQuotas::default().reservations_per_domain
        );
    }
}
