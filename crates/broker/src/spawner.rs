//! Sandbox spawning.
//!
//! The broker allocates the principal (`CreatePrincipal`, journaled) and
//! only then asks a [`SandboxSpawner`] to launch the sandbox for it. The
//! spawner returns the host end of the sandbox's dedicated
//! `SOCK_SEQPACKET` channel; the broker binds that channel to the AgentId it
//! allocated (ADR-0004, ADR-0022). Identity is the channel, never a payload
//! field and not `SO_PEERCRED` (which names the process that created the
//! socketpair, i.e. the broker/launcher itself).
//!
//! Spawning runs on a dedicated, long-lived thread ([`SpawnerThread`]):
//! the launcher ties each sandbox (`--die-with-parent`) to the thread that
//! called `spawn`, so that thread must outlive the sandboxes, and a slow
//! launch must not block the single writer.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use tessera_capability_core::AgentId;
use tessera_launcher::{
    AGENT_ID_ENV, AgentLabel, LaunchProfile, Launcher, LauncherConfig, LoopbackShim, ModelRoute,
    ResourceLimits, SandboxHandle, StdioMode,
};

use crate::convert::agent_label;

/// Launches and stops sandboxes.
pub trait SandboxSpawner: Send + 'static {
    /// Launch a sandbox for `agent` from the trusted profile `profile` and
    /// return the host end of its broker channel.
    fn spawn(&mut self, agent: AgentId, profile: &str) -> Result<OwnedFd, String>;
    /// Stop (kill) the sandbox of `agent`, if any.
    fn stop(&mut self, agent: AgentId);
}

/// A trusted launch profile from the daemon configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    /// Program to run inside the sandbox.
    pub program: PathBuf,
    /// Arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Host workspace directory (bound at `/workspace`).
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    /// Extra read-only binds `(host, sandbox)`.
    #[serde(default)]
    pub ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Extra environment.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// cgroup memory limit.
    #[serde(default)]
    pub memory_max_bytes: Option<u64>,
    /// cgroup pids limit.
    #[serde(default)]
    pub pids_max: Option<u64>,
    /// Pipe stdio to the spawner (tests) instead of inheriting `/dev/null`.
    #[serde(default)]
    pub piped_stdio: bool,
    /// Compatibility mode: model API route through the host model proxy
    /// (`docs/compat.md`). An unmediated, unlimited-use baseline channel
    /// and a disclosure channel (threat model R-2).
    #[serde(default)]
    pub model_route: Option<ModelRouteSpec>,
}

/// Model API route of a compatibility-mode profile.
///
/// ```json
/// "model_route": { "socket": "/run/user/1000/tessera/agent-1/model.sock",
///                  "loopback_port": 18080,
///                  "netshim_path": "/usr/libexec/tessera/tessera-netshim" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteSpec {
    /// Host path of the `tessera-model-proxy` socket for this profile.
    pub socket: PathBuf,
    /// Loopback TCP port for `tessera-netshim` (omit for harnesses that
    /// speak HTTP over the Unix socket, e.g. `ANTHROPIC_UNIX_SOCKET`).
    #[serde(default)]
    pub loopback_port: Option<u16>,
    /// Host path of `tessera-netshim`; required with `loopback_port`.
    #[serde(default)]
    pub netshim_path: Option<PathBuf>,
}

impl ModelRouteSpec {
    /// Convert to the launcher's form.
    pub fn to_route(&self) -> Result<ModelRoute, String> {
        let loopback = match (self.loopback_port, &self.netshim_path) {
            (None, None) => None,
            (Some(port), Some(path)) => Some(LoopbackShim {
                port,
                netshim_path: path.clone(),
            }),
            _ => return Err("model_route: loopback_port and netshim_path go together".into()),
        };
        Ok(ModelRoute {
            host_socket: self.socket.clone(),
            loopback,
        })
    }
}

/// One operator baseline grant installed for a principal at creation
/// (recorded as `InstallBaseline`, R2: separately from approved roots).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineGrant {
    /// Scope.
    pub scope: tessera_protocol::WireScope,
    /// Budget.
    pub budget: tessera_protocol::WireBudget,
    /// Delegation depth.
    pub depth: tessera_protocol::WireDepth,
    /// Lifetime in ms (`None`: until revoked or the epoch ends).
    #[serde(default)]
    pub expiry_ms: Option<u64>,
}

/// An operator-configured profile that *agents* may name in `Spawn`
/// (spec §9.2). Agents name it by its numeric `LaunchProfileId`; it maps to
/// a trusted launcher profile by name. The child receives exactly the
/// `baseline` grants listed here and nothing from its parent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpawnProfile {
    /// Name of a trusted launcher profile ([`ProfileSpec`]).
    pub profile: String,
    /// Baseline authority of every child launched from this profile.
    #[serde(default)]
    pub baseline: Vec<BaselineGrant>,
}

/// Hook run after each launch (e.g. a test taking the sandbox's stdio).
pub type OnSpawn = Box<dyn FnMut(AgentId, &mut SandboxHandle) + Send>;

/// Spawner backed by `tessera-launcher`.
pub struct LauncherSpawner {
    launcher: Launcher,
    profiles: HashMap<String, ProfileSpec>,
    running: HashMap<AgentId, SandboxHandle>,
    /// Handles whose stdio a test wants (only with `piped_stdio`).
    pub on_spawn: Option<OnSpawn>,
}

impl LauncherSpawner {
    /// Probe the host and refuse if a mandatory control is missing (R10).
    pub fn new(
        config: LauncherConfig,
        profiles: HashMap<String, ProfileSpec>,
    ) -> Result<Self, tessera_launcher::LaunchError> {
        Ok(LauncherSpawner {
            launcher: Launcher::new(config)?,
            profiles,
            running: HashMap::new(),
            on_spawn: None,
        })
    }

    /// Kill and remove sandbox cgroups left by an earlier broker run (spec
    /// §11). `tesserad` calls this before serving and refuses to start on
    /// error.
    pub fn sweep_stale_cgroups(&self) -> Result<Vec<PathBuf>, tessera_launcher::LaunchError> {
        self.launcher.sweep_stale_cgroups()
    }
}

impl SandboxSpawner for LauncherSpawner {
    fn spawn(&mut self, agent: AgentId, profile: &str) -> Result<OwnedFd, String> {
        let p = self
            .profiles
            .get(profile)
            .ok_or_else(|| format!("unknown launch profile {profile:?}"))?;
        let label = AgentLabel::new(agent_label(agent)).map_err(|e| e.to_string())?;
        let mut lp = LaunchProfile::new(label, &p.program).args(p.args.iter());
        if let Some(ws) = &p.workspace {
            lp = lp.workspace(ws);
        }
        for (h, s) in &p.ro_binds {
            lp = lp.ro_bind(h, s);
        }
        for (k, v) in &p.env {
            if k != AGENT_ID_ENV {
                lp = lp.env(k, v);
            }
        }
        lp = lp.limits(ResourceLimits {
            memory_max_bytes: p.memory_max_bytes,
            pids_max: p.pids_max,
            ..ResourceLimits::default()
        });
        if let Some(m) = &p.model_route {
            lp = lp.model_route(m.to_route()?);
        }
        if p.piped_stdio {
            lp = lp.stdio(StdioMode::Piped, StdioMode::Piped, StdioMode::Piped);
        }
        let mut h = self.launcher.spawn(&lp).map_err(|e| e.to_string())?;
        let fd = h
            .take_broker_channel()
            .ok_or("launcher returned no broker channel")?;
        if let Some(cb) = self.on_spawn.as_mut() {
            cb(agent, &mut h);
        }
        self.running.insert(agent, h);
        Ok(fd)
    }

    fn stop(&mut self, agent: AgentId) {
        if let Some(mut h) = self.running.remove(&agent) {
            let _ = h.stop();
        }
    }
}

impl Drop for LauncherSpawner {
    fn drop(&mut self) {
        for (_, mut h) in self.running.drain() {
            let _ = h.stop();
        }
    }
}

pub(crate) enum SpawnerMsg {
    Spawn {
        agent: AgentId,
        profile: String,
        done: Box<dyn FnOnce(Result<OwnedFd, String>) + Send>,
    },
    Stop(AgentId),
}

/// Owns a [`SandboxSpawner`] on a dedicated long-lived thread.
pub(crate) struct SpawnerThread {
    tx: mpsc::Sender<SpawnerMsg>,
    join: Option<thread::JoinHandle<()>>,
}

impl SpawnerThread {
    pub(crate) fn start(mut spawner: Box<dyn SandboxSpawner>) -> Self {
        let (tx, rx) = mpsc::channel::<SpawnerMsg>();
        let join = thread::Builder::new()
            .name("tessera-spawner".into())
            .spawn(move || {
                for msg in rx {
                    match msg {
                        SpawnerMsg::Spawn {
                            agent,
                            profile,
                            done,
                        } => done(spawner.spawn(agent, &profile)),
                        SpawnerMsg::Stop(a) => spawner.stop(a),
                    }
                }
                // Channel closed: dropping the spawner stops every sandbox.
            })
            .ok();
        SpawnerThread { tx, join }
    }

    pub(crate) fn send(&self, m: SpawnerMsg) {
        let _ = self.tx.send(m);
    }
}

impl Drop for SpawnerThread {
    fn drop(&mut self) {
        let (tx, _) = mpsc::channel();
        drop(std::mem::replace(&mut self.tx, tx));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_route_spec() {
        let p: ProfileSpec = serde_json::from_str(
            r#"{ "program": "/usr/bin/python3",
                 "model_route": { "socket": "/run/user/1000/tessera/a/model.sock",
                                  "loopback_port": 18080,
                                  "netshim_path": "/usr/libexec/tessera/tessera-netshim" } }"#,
        )
        .unwrap();
        let r = p.model_route.unwrap().to_route().unwrap();
        assert_eq!(r.loopback.as_ref().unwrap().port, 18080);
        let socket_only = ModelRouteSpec {
            socket: "/s".into(),
            loopback_port: None,
            netshim_path: None,
        };
        assert!(socket_only.to_route().unwrap().loopback.is_none());
        let half = ModelRouteSpec {
            loopback_port: Some(1),
            ..socket_only
        };
        assert!(half.to_route().is_err());
        assert!(
            serde_json::from_str::<ProfileSpec>(
                r#"{ "program": "/x", "model_route": { "socket": "/s", "port": 1 } }"#
            )
            .is_err()
        );
    }
}
