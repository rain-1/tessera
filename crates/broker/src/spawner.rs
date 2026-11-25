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
use std::fs::{self, DirBuilder};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use tessera_capability_core::AgentId;
use tessera_launcher::{
    AGENT_ID_ENV, AgentLabel, LaunchError, LaunchProfile, Launcher, LauncherConfig, ResourceLimits,
    SandboxHandle, StdioMode,
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
    /// Broker-owned host directory for fresh per-principal workspaces.
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    /// Extra read-only binds `(host, sandbox)`.
    #[serde(default)]
    pub ro_binds: Vec<(PathBuf, PathBuf)>,
    /// Extra environment.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// cgroup memory limit in bytes, or `"unlimited"`. Omitted or null uses
    /// the launcher default.
    #[serde(default)]
    pub memory_max_bytes: Option<CgroupLimit>,
    /// cgroup pids limit, or `"unlimited"`. Omitted or null uses the
    /// launcher default.
    #[serde(default)]
    pub pids_max: Option<CgroupLimit>,
    /// Pipe stdio to the spawner (tests) instead of inheriting `/dev/null`.
    #[serde(default)]
    pub piped_stdio: bool,
}

/// A cgroup limit in a launch profile (security review finding 2): a
/// number, or the explicit string `"unlimited"`. An omitted limit is never
/// unlimited; it keeps the launcher default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupLimit {
    /// This many bytes or processes.
    Max(u64),
    /// No limit (the operator said so explicitly).
    Unlimited,
}

const UNLIMITED: &str = "unlimited";

impl serde::Serialize for CgroupLimit {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CgroupLimit::Max(n) => s.serialize_u64(*n),
            CgroupLimit::Unlimited => s.serialize_str(UNLIMITED),
        }
    }
}

impl<'de> serde::Deserialize<'de> for CgroupLimit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Number(u64),
            Word(String),
        }
        match Repr::deserialize(d)? {
            Repr::Number(n) => Ok(CgroupLimit::Max(n)),
            Repr::Word(w) if w == UNLIMITED => Ok(CgroupLimit::Unlimited),
            Repr::Word(w) => Err(serde::de::Error::custom(format!(
                "expected a number or \"{UNLIMITED}\", got {w:?}"
            ))),
        }
    }
}

impl CgroupLimit {
    /// The launcher setting: `None` means no limit.
    fn resolve(limit: Option<CgroupLimit>, default: Option<u64>) -> Option<u64> {
        match limit {
            None => default,
            Some(CgroupLimit::Max(n)) => Some(n),
            Some(CgroupLimit::Unlimited) => None,
        }
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
        mut profiles: HashMap<String, ProfileSpec>,
    ) -> Result<Self, LaunchError> {
        prepare_profiles(&mut profiles, &config.protected_host_paths)?;
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

fn overlapping(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn prepare_profiles(
    profiles: &mut HashMap<String, ProfileSpec>,
    protected: &[PathBuf],
) -> Result<(), LaunchError> {
    let mut workspace_roots = Vec::new();
    for (name, profile) in profiles.iter_mut() {
        if let Some(root) = &mut profile.workspace {
            let canon = fs::canonicalize(&root).map_err(|e| {
                LaunchError::InvalidProfile(format!(
                    "profile {name} workspace {}: {e}",
                    root.display()
                ))
            })?;
            let md = fs::metadata(&canon)?;
            if !md.is_dir()
                || md.uid() != rustix::process::geteuid().as_raw()
                || md.mode() & 0o022 != 0
            {
                return Err(LaunchError::InvalidProfile(format!(
                    "profile {name} workspace {} must be a broker-owned directory without group or world write access",
                    canon.display()
                )));
            }
            if let Some(path) = protected.iter().find(|p| overlapping(&canon, p)) {
                return Err(LaunchError::InvalidProfile(format!(
                    "profile {name} workspace {} overlaps protected host path {}",
                    canon.display(),
                    path.display()
                )));
            }
            workspace_roots.push(canon.clone());
            *root = canon;
        }
    }
    Launcher::check_runtime_exposure(&workspace_roots)?;
    for (name, profile) in profiles.iter_mut() {
        for (host, _) in &mut profile.ro_binds {
            let canon = fs::canonicalize(&host).map_err(|e| {
                LaunchError::InvalidProfile(format!(
                    "profile {name} bind source {}: {e}",
                    host.display()
                ))
            })?;
            if let Some(path) = protected
                .iter()
                .chain(&workspace_roots)
                .find(|p| overlapping(&canon, p))
            {
                return Err(LaunchError::InvalidProfile(format!(
                    "profile {name} bind source {} overlaps protected host path or workspace root {}",
                    canon.display(),
                    path.display()
                )));
            }
            *host = canon;
        }
    }
    Ok(())
}

impl ProfileSpec {
    fn limits(&self) -> ResourceLimits {
        let defaults = ResourceLimits::default();
        ResourceLimits {
            memory_max_bytes: CgroupLimit::resolve(
                self.memory_max_bytes,
                defaults.memory_max_bytes,
            ),
            pids_max: CgroupLimit::resolve(self.pids_max, defaults.pids_max),
            ..defaults
        }
    }
}

fn create_workspace(root: &Path, label: &AgentLabel) -> std::io::Result<PathBuf> {
    let dir = root.join(label.as_str());
    DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

impl SandboxSpawner for LauncherSpawner {
    fn spawn(&mut self, agent: AgentId, profile: &str) -> Result<OwnedFd, String> {
        let p = self
            .profiles
            .get(profile)
            .ok_or_else(|| format!("unknown launch profile {profile:?}"))?;
        let label = AgentLabel::new(agent_label(agent)).map_err(|e| e.to_string())?;
        let mut lp = LaunchProfile::new(label.clone(), &p.program).args(p.args.iter());
        let workspace = p
            .workspace
            .as_deref()
            .map(|root| create_workspace(root, &label))
            .transpose()
            .map_err(|e| format!("create workspace for {label}: {e}"))?;
        if let Some(ws) = &workspace {
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
        lp = lp.limits(p.limits());
        if p.piped_stdio {
            lp = lp.stdio(StdioMode::Piped, StdioMode::Piped, StdioMode::Piped);
        }
        let mut h = self.launcher.spawn(&lp).map_err(|e| {
            if let Some(ws) = &workspace {
                let _ = fs::remove_dir(ws);
            }
            e.to_string()
        })?;
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
    use std::os::unix::fs::symlink;

    fn profile() -> ProfileSpec {
        serde_json::from_str(r#"{"program":"/bin/true"}"#).unwrap()
    }

    #[test]
    fn omitted_limits_inherit_launcher_defaults() {
        let mut p = profile();
        assert_eq!(p.limits(), ResourceLimits::default());
        p.pids_max = Some(CgroupLimit::Max(64));
        assert_eq!(p.limits().pids_max, Some(64));
        assert_eq!(
            p.limits().memory_max_bytes,
            ResourceLimits::default().memory_max_bytes
        );
    }

    /// Security review finding 2 (proof of concept `limits`): a profile
    /// without limits keeps the launcher's memory and pid limits; only the
    /// explicit word "unlimited" removes one.
    #[test]
    fn only_an_explicit_unlimited_removes_a_limit() {
        let defaults = ResourceLimits::default();
        assert!(defaults.memory_max_bytes.is_some() && defaults.pids_max.is_some());
        for json in [
            r#"{"program":"/bin/sleep","args":["5"]}"#,
            r#"{"program":"/bin/sleep","memory_max_bytes":null,"pids_max":null}"#,
        ] {
            let p: ProfileSpec = serde_json::from_str(json).unwrap();
            assert_eq!(p.limits(), defaults, "{json}");
        }
        let p: ProfileSpec = serde_json::from_str(
            r#"{"program":"/bin/sleep","memory_max_bytes":"unlimited","pids_max":100}"#,
        )
        .unwrap();
        assert_eq!(p.limits().memory_max_bytes, None);
        assert_eq!(p.limits().pids_max, Some(100));
        assert_eq!(p.limits().swap_max_bytes, defaults.swap_max_bytes);
        for bad in ["\"none\"", "\"\"", "-1", "1.5", "\"Unlimited\"", "true"] {
            let json = format!(r#"{{"program":"/bin/sleep","pids_max":{bad}}}"#);
            assert!(
                serde_json::from_str::<ProfileSpec>(&json).is_err(),
                "{json}"
            );
        }
        let round = serde_json::to_string(&p).unwrap();
        assert!(
            round.contains(r#""memory_max_bytes":"unlimited""#),
            "{round}"
        );
        assert!(round.contains(r#""pids_max":100"#), "{round}");
    }

    #[test]
    fn each_workspace_is_created_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let a = AgentLabel::new("e1.s0").unwrap();
        let b = AgentLabel::new("e1.s1").unwrap();
        let first = create_workspace(tmp.path(), &a).unwrap();
        fs::write(first.join("marker"), "first").unwrap();
        let second = create_workspace(tmp.path(), &b).unwrap();
        assert!(second.read_dir().unwrap().next().is_none());
        assert_eq!(fs::metadata(second).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            create_workspace(tmp.path(), &a).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn profiles_reject_overlaps_with_protected_paths_and_other_workspaces() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let workspaces = root.join("workspaces");
        let state = root.join("state");
        let run = root.join("run");
        for path in [&workspaces, &state, &run] {
            DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        let protected = [state.clone(), run.join("admin.sock")];
        let state_child = state.join("child");
        fs::create_dir(&state_child).unwrap();
        let alias = root.join("alias");
        symlink(&state_child, &alias).unwrap();

        let mut worker = profile();
        worker.workspace = Some(workspaces.clone());
        let mut profiles = HashMap::from([("worker".into(), worker), ("other".into(), profile())]);
        prepare_profiles(&mut profiles, &protected).unwrap();
        for host in [&root, &run, &state, &alias, &workspaces] {
            profiles.get_mut("other").unwrap().ro_binds = vec![(host.clone(), "/data".into())];
            assert!(matches!(
                prepare_profiles(&mut profiles, &protected),
                Err(LaunchError::InvalidProfile(_))
            ));
        }
        let other = profiles.get_mut("other").unwrap();
        other.ro_binds.clear();
        other.workspace = Some(alias);
        assert!(matches!(
            prepare_profiles(&mut profiles, &protected),
            Err(LaunchError::InvalidProfile(_))
        ));
    }
}
