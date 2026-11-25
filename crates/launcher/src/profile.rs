use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::Serialize;

use crate::AgentLabel;

/// How the launcher treats cgroup v2 delegation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CgroupRequirement {
    /// Default. A delegated, writable cgroup v2 subtree with the `cpu`,
    /// `memory` and `pids` controllers and `cgroup.kill` must exist; otherwise
    /// every launch is refused (R10).
    Required,
    /// Explicit operator opt-out: if delegation is unavailable, sandboxes run
    /// without resource limits and process-tree cleanup falls back to PID
    /// namespace teardown. The reason is mandatory, is copied into every
    /// [`crate::LaunchRecord`], and a warning is printed on each launch. If
    /// delegation *is* available it is still used.
    AllowMissing { operator_reason: String },
}

/// How the launcher treats Landlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockRequirement {
    /// Default. Landlock ABI >= [`crate::REQUIRED_LANDLOCK_ABI`] must be
    /// available and the in-sandbox ruleset must report `FullyEnforced`.
    Required,
    /// Apply whatever the kernel supports; record the outcome.
    BestEffort,
    /// Do not apply Landlock (recorded).
    Disabled,
}

/// Operator-level launcher configuration (trusted).
#[derive(Clone, Debug)]
pub struct LauncherConfig {
    /// Absolute path of the bubblewrap binary. Never looked up in `$PATH`.
    pub bwrap_path: PathBuf,
    /// Absolute host path of the `tessera-sandbox-init` shim. Defaults to the
    /// file next to the current executable.
    pub init_path: PathBuf,
    pub cgroup: CgroupRequirement,
    pub landlock: LandlockRequirement,
    /// Name of the launcher-owned cgroup created below the delegation root.
    pub cgroup_group_name: String,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        let init_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("tessera-sandbox-init")))
            .unwrap_or_else(|| PathBuf::from("/usr/libexec/tessera/tessera-sandbox-init"));
        Self {
            bwrap_path: PathBuf::from("/usr/bin/bwrap"),
            init_path,
            cgroup: CgroupRequirement::Required,
            landlock: LandlockRequirement::Required,
            cgroup_group_name: "tessera.launcher".to_string(),
        }
    }
}

/// cgroup v2 limits applied to the sandbox leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceLimits {
    /// `memory.max` in bytes.
    pub memory_max_bytes: Option<u64>,
    /// `memory.swap.max` in bytes (0 disables swap for the sandbox).
    pub swap_max_bytes: Option<u64>,
    /// `pids.max`.
    pub pids_max: Option<u64>,
    /// `cpu.max` as (quota_us, period_us).
    pub cpu_max: Option<(u64, u64)>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: Some(2 << 30),
            swap_max_bytes: Some(0),
            pids_max: Some(512),
            cpu_max: None,
        }
    }
}

/// Additional read-only bind (host path -> sandbox path).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoBind {
    pub host: PathBuf,
    pub sandbox: PathBuf,
}

/// Standard stream configuration for the workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioMode {
    Null,
    Inherit,
    Piped,
}

/// A trusted launch profile (spec §9.2 `Spawn { launch_profile }`).
#[derive(Clone, Debug)]
pub struct LaunchProfile {
    pub agent: AgentLabel,
    /// Program path *inside* the sandbox (e.g. `/usr/bin/python3`).
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Host directory bound read-write at [`crate::SANDBOX_WORKSPACE`].
    pub workspace: Option<PathBuf>,
    /// Bind the workspace read-only instead.
    pub workspace_read_only: bool,
    /// Explicit workload environment. Keys starting with `TESSERA_` are
    /// reserved. `PATH`, `HOME`, `TMPDIR`, `LANG` get safe defaults if absent.
    pub env: BTreeMap<String, String>,
    pub extra_ro_binds: Vec<RoBind>,
    pub limits: ResourceLimits,
    pub stdin: StdioMode,
    pub stdout: StdioMode,
    pub stderr: StdioMode,
}

impl LaunchProfile {
    pub fn new(agent: AgentLabel, program: impl Into<PathBuf>) -> Self {
        Self {
            agent,
            program: program.into(),
            args: Vec::new(),
            workspace: None,
            workspace_read_only: false,
            env: BTreeMap::new(),
            extra_ro_binds: Vec::new(),
            limits: ResourceLimits::default(),
            stdin: StdioMode::Null,
            stdout: StdioMode::Inherit,
            stderr: StdioMode::Inherit,
        }
    }

    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn workspace(mut self, dir: impl Into<PathBuf>) -> Self {
        self.workspace = Some(dir.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn ro_bind(mut self, host: impl Into<PathBuf>, sandbox: impl Into<PathBuf>) -> Self {
        self.extra_ro_binds.push(RoBind {
            host: host.into(),
            sandbox: sandbox.into(),
        });
        self
    }

    pub fn stdio(mut self, stdin: StdioMode, stdout: StdioMode, stderr: StdioMode) -> Self {
        self.stdin = stdin;
        self.stdout = stdout;
        self.stderr = stderr;
        self
    }

    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }
}
