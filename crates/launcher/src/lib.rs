//! Tessera trusted launcher (spec §3, §9.1, §10.1, WP5).
//!
//! The launcher turns a trusted [`LaunchProfile`] into a confined sandbox
//! principal:
//!
//! * a Bubblewrap (`bwrap`) invocation with fresh user, mount, PID, IPC, UTS,
//!   network and cgroup namespaces, a minimal read-only runtime, a tmpfs
//!   `/tmp`, an explicit workspace bind, sandbox-only `/proc` and a minimal
//!   `/dev`;
//! * a seccomp-BPF deny filter (built with `seccompiler`, passed to bwrap
//!   through `--add-seccomp-fd`);
//! * a Landlock ruleset applied by the in-sandbox `tessera-sandbox-init`
//!   shim, which also closes every inherited descriptor except the broker
//!   channel before `exec`-ing the workload;
//! * a dedicated cgroup v2 leaf with CPU/memory/PID limits and `cgroup.kill`
//!   based process-tree termination when cgroup delegation is available.
//!
//! Unsupported mandatory controls fail closed (requirement R10): see
//! [`FeatureReport::missing_mandatory`] and [`Launcher::new`].
//!
//! # Broker channel
//!
//! Every sandbox gets a fresh `AF_UNIX`/`SOCK_SEQPACKET` socketpair. The host
//! end is returned in [`SandboxHandle`]; the sandbox end is installed as file
//! descriptor [`BROKER_FD`] (3) in the workload and announced through the
//! environment variable [`BROKER_FD_ENV`] (`TESSERA_BROKER_FD=3`). No other
//! descriptor above 2 survives into the workload.

#![forbid(unsafe_code)]

mod agent;
mod cgroup;
mod error;
pub mod init;
mod launcher;
mod probe;
mod profile;
pub mod seccomp;

pub use agent::AgentLabel;
pub use cgroup::{CgroupLeaf, sweep_group as sweep_cgroup_group};
pub use error::LaunchError;
pub use launcher::{ConfinementStatus, LaunchRecord, Launcher, SandboxHandle};
pub use probe::{
    BpfLsmProbe, BwrapProbe, CgroupProbe, FeatureReport, LandlockProbe, MissingControl,
    SeccompProbe, UserNamespaceProbe,
};
pub use profile::{
    CgroupRequirement, LandlockRequirement, LaunchProfile, LauncherConfig, ResourceLimits, RoBind,
    StdioMode,
};

/// File descriptor number of the broker channel inside the workload.
pub const BROKER_FD: i32 = 3;
/// Environment variable telling the workload which fd is its broker channel.
pub const BROKER_FD_ENV: &str = "TESSERA_BROKER_FD";
/// Environment variable carrying the caller-supplied agent label.
pub const AGENT_ID_ENV: &str = "TESSERA_AGENT_ID";
/// Mount point of the workspace inside the sandbox.
pub const SANDBOX_WORKSPACE: &str = "/workspace";
/// Path of the init shim inside the sandbox.
pub const SANDBOX_INIT_PATH: &str = "/.tessera/init";
/// Minimum supported bubblewrap version (`--disable-userns` appeared in 0.8.0).
pub const MIN_BWRAP_VERSION: (u32, u32, u32) = (0, 8, 0);
/// Landlock ABI the `Required` policy is pinned to (Linux 6.12: ABI 6, which
/// adds signal and abstract-unix-socket scoping).
pub const REQUIRED_LANDLOCK_ABI: i32 = 6;
