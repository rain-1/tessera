//! cgroup v2 delegation discovery and per-sandbox leaf management.
//!
//! Layout: `<delegation root>/<group>/<agent-label>-<unique>` where the
//! delegation root is the highest ancestor of the launcher's own cgroup that
//! is owned and writable by the launcher's effective UID (for a systemd user
//! session this is `user@UID.service`). The `<group>` node holds no processes
//! and enables the `cpu memory pids` controllers for its children.
//!
//! The workload is placed in its leaf *before* bubblewrap runs: the launcher
//! spawns `/bin/sh -c 'echo 0 > <leaf>/cgroup.procs && exec bwrap ...'`, so
//! every process of the sandbox (including bwrap's helpers) is born inside the
//! leaf. Process-tree termination writes `1` to `cgroup.kill`.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::fs::{Access, access};
use serde::Serialize;

use crate::probe::CgroupProbe;
use crate::{AgentLabel, LaunchError, ResourceLimits};

pub(crate) const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

fn read_trim(p: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(p)?.trim().to_string())
}

fn owned_and_writable(p: &Path, euid: u32) -> bool {
    match fs::metadata(p) {
        Ok(m) => m.uid() == euid && access(p, Access::WRITE_OK).is_ok(),
        Err(_) => false,
    }
}

/// Probes cgroup v2 and looks for a delegated subtree.
pub(crate) fn probe() -> CgroupProbe {
    let mut probe = CgroupProbe::default();
    let mount = Path::new(CGROUP_MOUNT);
    probe.v2_mounted = rustix::fs::statfs(mount)
        .map(|s| s.f_type == CGROUP2_SUPER_MAGIC)
        .unwrap_or(false);
    if !probe.v2_mounted {
        probe.reason = Some("cgroup2 not mounted at /sys/fs/cgroup (hybrid/v1 host?)".into());
        return probe;
    }
    let own = fs::read_to_string("/proc/self/cgroup").ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
    });
    let Some(own) = own else {
        probe.reason = Some("no unified (0::) entry in /proc/self/cgroup".into());
        return probe;
    };
    probe.own_cgroup = Some(own.clone());
    let euid = rustix::process::geteuid().as_raw();

    // Walk from the top so we pick the highest delegated ancestor.
    let mut cur = mount.to_path_buf();
    let mut found = None;
    for comp in Path::new(&own).components().skip(1) {
        cur.push(comp);
        if owned_and_writable(&cur, euid)
            && owned_and_writable(&cur.join("cgroup.procs"), euid)
            && owned_and_writable(&cur.join("cgroup.subtree_control"), euid)
        {
            found = Some(cur.clone());
            break;
        }
    }
    let Some(root) = found else {
        probe.reason = Some(format!(
            "no ancestor of {own} is delegated to uid {euid} (needs ownership of the directory, \
             cgroup.procs and cgroup.subtree_control); run under a systemd user session with \
             Delegate=yes or ask the operator for a delegated subtree"
        ));
        return probe;
    };
    let subtree = read_trim(&root.join("cgroup.subtree_control")).unwrap_or_default();
    let enabled: Vec<String> = subtree.split_whitespace().map(str::to_string).collect();
    probe.delegation_root = Some(root.display().to_string());
    probe.enabled_controllers = enabled.clone();
    probe.cgroup_kill =
        Path::new(CGROUP_MOUNT).join("cgroup.kill").exists() || root.join("cgroup.kill").exists();
    let missing: Vec<&str> = REQUIRED_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| !enabled.iter().any(|e| e == c))
        .collect();
    if !missing.is_empty() {
        probe.reason = Some(format!(
            "delegation root {} does not enable controller(s) {missing:?} in cgroup.subtree_control",
            root.display()
        ));
    } else if !probe.cgroup_kill {
        probe.reason = Some("cgroup.kill unsupported (kernel < 5.14)".into());
    } else {
        probe.usable = true;
    }
    probe
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A per-sandbox cgroup leaf owned by the launcher.
#[derive(Debug, Serialize)]
pub struct CgroupLeaf {
    path: PathBuf,
    #[serde(skip)]
    removed: bool,
}

impl CgroupLeaf {
    pub(crate) fn create(
        delegation_root: &Path,
        group: &str,
        agent: &AgentLabel,
        limits: &ResourceLimits,
    ) -> Result<Self, LaunchError> {
        let cg = |m: String| LaunchError::Cgroup(m);
        if group.is_empty() || group.contains('/') || group.starts_with('.') {
            return Err(cg(format!("invalid cgroup group name {group:?}")));
        }
        let group_dir = delegation_root.join(group);
        match fs::create_dir(&group_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(cg(format!("mkdir {}: {e}", group_dir.display()))),
        }
        let want = "+cpu +memory +pids";
        let current = read_trim(&group_dir.join("cgroup.subtree_control")).unwrap_or_default();
        if !REQUIRED_CONTROLLERS
            .iter()
            .all(|c| current.split_whitespace().any(|e| e == *c))
        {
            fs::write(group_dir.join("cgroup.subtree_control"), want).map_err(|e| {
                cg(format!(
                    "enable controllers in {}: {e}",
                    group_dir.display()
                ))
            })?;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!(
            "{}-{}-{}-{:x}",
            agent.as_str(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            nanos
        );
        let path = group_dir.join(name);
        fs::create_dir(&path).map_err(|e| cg(format!("mkdir {}: {e}", path.display())))?;
        let leaf = CgroupLeaf {
            path,
            removed: false,
        };
        let write = |file: &str, val: String| -> Result<(), LaunchError> {
            let p = leaf.path.join(file);
            fs::write(&p, &val).map_err(|e| cg(format!("write {val:?} to {}: {e}", p.display())))
        };
        if let Some(m) = limits.memory_max_bytes {
            write("memory.max", m.to_string())?;
            write("memory.oom.group", "1".into())?;
        }
        if let Some(s) = limits.swap_max_bytes
            && leaf.path.join("memory.swap.max").exists()
        {
            write("memory.swap.max", s.to_string())?;
        }
        if let Some(p) = limits.pids_max {
            write("pids.max", p.to_string())?;
        }
        if let Some((quota, period)) = limits.cpu_max {
            write("cpu.max", format!("{quota} {period}"))?;
        }
        Ok(leaf)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    /// Kills every process in the leaf (`cgroup.kill`).
    pub fn kill(&self) -> io::Result<()> {
        fs::write(self.path.join("cgroup.kill"), "1")
    }

    /// Returns true while any process remains in the leaf.
    pub fn populated(&self) -> bool {
        fs::read_to_string(self.path.join("cgroup.events"))
            .map(|s| s.lines().any(|l| l.trim() == "populated 1"))
            .unwrap_or(false)
    }

    /// Kills remaining processes, waits for the leaf to drain and removes it.
    pub(crate) fn destroy(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.populated() {
                let _ = self.kill();
            }
            match fs::remove_dir(&self.path) {
                Ok(()) => {
                    self.removed = true;
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    self.removed = true;
                    return Ok(());
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}
