//! Host feature probe (spec §10.2: "Record tested kernel build, enabled LSMs,
//! BTF availability, feature probe and policy version. Block launch if
//! mandatory controls are unavailable").

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use landlock::{AccessFs, LandlockStatus, Ruleset, RulesetAttr};
use serde::Serialize;

use crate::launcher::runtime_args;
use crate::{
    CgroupRequirement, LandlockRequirement, LauncherConfig, MIN_BWRAP_VERSION,
    REQUIRED_LANDLOCK_ABI, seccomp,
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct BwrapProbe {
    pub path: String,
    pub found: bool,
    pub version: Option<String>,
    pub version_ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct UserNamespaceProbe {
    /// Debian `kernel.unprivileged_userns_clone` sysctl, if present.
    pub unprivileged_userns_clone: Option<String>,
    pub max_user_namespaces: Option<u64>,
    /// Ubuntu-style AppArmor restriction sysctl, if present.
    pub apparmor_restrict_unprivileged_userns: Option<String>,
    /// A real bwrap sandbox with all namespaces + `--disable-userns` started.
    pub sandbox_smoke_test: bool,
    pub smoke_test_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SeccompProbe {
    /// Kernel exposes `Seccomp:` in /proc/self/status (CONFIG_SECCOMP).
    pub available: bool,
    pub actions_avail: Vec<String>,
    /// Our filter set compiles for this architecture.
    pub filter_compiles: bool,
    pub filter_count: usize,
    pub denied_syscalls: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct LandlockProbe {
    pub in_lsm_list: bool,
    /// Kernel Landlock ABI (`None` if unsupported/disabled).
    pub abi: Option<i32>,
    pub status: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CgroupProbe {
    pub v2_mounted: bool,
    pub own_cgroup: Option<String>,
    pub delegation_root: Option<String>,
    pub enabled_controllers: Vec<String>,
    pub cgroup_kill: bool,
    pub usable: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct BpfLsmProbe {
    /// `bpf` is in /sys/kernel/security/lsm.
    pub active: bool,
    pub btf_vmlinux: bool,
    pub note: String,
}

/// Result of probing the host.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FeatureReport {
    pub kernel_release: String,
    pub kernel_version: String,
    pub arch: String,
    pub lsms: Vec<String>,
    pub yama_ptrace_scope: Option<String>,
    pub bwrap: BwrapProbe,
    pub user_namespaces: UserNamespaceProbe,
    pub seccomp: SeccompProbe,
    pub landlock: LandlockProbe,
    pub cgroup: CgroupProbe,
    pub bpf_lsm: BpfLsmProbe,
}

/// A mandatory control that is unavailable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MissingControl {
    pub control: String,
    pub reason: String,
}

fn read_opt(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

pub(crate) fn parse_bwrap_version(s: &str) -> Option<(u32, u32, u32)> {
    let v = s.split_whitespace().last()?;
    let mut it = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((
        it.next()??,
        it.next().flatten().unwrap_or(0),
        it.next().flatten().unwrap_or(0),
    ))
}

fn probe_landlock(in_lsm_list: bool) -> LandlockProbe {
    // Landlock domains are per-thread: restricting a throw-away thread reveals
    // the kernel ABI without restricting the launcher itself.
    let status = std::thread::spawn(|| {
        Ruleset::default()
            .handle_access(AccessFs::Execute)
            .and_then(|r| r.create())
            .and_then(|r| r.restrict_self())
            .map(|s| s.landlock)
            .map_err(|e| e.to_string())
    })
    .join()
    .unwrap_or_else(|_| Err("probe thread panicked".into()));
    match status {
        Ok(LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        }) => LandlockProbe {
            in_lsm_list,
            abi: Some(kernel_abi.unwrap_or(effective_abi as i32)),
            status: "available".into(),
        },
        Ok(LandlockStatus::NotEnabled) => LandlockProbe {
            in_lsm_list,
            abi: None,
            status: "not enabled (EOPNOTSUPP)".into(),
        },
        Ok(LandlockStatus::NotImplemented) => LandlockProbe {
            in_lsm_list,
            abi: None,
            status: "not implemented (ENOSYS)".into(),
        },
        Err(e) => LandlockProbe {
            in_lsm_list,
            abi: None,
            status: format!("probe error: {e}"),
        },
    }
}

fn probe_bwrap(path: &Path) -> BwrapProbe {
    let mut p = BwrapProbe {
        path: path.display().to_string(),
        ..Default::default()
    };
    match Command::new(path)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => {
            p.found = true;
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            p.version_ok = parse_bwrap_version(&v).is_some_and(|v| v >= MIN_BWRAP_VERSION);
            if !p.version_ok {
                p.error = Some(format!(
                    "version {v:?} older than required {}.{}.{}",
                    MIN_BWRAP_VERSION.0, MIN_BWRAP_VERSION.1, MIN_BWRAP_VERSION.2
                ));
            }
            p.version = Some(v);
        }
        Ok(out) => p.error = Some(format!("--version exited with {}", out.status)),
        Err(e) => p.error = Some(format!("cannot execute: {e}")),
    }
    p
}

fn smoke_test(bwrap: &Path) -> Result<(), String> {
    let mut cmd = Command::new(bwrap);
    cmd.env_clear()
        .args([
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
        ])
        .args(runtime_args())
        .args(["--proc", "/proc", "--dev", "/dev", "--", "/usr/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

impl FeatureReport {
    /// Probes the host. Side effects: runs `bwrap --version` and one trivial
    /// sandbox; applies a Landlock ruleset to a short-lived thread.
    pub fn probe(config: &LauncherConfig) -> Self {
        let lsms: Vec<String> = read_opt("/sys/kernel/security/lsm")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let has_lsm = |n: &str| lsms.iter().any(|l| l == n);

        let bwrap = probe_bwrap(&config.bwrap_path);
        let mut userns = UserNamespaceProbe {
            unprivileged_userns_clone: read_opt("/proc/sys/kernel/unprivileged_userns_clone"),
            max_user_namespaces: read_opt("/proc/sys/user/max_user_namespaces")
                .and_then(|s| s.parse().ok()),
            apparmor_restrict_unprivileged_userns: read_opt(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            ),
            ..Default::default()
        };
        if bwrap.found {
            match smoke_test(&config.bwrap_path) {
                Ok(()) => userns.sandbox_smoke_test = true,
                Err(e) => userns.smoke_test_error = Some(e),
            }
        } else {
            userns.smoke_test_error = Some("bwrap not available".into());
        }

        let status = read_opt("/proc/self/status").unwrap_or_default();
        let mut sc = SeccompProbe {
            available: status.lines().any(|l| l.starts_with("Seccomp:")),
            actions_avail: read_opt("/proc/sys/kernel/seccomp/actions_avail")
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect(),
            denied_syscalls: seccomp::denied_syscalls().len(),
            ..Default::default()
        };
        match seccomp::all_filters() {
            Ok(f) => {
                sc.filter_compiles = true;
                sc.filter_count = f.len();
            }
            Err(e) => sc.error = Some(e.to_string()),
        }

        FeatureReport {
            kernel_release: read_opt("/proc/sys/kernel/osrelease").unwrap_or_default(),
            kernel_version: read_opt("/proc/sys/kernel/version").unwrap_or_default(),
            arch: std::env::consts::ARCH.to_string(),
            yama_ptrace_scope: read_opt("/proc/sys/kernel/yama/ptrace_scope"),
            bwrap,
            user_namespaces: userns,
            seccomp: sc,
            landlock: probe_landlock(has_lsm("landlock")),
            cgroup: crate::cgroup::probe(),
            bpf_lsm: BpfLsmProbe {
                active: has_lsm("bpf"),
                btf_vmlinux: Path::new("/sys/kernel/btf/vmlinux").exists(),
                note: "informational: BPF LSM policies are WP7 and not yet mandatory; \
                       attaching requires privileges the launcher does not hold"
                    .into(),
            },
            lsms,
        }
    }

    /// Evaluates the report against the operator policy. An empty result
    /// means every mandatory control is present.
    pub fn missing_mandatory(
        &self,
        cgroup: &CgroupRequirement,
        landlock: LandlockRequirement,
    ) -> Vec<MissingControl> {
        let mut m = Vec::new();
        let mut miss = |control: &str, reason: String| {
            m.push(MissingControl {
                control: control.into(),
                reason,
            })
        };
        if !self.bwrap.found || !self.bwrap.version_ok {
            miss(
                "bubblewrap",
                self.bwrap
                    .error
                    .clone()
                    .unwrap_or_else(|| "unusable".into()),
            );
        }
        if !self.user_namespaces.sandbox_smoke_test {
            miss(
                "namespaces",
                self.user_namespaces
                    .smoke_test_error
                    .clone()
                    .unwrap_or_else(|| "sandbox smoke test failed".into()),
            );
        }
        let needs = ["errno", "allow", "kill_process"];
        if !self.seccomp.available
            || !self.seccomp.filter_compiles
            || !needs
                .iter()
                .all(|a| self.seccomp.actions_avail.iter().any(|x| x == a))
        {
            miss(
                "seccomp",
                self.seccomp.error.clone().unwrap_or_else(|| {
                    format!(
                        "seccomp unavailable or missing actions {needs:?} (have {:?})",
                        self.seccomp.actions_avail
                    )
                }),
            );
        }
        if landlock == LandlockRequirement::Required
            && self.landlock.abi.unwrap_or(0) < REQUIRED_LANDLOCK_ABI
        {
            miss(
                "landlock",
                format!(
                    "Landlock ABI >= {REQUIRED_LANDLOCK_ABI} required, kernel reports {:?} ({})",
                    self.landlock.abi, self.landlock.status
                ),
            );
        }
        if *cgroup == CgroupRequirement::Required && !self.cgroup.usable {
            miss(
                "cgroup_v2_delegation",
                format!(
                    "{} (operator may opt out explicitly with CgroupRequirement::AllowMissing)",
                    self.cgroup
                        .reason
                        .clone()
                        .unwrap_or_else(|| "unusable".into())
                ),
            );
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> FeatureReport {
        FeatureReport {
            bwrap: BwrapProbe {
                found: true,
                version_ok: true,
                ..Default::default()
            },
            user_namespaces: UserNamespaceProbe {
                sandbox_smoke_test: true,
                ..Default::default()
            },
            seccomp: SeccompProbe {
                available: true,
                filter_compiles: true,
                actions_avail: vec!["errno".into(), "allow".into(), "kill_process".into()],
                ..Default::default()
            },
            landlock: LandlockProbe {
                abi: Some(6),
                ..Default::default()
            },
            cgroup: CgroupProbe {
                usable: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn complete_host_passes() {
        let r = good();
        assert!(
            r.missing_mandatory(&CgroupRequirement::Required, LandlockRequirement::Required)
                .is_empty()
        );
    }

    #[test]
    fn each_missing_control_refuses() {
        let req = CgroupRequirement::Required;
        let ll = LandlockRequirement::Required;
        type Mutation = Box<dyn Fn(&mut FeatureReport)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("bubblewrap", Box::new(|r| r.bwrap.found = false)),
            ("bubblewrap", Box::new(|r| r.bwrap.version_ok = false)),
            (
                "namespaces",
                Box::new(|r| r.user_namespaces.sandbox_smoke_test = false),
            ),
            ("seccomp", Box::new(|r| r.seccomp.available = false)),
            ("seccomp", Box::new(|r| r.seccomp.actions_avail.clear())),
            ("landlock", Box::new(|r| r.landlock.abi = None)),
            ("landlock", Box::new(|r| r.landlock.abi = Some(5))),
            (
                "cgroup_v2_delegation",
                Box::new(|r| r.cgroup.usable = false),
            ),
        ];
        for (control, mutate) in cases {
            let mut r = good();
            mutate(&mut r);
            let missing = r.missing_mandatory(&req, ll);
            assert_eq!(missing.len(), 1, "{control}: {missing:?}");
            assert_eq!(missing[0].control, control);
        }
    }

    #[test]
    fn explicit_opt_outs() {
        let mut r = good();
        r.cgroup.usable = false;
        r.landlock.abi = None;
        let optout = CgroupRequirement::AllowMissing {
            operator_reason: "CI container without delegation".into(),
        };
        assert!(
            r.missing_mandatory(&optout, LandlockRequirement::BestEffort)
                .is_empty()
        );
        assert!(
            r.missing_mandatory(&optout, LandlockRequirement::Disabled)
                .is_empty()
        );
    }

    #[test]
    fn version_parse() {
        assert_eq!(parse_bwrap_version("bubblewrap 0.12.0"), Some((0, 12, 0)));
        assert_eq!(parse_bwrap_version("bubblewrap 0.8"), Some((0, 8, 0)));
        assert!(parse_bwrap_version("bubblewrap 0.6.2").unwrap() < MIN_BWRAP_VERSION);
        assert_eq!(parse_bwrap_version("garbage"), None);
    }
}
