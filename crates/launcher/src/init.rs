//! In-sandbox init shim (`tessera-sandbox-init`).
//!
//! bubblewrap executes this shim as the sandbox's first program, *after* the
//! namespaces, mounts, capability drop, `no_new_privs` and seccomp filters are
//! in place. Before it `exec`s the untrusted workload it:
//!
//! 1. closes every file descriptor except 0, 1, 2 and the explicitly kept
//!    broker channel (defence against descriptors leaked into the launcher or
//!    bubblewrap by their own parents);
//! 2. applies a Landlock ruleset (filesystem access limited to the runtime,
//!    workspace, `/tmp` and `/dev`; all TCP bind/connect denied except on
//!    the ports named by `--allow-tcp-port` (compatibility-mode loopback
//!    shim, Required mode only); signal and abstract-unix-socket scoping);
//! 3. verifies seccomp mode 2 and `NoNewPrivs` from `/proc/self/status`;
//! 4. reports one status line to the launcher over the status pipe and only
//!    then `exec`s the workload.
//!
//! Command line (built by [`crate::Launcher`]; not a stable interface):
//!
//! ```text
//! tessera-sandbox-init --status-fd N [--keep-fd N]... --landlock required|best_effort|disabled
//!     [--allow-tcp-port PORT]... [--ro PATH]... [--rw PATH]... [--dev PATH]... -- PROGRAM [ARGS]...
//! ```

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::LandlockRequirement;

/// Exit code when the shim refuses to start the workload.
pub const EXIT_CONFINEMENT_FAILED: i32 = 126;
/// Exit code when `exec` of the workload fails.
pub const EXIT_EXEC_FAILED: i32 = 127;

#[derive(Debug, Default)]
struct Args {
    status_fd: Option<i32>,
    keep: Vec<i32>,
    landlock: Option<LandlockRequirement>,
    ro: Vec<PathBuf>,
    rw: Vec<PathBuf>,
    dev: Vec<PathBuf>,
    tcp_ports: Vec<u16>,
    program: Option<OsString>,
    args: Vec<OsString>,
}

fn parse(mut it: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut a = Args::default();
    let num = |v: Option<OsString>| -> Result<i32, String> {
        v.and_then(|s| s.into_string().ok())
            .and_then(|s| s.parse().ok())
            .filter(|n: &i32| *n >= 0)
            .ok_or_else(|| "expected fd number".to_string())
    };
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--status-fd") => a.status_fd = Some(num(it.next())?),
            Some("--keep-fd") => a.keep.push(num(it.next())?),
            Some("--landlock") => {
                a.landlock = Some(
                    match it.next().and_then(|s| s.into_string().ok()).as_deref() {
                        Some("required") => LandlockRequirement::Required,
                        Some("best_effort") => LandlockRequirement::BestEffort,
                        Some("disabled") => LandlockRequirement::Disabled,
                        other => return Err(format!("bad --landlock {other:?}")),
                    },
                )
            }
            Some("--allow-tcp-port") => {
                let port = it
                    .next()
                    .and_then(|s| s.into_string().ok())
                    .and_then(|s| s.parse::<u16>().ok())
                    .filter(|p| *p != 0)
                    .ok_or("--allow-tcp-port needs a non-zero port")?;
                a.tcp_ports.push(port);
            }
            Some("--ro") => a.ro.push(it.next().ok_or("--ro needs a path")?.into()),
            Some("--rw") => a.rw.push(it.next().ok_or("--rw needs a path")?.into()),
            Some("--dev") => a.dev.push(it.next().ok_or("--dev needs a path")?.into()),
            Some("--") => {
                a.program = Some(it.next().ok_or("missing program")?);
                a.args = it.collect();
                return Ok(a);
            }
            _ => return Err(format!("unexpected argument {arg:?}")),
        }
    }
    Err("missing `-- PROGRAM`".into())
}

/// Closes every descriptor except stdio and `keep`.
fn close_other_fds(keep: &[i32]) -> Result<Vec<i32>, String> {
    let open: Vec<i32> = fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("list /proc/self/fd: {e}"))?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    // The read_dir descriptor is closed by now; closing its stale number
    // simply returns EBADF.
    for fd in open {
        if fd > 2 && !keep.contains(&fd) {
            let _ = nix::unistd::close(fd);
        }
    }
    let listed: Vec<i32> = fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("list /proc/self/fd: {e}"))?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    // Drop the (now closed) descriptor read_dir itself used for the listing.
    let mut left: Vec<i32> = listed
        .into_iter()
        .filter(|fd| fs::read_link(format!("/proc/self/fd/{fd}")).is_ok())
        .collect();
    left.sort_unstable();
    Ok(left)
}

fn status_field(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
}

fn apply_landlock(a: &Args, req: LandlockRequirement) -> Result<String, String> {
    // A TCP port exception is only meaningful if Landlock restricts every
    // other port; anything weaker would silently open the network policy.
    if !a.tcp_ports.is_empty() && req != LandlockRequirement::Required {
        return Err("--allow-tcp-port requires --landlock required".into());
    }
    if req == LandlockRequirement::Disabled {
        return Ok("disabled".into());
    }
    let abi = ABI::V6;
    let level = CompatLevel::BestEffort;
    let fs_all = AccessFs::from_all(abi);
    let ro: BitFlags<AccessFs> = AccessFs::from_read(abi);
    let dev: BitFlags<AccessFs> = ro | AccessFs::WriteFile | AccessFs::IoctlDev;
    let e = |e: landlock::RulesetError| e.to_string();
    let mut created = Ruleset::default()
        .set_compatibility(level)
        .handle_access(fs_all)
        .map_err(e)?
        .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
        .map_err(e)?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(e)?
        .create()
        .map_err(e)?;
    let groups: [(&Vec<PathBuf>, BitFlags<AccessFs>); 3] =
        [(&a.ro, ro), (&a.rw, fs_all), (&a.dev, dev)];
    for (paths, access) in groups {
        for p in paths {
            // Paths absent from this sandbox (e.g. /lib32) are skipped: no rule
            // means no access, which is the safe direction.
            let Ok(md) = std::fs::metadata(p) else {
                continue;
            };
            // A single-file bind (e.g. one binary) gets a file-level rule:
            // directory-only rights (ReadDir, MakeReg, ...) do not apply to
            // a file, and asking for them would downgrade the ruleset to
            // "partial" and make a Required launch fail.
            let access = if md.is_dir() {
                access & fs_all
            } else {
                access & AccessFs::from_file(abi)
            };
            if let Ok(fd) = PathFd::new(p) {
                created = created.add_rule(PathBeneath::new(fd, access)).map_err(e)?;
            }
        }
    }
    for port in &a.tcp_ports {
        created = created
            .add_rule(NetPort::new(
                *port,
                AccessNet::BindTcp | AccessNet::ConnectTcp,
            ))
            .map_err(e)?;
    }
    let st = created.restrict_self().map_err(e)?;
    let label = match st.ruleset {
        RulesetStatus::FullyEnforced => "full",
        RulesetStatus::PartiallyEnforced => "partial",
        RulesetStatus::NotEnforced => "none",
    };
    if req == LandlockRequirement::Required
        && (st.ruleset != RulesetStatus::FullyEnforced || !st.no_new_privs)
    {
        return Err(format!(
            "Landlock required but ruleset is {label} (no_new_privs={})",
            st.no_new_privs
        ));
    }
    Ok(label.into())
}

/// Entry point of the `tessera-sandbox-init` binary. Never returns on success.
pub fn main_with_args(argv: impl Iterator<Item = OsString>) -> i32 {
    let a = match parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tessera-sandbox-init: {e}");
            return EXIT_CONFINEMENT_FAILED;
        }
    };
    // Re-open the status pipe through procfs so it is an owned File without
    // any unsafe fd adoption; the original number is closed below.
    let mut status = match a.status_fd {
        Some(fd) => match OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{fd}"))
        {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("tessera-sandbox-init: cannot open status fd {fd}: {e}");
                return EXIT_CONFINEMENT_FAILED;
            }
        },
        None => None,
    };
    let result = confine(&a, status.as_ref());
    match result {
        Ok(line) => {
            if let Some(f) = status.as_mut()
                && writeln!(f, "ok {line}").is_err()
            {
                return EXIT_CONFINEMENT_FAILED;
            }
            drop(status);
            let program = a.program.clone().unwrap_or_default();
            let err = Command::new(&program).args(&a.args).exec();
            eprintln!("tessera-sandbox-init: exec {program:?}: {err}");
            EXIT_EXEC_FAILED
        }
        Err(e) => {
            eprintln!("tessera-sandbox-init: refusing to start workload: {e}");
            if let Some(f) = status.as_mut() {
                let _ = writeln!(f, "err {}", e.replace('\n', " "));
            }
            EXIT_CONFINEMENT_FAILED
        }
    }
}

fn confine(a: &Args, status: Option<&File>) -> Result<String, String> {
    let mut keep = a.keep.clone();
    if let Some(f) = status {
        keep.push(f.as_raw_fd());
    }
    let left = close_other_fds(&keep)?;
    let req = a.landlock.ok_or("missing --landlock")?;
    let landlock = apply_landlock(a, req)?;

    let proc_status = fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("read /proc/self/status: {e}"))?;
    let seccomp = status_field(&proc_status, "Seccomp:").unwrap_or_default();
    let nnp = status_field(&proc_status, "NoNewPrivs:").unwrap_or_default();
    let cap_eff = status_field(&proc_status, "CapEff:").unwrap_or_default();
    if seccomp != "2" {
        return Err(format!("seccomp filter not active (Seccomp: {seccomp:?})"));
    }
    if nnp != "1" {
        return Err(format!("no_new_privs not set (NoNewPrivs: {nnp:?})"));
    }
    if !cap_eff.trim_start_matches('0').is_empty() {
        return Err(format!(
            "effective capabilities not empty (CapEff: {cap_eff})"
        ));
    }
    let visible: Vec<String> = left
        .iter()
        .filter(|fd| Some(**fd) != status.map(|f| f.as_raw_fd()))
        .map(|fd| fd.to_string())
        .collect();
    Ok(format!(
        "seccomp={seccomp} nnp={nnp} capeff={cap_eff} landlock={landlock} fds={}",
        visible.join(",")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> impl Iterator<Item = OsString> {
        v.iter().map(OsString::from).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn parses_command_line() {
        let a = parse(os(&[
            "--status-fd",
            "4",
            "--keep-fd",
            "3",
            "--landlock",
            "required",
            "--ro",
            "/usr",
            "--rw",
            "/workspace",
            "--dev",
            "/dev",
            "--",
            "/bin/sh",
            "-c",
            "--ro",
        ]))
        .unwrap();
        assert_eq!(a.status_fd, Some(4));
        assert_eq!(a.keep, vec![3]);
        assert_eq!(a.landlock, Some(LandlockRequirement::Required));
        assert_eq!(a.program, Some("/bin/sh".into()));
        assert_eq!(a.args, vec![OsString::from("-c"), OsString::from("--ro")]);
    }

    #[test]
    fn tcp_port_exception_parsing_and_fail_closed() {
        let a = parse(os(&[
            "--landlock",
            "required",
            "--allow-tcp-port",
            "18080",
            "--",
            "/bin/true",
        ]))
        .unwrap();
        assert_eq!(a.tcp_ports, vec![18080]);
        for bad in ["0", "70000", "x"] {
            assert!(parse(os(&["--allow-tcp-port", bad, "--", "x"])).is_err());
        }
        // A port exception without a Required ruleset is refused before any
        // Landlock call (it would otherwise silently open the network).
        for req in [
            LandlockRequirement::BestEffort,
            LandlockRequirement::Disabled,
        ] {
            let mut a = Args::default();
            a.tcp_ports.push(18080);
            assert!(apply_landlock(&a, req).is_err());
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(os(&["--status-fd", "-1", "--", "x"])).is_err());
        assert!(parse(os(&["--landlock", "maybe", "--", "x"])).is_err());
        assert!(parse(os(&["--keep-fd", "3"])).is_err());
        assert!(parse(os(&["--bogus", "--", "x"])).is_err());
    }
}
