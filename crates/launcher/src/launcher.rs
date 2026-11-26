//! Launcher and sandbox handle.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::process::{
    Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use command_fds::{CommandFdExt, FdMapping};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use serde::Serialize;

use crate::cgroup::CgroupLeaf;
use crate::{
    AGENT_ID_ENV, AgentLabel, BROKER_FD, BROKER_FD_ENV, CgroupRequirement, FeatureReport,
    LandlockRequirement, LaunchError, LaunchProfile, LauncherConfig, MODEL_PORT_ENV,
    MODEL_SOCKET_ENV, ModelRoute, ResourceLimits, SANDBOX_INIT_PATH, SANDBOX_MODEL_SOCKET,
    SANDBOX_NETSHIM_PATH, SANDBOX_WORKSPACE, StdioMode, seccomp,
};

/// Descriptor numbers as seen by bubblewrap (and, before the init shim
/// closes them, by the sandbox). Only [`BROKER_FD`] survives into the workload.
const STATUS_FD: i32 = 4;
const FIRST_SECCOMP_FD: i32 = 5;
const FIRST_DATA_FD: i32 = 10;

/// How long to wait for the init shim to confirm confinement.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(20);

const RUNTIME_TOP_LEVEL: &[&str] = &["bin", "sbin", "lib", "lib32", "lib64", "libx32"];
/// Read-only host files exposed under /etc (if present).
const ETC_FILES: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/localtime",
];
/// Sandbox paths an extra bind may not shadow or nest in.
const RESERVED_SANDBOX_PATHS: &[&str] = &[
    "/usr",
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/dev",
    "/tmp",
    "/workspace",
    "/.tessera",
    "/sys",
    "/run",
];
/// Host locations that may never be exposed (nor any ancestor of them).
const PROTECTED_HOST_PATHS: &[&str] = &[
    "/etc",
    "/usr",
    "/run",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
    "/home",
    "/var/lib",
    "/tmp/.X11-unix",
];
/// Host trees under which nothing may be exposed.
const FORBIDDEN_HOST_TREES: &[&str] = &["/run", "/var/run", "/proc", "/sys", "/dev"];
/// Words that mark credential-agent sockets and keyrings when they appear
/// in a path component (split at every non-alphanumeric character, compared
/// case-insensitively), e.g. `gnupg/S.gpg-agent`, `S.gpg-agent.ssh`,
/// `openssh_agent`, `.ssh`, `keyring`. Never in a model socket path or the
/// model socket directory (defence in depth behind `model_socket_dir`).
const CREDENTIAL_AGENT_WORDS: &[&str] = &["gnupg", "gpg", "keyring", "keyrings", "ssh", "openssh"];

/// Arguments laying out the read-only runtime (`/usr` plus top-level
/// symlinks or directories such as `/lib64`).
pub(crate) fn runtime_args() -> Vec<OsString> {
    let mut v: Vec<OsString> = vec!["--ro-bind".into(), "/usr".into(), "/usr".into()];
    for name in RUNTIME_TOP_LEVEL {
        let host = Path::new("/").join(name);
        match fs::symlink_metadata(&host) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Ok(target) = fs::read_link(&host) {
                    v.extend(["--symlink".into(), target.into(), host.into()]);
                }
            }
            Ok(m) if m.is_dir() => {
                v.extend(["--ro-bind".into(), host.clone().into(), host.into()]);
            }
            _ => {}
        }
    }
    v
}

/// Effective confinement reported by the in-sandbox init shim just before it
/// executed the workload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConfinementStatus {
    /// `Seccomp:` field of /proc/self/status (2 = filter mode).
    pub seccomp_mode: String,
    pub no_new_privs: bool,
    pub cap_eff: String,
    /// `full`, `partial`, `none` or `disabled`.
    pub landlock: String,
    /// File descriptors open when the workload was executed.
    pub open_fds: Vec<i32>,
}

impl ConfinementStatus {
    fn parse(line: &str) -> Self {
        let mut s = ConfinementStatus::default();
        for kv in line.split_whitespace() {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            match k {
                "seccomp" => s.seccomp_mode = v.into(),
                "nnp" => s.no_new_privs = v == "1",
                "capeff" => s.cap_eff = v.into(),
                "landlock" => s.landlock = v.into(),
                "fds" => s.open_fds = v.split(',').filter_map(|x| x.parse().ok()).collect(),
                _ => {}
            }
        }
        s
    }
}

/// Audit record of one launch: what was requested and what was confirmed.
#[derive(Clone, Debug, Serialize)]
pub struct LaunchRecord {
    pub agent: AgentLabel,
    pub launched_at_unix_ms: u128,
    pub outer_pid: u32,
    pub kernel_release: String,
    pub bwrap_version: Option<String>,
    pub namespaces: Vec<&'static str>,
    pub seccomp_denied_syscalls: Vec<&'static str>,
    pub seccomp_filters: usize,
    pub landlock_requirement: LandlockRequirement,
    pub cgroup_requirement: CgroupRequirement,
    /// Leaf cgroup path, or `None` when running under the operator opt-out.
    pub cgroup: Option<String>,
    /// Set when this sandbox runs without cgroup confinement because of
    /// [`CgroupRequirement::AllowMissing`].
    pub cgroup_opt_out_reason: Option<String>,
    pub limits: Option<ResourceLimits>,
    pub workspace: Option<String>,
    pub workspace_read_only: bool,
    pub broker_fd: i32,
    /// Compatibility-mode model route, if any (an unmediated baseline
    /// channel; see `docs/compat.md`).
    pub model_route: Option<ModelRoute>,
    pub confinement: ConfinementStatus,
}

/// The trusted launcher.
#[derive(Debug)]
pub struct Launcher {
    config: LauncherConfig,
    report: FeatureReport,
}

fn normalized_abs(p: &Path) -> bool {
    p.is_absolute()
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .and_then(|p| fs::canonicalize(p).ok())
}

/// Rejects host paths that would expose protected host state.
fn check_host_exposure(what: &str, canon: &Path) -> Result<(), LaunchError> {
    let bad = |m: String| {
        Err(LaunchError::InvalidProfile(format!(
            "{what} {}: {m}",
            canon.display()
        )))
    };
    if canon == Path::new("/") {
        return bad("refusing to expose the host root".into());
    }
    let mut protected: Vec<PathBuf> = PROTECTED_HOST_PATHS.iter().map(PathBuf::from).collect();
    if let Some(h) = home_dir() {
        protected.push(h);
    }
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        protected.push(PathBuf::from(rt));
    }
    for p in &protected {
        if p.starts_with(canon) {
            return bad(format!("would expose protected location {}", p.display()));
        }
    }
    for t in FORBIDDEN_HOST_TREES {
        if canon.starts_with(t) {
            return bad(format!("lies inside forbidden tree {t}"));
        }
    }
    Ok(())
}

fn credential_agent_component(p: &Path) -> Option<String> {
    p.components().find_map(|c| match c {
        Component::Normal(n) => {
            let n = n.to_string_lossy().to_lowercase();
            n.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| CREDENTIAL_AGENT_WORDS.contains(&w))
                .then_some(n)
        }
        _ => None,
    })
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .and_then(|p| fs::canonicalize(p).ok())
}

/// Validate [`LauncherConfig::model_socket_dir`] and return it canonical.
fn check_model_socket_dir(dir: &Path) -> Result<PathBuf, LaunchError> {
    use std::os::unix::fs::MetadataExt;
    let invalid = |m: String| Err(LaunchError::InvalidProfile(format!("model_socket_dir {m}")));
    let canon = fs::canonicalize(dir).map_err(|e| {
        LaunchError::InvalidProfile(format!("model_socket_dir {}: {e}", dir.display()))
    })?;
    let md = fs::metadata(&canon)?;
    let uid = rustix::process::getuid().as_raw();
    if !md.is_dir() || md.uid() != uid || md.mode() & 0o777 != 0o700 {
        return invalid(format!(
            "{} must be a directory owned by uid {uid} with mode 0700",
            canon.display()
        ));
    }
    for (var, p) in [
        ("XDG_RUNTIME_DIR", env_dir("XDG_RUNTIME_DIR")),
        ("HOME", home_dir()),
    ] {
        if let Some(p) = p
            && p.starts_with(&canon)
        {
            return invalid(format!(
                "{} is ${var} or contains it; use a dedicated directory",
                canon.display()
            ));
        }
    }
    if let Some(c) = credential_agent_component(&canon) {
        return invalid(format!(
            "{} has a credential-agent path component {c:?}",
            canon.display()
        ));
    }
    Ok(canon)
}

fn check_protected_paths(source: &Path, protected: &[PathBuf]) -> Result<(), LaunchError> {
    for path in protected {
        if source.starts_with(path) || path.starts_with(source) {
            return Err(LaunchError::InvalidProfile(format!(
                "mount source {} overlaps protected host path {}",
                source.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

fn sealed_memfd(name: &str, data: &[u8]) -> Result<OwnedFd, LaunchError> {
    let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
        .map_err(io::Error::from)?;
    let mut f = File::from(fd);
    f.write_all(data)?;
    f.seek(SeekFrom::Start(0))?;
    let fd = OwnedFd::from(f);
    fcntl_add_seals(
        &fd,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(io::Error::from)?;
    Ok(fd)
}

fn stdio(m: StdioMode) -> Stdio {
    match m {
        StdioMode::Null => Stdio::null(),
        StdioMode::Inherit => Stdio::inherit(),
        StdioMode::Piped => Stdio::piped(),
    }
}

/// A validated model route: canonical socket, optional (port, netshim).
struct CheckedModelRoute {
    socket: PathBuf,
    loopback: Option<(u16, PathBuf)>,
}

/// Everything needed to run one sandbox, prepared before any process exists.
struct Plan {
    bwrap_args: Vec<OsString>,
    mappings: Vec<FdMapping>,
    broker_host: OwnedFd,
    status_reader: io::PipeReader,
    workspace: Option<PathBuf>,
}

impl Launcher {
    /// Probes the host and refuses (R10) if a mandatory control is missing.
    pub fn new(config: LauncherConfig) -> Result<Self, LaunchError> {
        let report = FeatureReport::probe(&config);
        Self::with_report(config, report)
    }

    /// Builds a launcher from an existing probe report (re-validated).
    pub fn with_report(config: LauncherConfig, report: FeatureReport) -> Result<Self, LaunchError> {
        if !config.bwrap_path.is_absolute() || !config.init_path.is_absolute() {
            return Err(LaunchError::InvalidProfile(
                "bwrap_path and init_path must be absolute".into(),
            ));
        }
        if let CgroupRequirement::AllowMissing { operator_reason } = &config.cgroup
            && operator_reason.trim().is_empty()
        {
            return Err(LaunchError::InvalidProfile(
                "cgroup opt-out requires a non-empty operator_reason".into(),
            ));
        }
        let mut missing = report.missing_mandatory(&config.cgroup, config.landlock);
        if !config.init_path.is_file() {
            missing.push(crate::MissingControl {
                control: "sandbox_init".into(),
                reason: format!(
                    "init shim {} not found (it closes inherited fds and applies Landlock)",
                    config.init_path.display()
                ),
            });
        }
        if !missing.is_empty() {
            return Err(LaunchError::MissingMandatoryControl(missing));
        }
        Self::check_runtime_exposure(&config.protected_host_paths)?;
        let mut config = config;
        if let Some(dir) = &config.model_socket_dir {
            config.model_socket_dir = Some(check_model_socket_dir(dir)?);
        }
        Ok(Self { config, report })
    }

    /// Refuse paths that would be exposed by the launcher's built-in binds.
    pub fn check_runtime_exposure(paths: &[PathBuf]) -> Result<(), LaunchError> {
        if paths.is_empty() {
            return Ok(());
        }
        let runtime = runtime_args();
        for source in runtime
            .as_chunks::<3>()
            .0
            .iter()
            .filter(|arg| arg[0] == "--ro-bind")
            .map(|arg| Path::new(&arg[1]))
        {
            check_protected_paths(&fs::canonicalize(source)?, paths)?;
        }
        for source in ETC_FILES {
            match fs::canonicalize(source) {
                Ok(canon) => check_protected_paths(&canon, paths)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub fn report(&self) -> &FeatureReport {
        &self.report
    }

    /// Kill and remove every sandbox cgroup leaf in this launcher's group
    /// that this process did not create (leftovers of an earlier broker
    /// run). Call once at startup, before the first spawn, and refuse to
    /// start on error (fail closed). A no-op without cgroup delegation (no
    /// leaves can exist then). See [`crate::sweep_cgroup_group`].
    pub fn sweep_stale_cgroups(&self) -> Result<Vec<PathBuf>, LaunchError> {
        match (
            &self.report.cgroup.usable,
            &self.report.cgroup.delegation_root,
        ) {
            (true, Some(root)) => {
                crate::cgroup::sweep_group(Path::new(root), &self.config.cgroup_group_name)
            }
            _ => Ok(Vec::new()),
        }
    }

    pub fn config(&self) -> &LauncherConfig {
        &self.config
    }

    fn workload_env(profile: &LaunchProfile) -> Result<Vec<(String, String)>, LaunchError> {
        let mut env = profile.env.clone();
        for (k, v) in &env {
            let valid_key = !k.is_empty()
                && !k.as_bytes()[0].is_ascii_digit()
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !valid_key || k.starts_with("TESSERA_") || v.contains('\0') {
                return Err(LaunchError::InvalidProfile(format!(
                    "invalid or reserved environment variable {k:?}"
                )));
            }
        }
        let home = if profile.workspace.is_some() {
            SANDBOX_WORKSPACE
        } else {
            "/tmp"
        };
        for (k, v) in [
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("HOME", home),
            ("TMPDIR", "/tmp"),
            ("LANG", "C.UTF-8"),
        ] {
            env.entry(k.into()).or_insert_with(|| v.into());
        }
        env.insert(AGENT_ID_ENV.into(), profile.agent.to_string());
        env.insert(BROKER_FD_ENV.into(), BROKER_FD.to_string());
        Ok(env.into_iter().collect())
    }

    /// Validate a compatibility-mode model route as [`Launcher::spawn`]
    /// would, without launching anything (e.g. at daemon start).
    pub fn validate_model_route(&self, r: &ModelRoute) -> Result<(), LaunchError> {
        self.check_model_route(r).map(|_| ())
    }

    /// Validate a compatibility-mode model route (fail closed).
    fn check_model_route(&self, r: &ModelRoute) -> Result<CheckedModelRoute, LaunchError> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let invalid = |m: String| LaunchError::InvalidProfile(m);
        let Some(dir) = &self.config.model_socket_dir else {
            return Err(invalid(
                "model routes require LauncherConfig.model_socket_dir".into(),
            ));
        };
        // SSH_AUTH_SOCK is compared before and after resolving symlinks.
        let ssh_agent = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        if ssh_agent.as_ref().is_some_and(|p| *p == r.host_socket) {
            return Err(invalid("model socket is the SSH agent socket".into()));
        }
        let socket = fs::canonicalize(&r.host_socket)
            .map_err(|e| invalid(format!("model socket {}: {e}", r.host_socket.display())))?;
        // Only sockets in the operator's dedicated directory: never a host
        // agent socket such as the GnuPG or SSH agent in $XDG_RUNTIME_DIR.
        if !socket.starts_with(dir) || socket == *dir {
            return Err(invalid(format!(
                "model socket {} is outside model_socket_dir {}",
                socket.display(),
                dir.display()
            )));
        }
        if let Some(c) = credential_agent_component(&socket) {
            return Err(invalid(format!(
                "model socket {} has a credential-agent path component {c:?}",
                socket.display()
            )));
        }
        let md = fs::symlink_metadata(&socket)?;
        let uid = rustix::process::getuid().as_raw();
        // Only a private socket owned by the launcher's user (the model
        // proxy creates it 0600) may be exposed; this rules out host
        // service sockets such as the Docker or D-Bus sockets.
        if !md.file_type().is_socket() || md.uid() != uid || md.mode() & 0o077 != 0 {
            return Err(invalid(format!(
                "model socket {} must be a socket owned by uid {uid} with mode 0600",
                socket.display()
            )));
        }
        // Never the broker's admin socket or anything else protected.
        check_protected_paths(&socket, &self.config.protected_host_paths)?;
        if ssh_agent
            .and_then(|p| fs::canonicalize(p).ok())
            .is_some_and(|p| p == socket)
        {
            return Err(invalid("model socket is the SSH agent socket".into()));
        }
        let loopback = match &r.loopback {
            None => None,
            Some(l) => {
                if l.port == 0 {
                    return Err(invalid("model loopback port must be non-zero".into()));
                }
                // The port exception must be expressible and enforced: only
                // a fully enforced Landlock ruleset restricts TCP to it.
                if self.config.landlock != LandlockRequirement::Required {
                    return Err(invalid(
                        "a model loopback port requires LandlockRequirement::Required".into(),
                    ));
                }
                let shim = fs::canonicalize(&l.netshim_path)
                    .map_err(|e| invalid(format!("netshim {}: {e}", l.netshim_path.display())))?;
                if !shim.is_file() {
                    return Err(invalid(format!("netshim {} is not a file", shim.display())));
                }
                check_host_exposure("netshim", &shim)?;
                check_protected_paths(&shim, &self.config.protected_host_paths)?;
                Some((l.port, shim))
            }
        };
        Ok(CheckedModelRoute { socket, loopback })
    }

    fn plan(&self, profile: &LaunchProfile) -> Result<Plan, LaunchError> {
        let invalid = |m: String| LaunchError::InvalidProfile(m);
        if !normalized_abs(&profile.program) {
            return Err(invalid(format!(
                "program {} must be an absolute, normalized sandbox path",
                profile.program.display()
            )));
        }
        let mut env = Self::workload_env(profile)?;
        let model = match &profile.model_route {
            Some(r) => Some(self.check_model_route(r)?),
            None => None,
        };
        if let Some(m) = &model {
            env.push((MODEL_SOCKET_ENV.into(), SANDBOX_MODEL_SOCKET.into()));
            if let Some((port, _)) = &m.loopback {
                env.push((MODEL_PORT_ENV.into(), port.to_string()));
            }
        }

        let workspace = match &profile.workspace {
            Some(ws) => {
                let canon = fs::canonicalize(ws)
                    .map_err(|e| invalid(format!("workspace {}: {e}", ws.display())))?;
                if !canon.is_dir() {
                    return Err(invalid(format!(
                        "workspace {} is not a directory",
                        canon.display()
                    )));
                }
                check_host_exposure("workspace", &canon)?;
                check_protected_paths(&canon, &self.config.protected_host_paths)?;
                Some(canon)
            }
            None => None,
        };
        let mut extra = Vec::new();
        for b in &profile.extra_ro_binds {
            let canon = fs::canonicalize(&b.host)
                .map_err(|e| invalid(format!("bind source {}: {e}", b.host.display())))?;
            check_host_exposure("bind source", &canon)?;
            check_protected_paths(&canon, &self.config.protected_host_paths)?;
            if !normalized_abs(&b.sandbox) || b.sandbox == Path::new("/") {
                return Err(invalid(format!(
                    "bind target {} invalid",
                    b.sandbox.display()
                )));
            }
            for r in RESERVED_SANDBOX_PATHS {
                if b.sandbox.starts_with(r) || Path::new(r).starts_with(&b.sandbox) {
                    return Err(invalid(format!(
                        "bind target {} collides with reserved {r}",
                        b.sandbox.display()
                    )));
                }
            }
            extra.push((canon, b.sandbox.clone()));
        }

        // Broker channel: one fresh SOCK_SEQPACKET pair per sandbox.
        let (broker_host, broker_sandbox) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from)?;
        let (status_reader, status_writer) = io::pipe()?;

        let mut mappings = vec![
            FdMapping {
                parent_fd: broker_sandbox,
                child_fd: BROKER_FD,
            },
            FdMapping {
                parent_fd: status_writer.into(),
                child_fd: STATUS_FD,
            },
        ];
        let mut a: Vec<OsString> = Vec::new();
        let mut push = |xs: &[&str]| a.extend(xs.iter().map(OsString::from));
        push(&[
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
            "--hostname",
            "tessera",
            "--clearenv",
        ]);
        for (k, v) in &env {
            a.extend(["--setenv".into(), k.into(), v.into()]);
        }
        a.extend(runtime_args());
        a.extend(["--dir".into(), "/etc".into()]);
        for f in ETC_FILES {
            a.extend(["--ro-bind-try".into(), (*f).into(), (*f).into()]);
        }
        // Synthetic identity files: no host account names leak in.
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let home = if workspace.is_some() {
            SANDBOX_WORKSPACE
        } else {
            "/tmp"
        };
        let data: [(&str, String); 4] = [
            (
                "/etc/passwd",
                format!("agent:x:{uid}:{gid}:Tessera agent:{home}:/bin/sh\n"),
            ),
            ("/etc/group", format!("agent:x:{gid}:\n")),
            ("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n".into()),
            (
                "/etc/nsswitch.conf",
                "passwd: files\ngroup: files\nhosts: files\n".into(),
            ),
        ];
        for (i, (dest, content)) in data.iter().enumerate() {
            let fd_no = FIRST_DATA_FD + i as i32;
            mappings.push(FdMapping {
                parent_fd: sealed_memfd("tessera-etc", content.as_bytes())?,
                child_fd: fd_no,
            });
            a.extend([
                "--ro-bind-data".into(),
                fd_no.to_string().into(),
                (*dest).into(),
            ]);
        }
        a.extend([
            "--proc".into(),
            "/proc".into(),
            "--dev".into(),
            "/dev".into(),
            "--tmpfs".into(),
            "/dev/shm".into(),
            "--tmpfs".into(),
            "/tmp".into(),
        ]);
        if let Some(ws) = &workspace {
            let flag = if profile.workspace_read_only {
                "--ro-bind"
            } else {
                "--bind"
            };
            a.extend([flag.into(), ws.clone().into(), SANDBOX_WORKSPACE.into()]);
            a.extend(["--chdir".into(), SANDBOX_WORKSPACE.into()]);
        } else {
            a.extend(["--chdir".into(), "/tmp".into()]);
        }
        for (host, dest) in &extra {
            a.extend(["--ro-bind".into(), host.clone().into(), dest.clone().into()]);
        }
        if let Some(m) = &model {
            // A Unix socket on a read-only bind can still be connected to.
            a.extend([
                "--ro-bind".into(),
                m.socket.clone().into(),
                SANDBOX_MODEL_SOCKET.into(),
            ]);
            if let Some((_, shim)) = &m.loopback {
                a.extend([
                    "--ro-bind".into(),
                    shim.clone().into(),
                    SANDBOX_NETSHIM_PATH.into(),
                ]);
            }
        }
        a.extend([
            "--ro-bind".into(),
            self.config.init_path.clone().into(),
            SANDBOX_INIT_PATH.into(),
        ]);
        for (i, prog) in seccomp::all_filters()?.iter().enumerate() {
            let fd_no = FIRST_SECCOMP_FD + i as i32;
            if fd_no >= FIRST_DATA_FD {
                return Err(LaunchError::Seccomp("too many filters".into()));
            }
            mappings.push(FdMapping {
                parent_fd: sealed_memfd("tessera-seccomp", &seccomp::to_bytes(prog))?,
                child_fd: fd_no,
            });
            a.extend(["--add-seccomp-fd".into(), fd_no.to_string().into()]);
        }
        a.extend(["--remount-ro".into(), "/".into()]);

        // Init shim command line.
        let landlock = match self.config.landlock {
            LandlockRequirement::Required => "required",
            LandlockRequirement::BestEffort => "best_effort",
            LandlockRequirement::Disabled => "disabled",
        };
        a.extend(["--".into(), SANDBOX_INIT_PATH.into()]);
        a.extend([
            "--status-fd".into(),
            STATUS_FD.to_string().into(),
            "--keep-fd".into(),
            BROKER_FD.to_string().into(),
            "--landlock".into(),
            landlock.into(),
        ]);
        let loopback = model.as_ref().and_then(|m| m.loopback.as_ref());
        if let Some((port, _)) = loopback {
            a.extend(["--allow-tcp-port".into(), port.to_string().into()]);
        }
        let mut ro: Vec<OsString> = vec!["/usr".into(), "/etc".into(), "/proc".into()];
        ro.extend(
            RUNTIME_TOP_LEVEL
                .iter()
                .map(|n| OsString::from(format!("/{n}"))),
        );
        ro.extend(extra.iter().map(|(_, d)| d.clone().into()));
        if loopback.is_some() {
            ro.push(SANDBOX_NETSHIM_PATH.into());
        }
        let mut rw: Vec<OsString> = vec!["/tmp".into(), "/dev/shm".into()];
        if workspace.is_some() {
            if profile.workspace_read_only {
                ro.push(SANDBOX_WORKSPACE.into());
            } else {
                rw.push(SANDBOX_WORKSPACE.into());
            }
        }
        for p in ro {
            a.extend(["--ro".into(), p]);
        }
        for p in rw {
            a.extend(["--rw".into(), p]);
        }
        a.extend(["--dev".into(), "/dev".into()]);
        a.push("--".into());
        if let Some((port, _)) = loopback {
            // The shim binds the port, then runs the workload as its child.
            a.extend([
                SANDBOX_NETSHIM_PATH.into(),
                "--listen".into(),
                format!("127.0.0.1:{port}").into(),
                "--socket".into(),
                SANDBOX_MODEL_SOCKET.into(),
                "--".into(),
            ]);
        }
        a.push(profile.program.clone().into());
        a.extend(profile.args.iter().cloned());

        Ok(Plan {
            bwrap_args: a,
            mappings,
            broker_host,
            status_reader,
            workspace,
        })
    }

    /// Returns the bubblewrap argument vector that would be used for
    /// `profile` (for inspection, auditing and tests). Descriptor numbers
    /// refer to the launcher's fd mapping.
    pub fn bwrap_args(&self, profile: &LaunchProfile) -> Result<Vec<OsString>, LaunchError> {
        Ok(self.plan(profile)?.bwrap_args)
    }

    /// Launches a sandbox. Returns only after the in-sandbox init shim has
    /// confirmed that seccomp, no_new_privs, an empty capability set and the
    /// required Landlock ruleset are active and that only fds 0-2 and the
    /// broker channel remain; otherwise the process tree is killed and an
    /// error returned.
    ///
    /// Note: bubblewrap runs with `--die-with-parent`, i.e. `PR_SET_PDEATHSIG`
    /// bound to the *thread* that calls `spawn`. Call it from a thread that
    /// outlives the sandbox.
    pub fn spawn(&self, profile: &LaunchProfile) -> Result<SandboxHandle, LaunchError> {
        let plan = self.plan(profile)?;
        let mut opt_out_reason = None;
        let cgroup = if self.report.cgroup.usable {
            let root = self
                .report
                .cgroup
                .delegation_root
                .as_deref()
                .unwrap_or_default();
            Some(CgroupLeaf::create(
                Path::new(root),
                &self.config.cgroup_group_name,
                &profile.agent,
                &profile.limits,
            )?)
        } else {
            match &self.config.cgroup {
                CgroupRequirement::AllowMissing { operator_reason } => {
                    eprintln!(
                        "tessera-launcher: WARNING: launching {} WITHOUT cgroup v2 confinement \
                         (no resource limits; tree kill via PID-namespace teardown only). \
                         Operator opt-out reason: {operator_reason}",
                        profile.agent
                    );
                    opt_out_reason = Some(operator_reason.clone());
                    None
                }
                CgroupRequirement::Required => {
                    return Err(LaunchError::MissingMandatoryControl(vec![
                        crate::MissingControl {
                            control: "cgroup_v2_delegation".into(),
                            reason: "cgroup delegation unavailable".into(),
                        },
                    ]));
                }
            }
        };

        let mut cmd = match &cgroup {
            Some(leaf) => {
                // Enter the leaf before exec'ing bwrap so no sandbox process
                // is ever born outside it.
                let mut c = Command::new("/bin/sh");
                c.arg("-c")
                    .arg("echo 0 > \"$0\" || exit 125; exec \"$@\"")
                    .arg(leaf.procs_path())
                    .arg(&self.config.bwrap_path);
                c
            }
            None => Command::new(&self.config.bwrap_path),
        };
        cmd.args(&plan.bwrap_args)
            .env_clear()
            // Avoid leaking the launcher's cwd (e.g. via PWD of the sh
            // trampoline into bwrap's environment).
            .current_dir("/")
            .stdin(stdio(profile.stdin))
            .stdout(stdio(profile.stdout))
            .stderr(stdio(profile.stderr));
        cmd.fd_mappings(plan.mappings)
            .map_err(|e| LaunchError::InvalidProfile(e.to_string()))?;
        let spawned = cmd.spawn();
        // Dropping the command closes the launcher's copies of the sandbox
        // ends (broker socket, status pipe writer, memfds).
        drop(cmd);
        let child = spawned?;
        let pid = child.id();
        let pidfd = Pid::from_raw(pid as i32)
            .ok_or_else(|| io::Error::other("invalid pid"))
            .and_then(|p| pidfd_open(p, PidfdFlags::empty()).map_err(io::Error::from));

        let mut handle = SandboxHandle {
            agent: profile.agent.clone(),
            pid,
            pidfd: pidfd.ok(),
            child: Some(child),
            broker: Some(plan.broker_host),
            cgroup,
            record: LaunchRecord {
                agent: profile.agent.clone(),
                launched_at_unix_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0),
                outer_pid: pid,
                kernel_release: self.report.kernel_release.clone(),
                bwrap_version: self.report.bwrap.version.clone(),
                namespaces: vec!["user", "mnt", "pid", "ipc", "net", "uts", "cgroup"],
                seccomp_denied_syscalls: seccomp::denied_syscalls()
                    .into_iter()
                    .map(|(n, _)| n)
                    .collect(),
                seccomp_filters: seccomp::all_filters()?.len(),
                landlock_requirement: self.config.landlock,
                cgroup_requirement: self.config.cgroup.clone(),
                cgroup: None,
                cgroup_opt_out_reason: opt_out_reason,
                limits: None,
                workspace: plan.workspace.as_ref().map(|p| p.display().to_string()),
                workspace_read_only: profile.workspace_read_only,
                broker_fd: BROKER_FD,
                model_route: profile.model_route.clone(),
                confinement: ConfinementStatus::default(),
            },
            finished: false,
        };
        if let Some(leaf) = &handle.cgroup {
            handle.record.cgroup = Some(leaf.path().display().to_string());
            handle.record.limits = Some(profile.limits.clone());
        }
        if handle.pidfd.is_none() {
            let _ = handle.stop();
            return Err(LaunchError::ConfinementNotConfirmed(
                "pidfd_open failed".into(),
            ));
        }

        match read_status(plan.status_reader, CONFIRM_TIMEOUT) {
            Ok(line) => {
                let st = ConfinementStatus::parse(&line);
                let landlock_ok = match self.config.landlock {
                    LandlockRequirement::Required => st.landlock == "full",
                    _ => true,
                };
                let fds_ok = st.open_fds == [0, 1, 2, BROKER_FD];
                if st.seccomp_mode != "2" || !st.no_new_privs || !landlock_ok || !fds_ok {
                    let _ = handle.stop();
                    return Err(LaunchError::ConfinementNotConfirmed(format!(
                        "unexpected status {line:?}"
                    )));
                }
                handle.record.confinement = st;
                Ok(handle)
            }
            Err(msg) => {
                let status = handle.stop().ok();
                Err(LaunchError::ConfinementNotConfirmed(format!(
                    "{msg} (sandbox exit status: {status:?})"
                )))
            }
        }
    }
}

fn read_status(reader: io::PipeReader, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = BufReader::new(reader);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out waiting for init shim".into());
        }
        let ts = rustix::time::Timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(buf.get_ref(), PollFlags::IN)];
        match poll(&mut fds, Some(&ts)) {
            Ok(0) => continue,
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(format!("poll status pipe: {e}")),
        }
    }
    let mut line = String::new();
    buf.read_line(&mut line).map_err(|e| e.to_string())?;
    let line = line.trim_end();
    if let Some(ok) = line.strip_prefix("ok ") {
        Ok(ok.to_string())
    } else if let Some(err) = line.strip_prefix("err ") {
        Err(format!("init shim refused: {err}"))
    } else if line.is_empty() {
        Err("sandbox exited before confirming confinement".into())
    } else {
        Err(format!("malformed status line {line:?}"))
    }
}

/// A running sandbox principal.
///
/// Dropping the handle stops the sandbox (kills the whole process tree).
#[derive(Debug)]
pub struct SandboxHandle {
    agent: AgentLabel,
    pid: u32,
    pidfd: Option<OwnedFd>,
    child: Option<Child>,
    broker: Option<OwnedFd>,
    cgroup: Option<CgroupLeaf>,
    record: LaunchRecord,
    finished: bool,
}

impl SandboxHandle {
    pub fn agent(&self) -> &AgentLabel {
        &self.agent
    }

    /// Host PID of the outermost sandbox process (bubblewrap). Prefer
    /// [`SandboxHandle::pidfd`] for anything identity-sensitive.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// pidfd of the outermost sandbox process (stable against PID reuse).
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(|f| f.as_fd())
    }

    /// Host end of the broker channel (`AF_UNIX`, `SOCK_SEQPACKET`).
    pub fn broker_channel(&self) -> Option<BorrowedFd<'_>> {
        self.broker.as_ref().map(|f| f.as_fd())
    }

    /// Takes ownership of the host end of the broker channel.
    pub fn take_broker_channel(&mut self) -> Option<OwnedFd> {
        self.broker.take()
    }

    pub fn cgroup(&self) -> Option<&CgroupLeaf> {
        self.cgroup.as_ref()
    }

    pub fn record(&self) -> &LaunchRecord {
        &self.record
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    fn cleanup(&mut self) {
        self.finished = true;
        if let Some(mut leaf) = self.cgroup.take() {
            let _ = leaf.destroy();
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("already reaped"));
        };
        let r = child.try_wait()?;
        if r.is_some() {
            self.cleanup();
        }
        Ok(r)
    }

    /// Waits for the sandbox to exit, then removes its cgroup.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let Some(child) = self.child.as_mut() else {
            return Err(io::Error::other("already reaped"));
        };
        let st = child.wait()?;
        self.cleanup();
        Ok(st)
    }

    /// Waits up to `timeout`; on expiry the sandbox is stopped and `None`
    /// returned.
    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(st) = self.try_wait()? {
                return Ok(Some(st));
            }
            if Instant::now() >= deadline {
                self.stop()?;
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Collects piped stdout/stderr and waits for exit.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("already reaped"))?;
        let out = child.wait_with_output()?;
        self.cleanup();
        Ok(out)
    }

    /// Kills the entire sandbox process tree and reaps it.
    ///
    /// With a cgroup leaf, `cgroup.kill` SIGKILLs every member atomically
    /// (including processes that escaped the session or daemonised). Without
    /// one (operator opt-out), the PID namespace's init (the outer
    /// bubblewrap's child) and the outer bubblewrap process are SIGKILLed via
    /// pidfds, and this returns only after the namespace init has *exited*:
    /// the kernel kills and reaps every other process of the namespace
    /// before its init's exit completes, so nothing of the sandbox runs
    /// afterwards. (Relying on `--die-with-parent` alone is asynchronous:
    /// the outer process could be reaped while the namespace still ran.)
    pub fn stop(&mut self) -> io::Result<ExitStatus> {
        if let Some(leaf) = &self.cgroup {
            let _ = leaf.kill();
        }
        // Pin the namespace init(s) before the outer process dies.
        let inits = if self.finished {
            Vec::new()
        } else {
            namespace_inits(self.pid)
        };
        for fd in &inits {
            let _ = pidfd_send_signal(fd, Signal::KILL);
        }
        if !self.finished
            && let Some(pidfd) = &self.pidfd
        {
            // ESRCH (already exited, not yet reaped) is fine.
            let _ = pidfd_send_signal(pidfd, Signal::KILL);
        }
        self.broker = None;
        let st = match self.child.as_mut() {
            Some(c) => c.wait()?,
            None => return Err(io::Error::other("already reaped")),
        };
        for fd in &inits {
            wait_pidfd_exit(fd, Duration::from_secs(10))?;
        }
        self.cleanup();
        Ok(st)
    }
}

/// pidfds of the current children of `pid` (bubblewrap's PID-namespace
/// init). Each is checked, after `pidfd_open`, to still be a child of `pid`,
/// so a recycled pid is never signalled.
fn namespace_inits(pid: u32) -> Vec<OwnedFd> {
    let list = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap_or_default();
    list.split_whitespace()
        .filter_map(|c| c.parse::<i32>().ok())
        .filter_map(|c| {
            let fd = pidfd_open(Pid::from_raw(c)?, PidfdFlags::empty()).ok()?;
            let stat = fs::read_to_string(format!("/proc/{c}/stat")).ok()?;
            // Field 4 (ppid) follows the parenthesised command name.
            let ppid: u32 = stat
                .rsplit_once(')')?
                .1
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            (ppid == pid).then_some(fd)
        })
        .collect()
}

/// Wait until the process behind `fd` has exited (pidfd becomes readable).
fn wait_pidfd_exit(fd: &OwnedFd, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "sandbox PID namespace did not terminate",
            ));
        }
        let ts = rustix::time::Timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        match poll(&mut fds, Some(&ts)) {
            Ok(0) => continue,
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

impl Drop for SandboxHandle {
    fn drop(&mut self) {
        if self.child.is_some() && !self.finished {
            let _ = self.stop();
        } else {
            self.cleanup();
        }
    }
}
