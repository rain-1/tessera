//! Integration tests that launch real sandboxes.
//!
//! Every test calls [`launcher`], which probes the host; if a mandatory control
//! is missing the test prints a loud `SKIPPED` banner and returns instead of
//! silently passing a weaker profile.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use tessera_launcher::{
    AgentLabel, CgroupRequirement, FeatureReport, LaunchError, LaunchProfile, Launcher,
    LauncherConfig, ResourceLimits, StdioMode,
};

const INIT: &str = env!("CARGO_BIN_EXE_tessera-sandbox-init");
const RUN: &str = env!("CARGO_BIN_EXE_tessera-launch-run");

fn probes_dir() -> PathBuf {
    fs::canonicalize(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/adversarial/probes"
    ))
    .expect("probe corpus")
}

fn config() -> LauncherConfig {
    LauncherConfig {
        init_path: INIT.into(),
        ..LauncherConfig::default()
    }
}

fn launcher_with(cfg: LauncherConfig) -> Option<Launcher> {
    match Launcher::new(cfg) {
        Ok(l) => Some(l),
        Err(LaunchError::MissingMandatoryControl(m)) => {
            eprintln!(
                "\n!!!!!!!! SKIPPED: mandatory sandbox control missing on this host: {m:?} !!!!!!!!\n"
            );
            None
        }
        Err(e) => panic!("launcher construction failed: {e}"),
    }
}

fn launcher() -> Option<Launcher> {
    launcher_with(config())
}

struct Ctx {
    ws: tempfile::TempDir,
}

fn ctx() -> Ctx {
    Ctx {
        ws: tempfile::tempdir().unwrap(),
    }
}

fn profile(c: &Ctx, label: &str, program: &str) -> LaunchProfile {
    LaunchProfile::new(AgentLabel::new(label).unwrap(), program)
        .workspace(c.ws.path())
        .ro_bind(probes_dir(), "/probes")
        .stdio(StdioMode::Null, StdioMode::Piped, StdioMode::Piped)
}

fn run(l: &Launcher, p: &LaunchProfile) -> Output {
    let h = l.spawn(p).unwrap_or_else(|e| panic!("spawn failed: {e}"));
    h.wait_with_output().unwrap()
}

fn show(o: &Output) -> String {
    format!(
        "status={:?}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn assert_contained(o: &Output) {
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success() && !out.contains("BREACH") && out.contains("RESULT: contained"),
        "{}",
        show(o)
    );
}

/// Canary in a directory under $HOME (never bound).
struct HomeCanary {
    dir: PathBuf,
    file: PathBuf,
    secret: String,
}
impl HomeCanary {
    fn new() -> Self {
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        let dir = tempfile::Builder::new()
            .prefix(".tessera-test-canary.")
            .tempdir_in(&home)
            .unwrap()
            .keep();
        let secret = format!(
            "tessera-canary-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        );
        let file = dir.join("secret");
        fs::write(&file, &secret).unwrap();
        Self { dir, file, secret }
    }
}
impl Drop for HomeCanary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn launch_record_confirms_confinement() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "record", "/bin/true");
    let mut h = l.spawn(&p).unwrap();
    let rec = h.record().clone();
    assert!(h.wait().unwrap().success());
    assert_eq!(rec.confinement.seccomp_mode, "2");
    assert!(rec.confinement.no_new_privs);
    assert_eq!(rec.confinement.cap_eff, "0000000000000000");
    assert_eq!(rec.confinement.landlock, "full");
    assert_eq!(rec.confinement.open_fds, vec![0, 1, 2, 3]);
    assert_eq!(rec.broker_fd, 3);
    assert!(
        rec.cgroup.is_some(),
        "delegation available, cgroup must be used"
    );
    assert!(rec.cgroup_opt_out_reason.is_none());
    assert_eq!(rec.agent.as_str(), "record");
    // cgroup leaf removed after exit
    assert!(!Path::new(rec.cgroup.as_ref().unwrap()).exists());
}

#[test]
fn cannot_read_canaries_outside_workspace() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let home = HomeCanary::new();
    let unbound = tempfile::tempdir().unwrap();
    let tmp_canary = unbound.path().join("secret");
    fs::write(&tmp_canary, &home.secret).unwrap();
    let p = profile(&c, "fsread", "/bin/sh")
        .arg("/probes/fs_read.sh")
        .env("CANARY_HOME", home.file.to_str().unwrap())
        .env("CANARY_TMP", tmp_canary.to_str().unwrap())
        .env("CANARY_SECRET", &home.secret);
    assert_contained(&run(&l, &p));

    // Direct check as well: the exact paths do not resolve.
    let p = profile(&c, "fsread2", "/bin/cat")
        .arg(home.file.as_os_str())
        .arg(tmp_canary.as_os_str());
    let o = run(&l, &p);
    assert!(!o.status.success(), "{}", show(&o));
    assert!(!String::from_utf8_lossy(&o.stdout).contains(&home.secret));
}

#[test]
fn cannot_write_outside_workspace() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "fswrite", "/bin/sh").arg("/probes/fs_write.sh");
    assert_contained(&run(&l, &p));
    // A file written to the workspace is visible on the host; /tmp is private.
    let p = profile(&c, "fswrite2", "/bin/sh")
        .arg("-c")
        .arg("echo inside > /workspace/out && echo private > /tmp/private-tessera-test");
    let o = run(&l, &p);
    assert!(o.status.success(), "{}", show(&o));
    assert_eq!(
        fs::read_to_string(c.ws.path().join("out")).unwrap(),
        "inside\n"
    );
    assert!(!Path::new("/tmp/private-tessera-test").exists());
}

#[test]
fn read_only_workspace() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let mut p = profile(&c, "rows", "/bin/sh")
        .arg("-c")
        .arg("echo x > /workspace/f");
    p.workspace_read_only = true;
    let o = run(&l, &p);
    assert!(!o.status.success(), "{}", show(&o));
    assert!(!c.ws.path().join("f").exists());
}

#[test]
fn no_network_and_no_host_sockets() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let sockdir = tempfile::tempdir().unwrap();
    let path = sockdir.path().join("host.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let name = format!("tessera-test-{}", std::process::id());
    let _abstract =
        UnixListener::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
    let p = profile(&c, "net", "/bin/sh")
        .arg("/probes/net.sh")
        .env("HOST_SOCKET", path.to_str().unwrap())
        .env("HOST_ABSTRACT", &name)
        .env("EXPECT_LANDLOCK", "required");
    let o = run(&l, &p);
    assert_contained(&o);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("ok: tcp 1.1.1.1:53 blocked"), "{out}");
    assert!(out.contains("ok: tcp bind denied by Landlock"), "{out}");
}

#[test]
fn host_pids_invisible() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "pids", "/bin/sh")
        .arg("/probes/pids.sh")
        .env("HOST_PID", std::process::id().to_string());
    assert_contained(&run(&l, &p));
}

#[test]
fn dangerous_syscalls_denied() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "syscalls", "/bin/sh").arg("/probes/escape.sh");
    let o = run(&l, &p);
    assert_contained(&o);
    let out = String::from_utf8_lossy(&o.stdout);
    for s in [
        "ptrace(TRACEME)",
        "io_uring_setup",
        "bpf ",
        "clone3",
        "clone(CLONE_NEWUSER",
    ] {
        assert!(
            out.lines()
                .any(|line| line.starts_with("ok: ") && line.contains(s)),
            "{s}: {out}"
        );
    }
}

#[test]
fn environment_is_explicit() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "env", "/bin/sh").arg("/probes/env.sh");
    assert_contained(&run(&l, &p));
    let p = profile(&c, "env2", "/usr/bin/env").env("CUSTOM", "1");
    let o = run(&l, &p);
    let mut keys: Vec<String> = String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "CUSTOM",
            "HOME",
            "LANG",
            "PATH",
            "PWD",
            "TESSERA_AGENT_ID",
            "TESSERA_BROKER_FD",
            "TMPDIR"
        ]
    );
}

/// Exercises the full path with a hostile *parent*: leaked non-CLOEXEC fds and
/// credential variables in the launcher's own environment.
#[test]
fn inherited_fds_and_host_env_do_not_leak() {
    if launcher().is_none() {
        return;
    }
    let c = ctx();
    let home = HomeCanary::new();
    let script = format!(
        "exec 7<'{}' 8<>/dev/null 9</etc/hostname; exec \"$@\"",
        home.file.display()
    );
    let o = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg("sh")
        .arg(RUN)
        .args([
            "--init",
            INIT,
            "--broker-echo",
            "--agent",
            "leaky-parent",
            "--workspace",
        ])
        .arg(c.ws.path())
        .arg("--ro-bind")
        .arg(format!("{}:/probes", probes_dir().display()))
        .args(["--env", "EXPECT_BROKER_ECHO=1", "--", "/bin/sh", "-c"])
        .arg("sh /probes/fds.sh && sh /probes/env.sh && ls -l /proc/self/fd")
        .env("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent")
        .env("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
        .env("AWS_SECRET_ACCESS_KEY", "nope")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", show(&o));
    assert!(!out.contains("BREACH"), "{out}");
    assert!(out.contains("ok: broker channel round trip"), "{out}");
    assert!(out.contains("ok: open fds: [0, 1, 2, 3]"), "{out}");
    assert!(!out.contains(&home.secret));
}

#[test]
fn broker_channel_round_trip() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "broker", "/usr/bin/python3").args([
        "-I",
        "-c",
        "import os; fd=int(os.environ['TESSERA_BROKER_FD']); os.write(fd, b'hello broker'); \
         print(os.read(fd, 100).decode()); os.write(fd, b'second message')",
    ]);
    let mut h = l.spawn(&p).unwrap();
    let mut chan = File::from(h.take_broker_channel().unwrap());
    let mut buf = [0u8; 256];
    let n = chan.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello broker");
    chan.write_all(b"pong from host").unwrap();
    // SOCK_SEQPACKET preserves message boundaries.
    let n = chan.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"second message");
    let o = h.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", show(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "pong from host");
    // Sandbox gone => EOF on the host end.
    assert_eq!(chan.read(&mut buf).unwrap(), 0);
}

#[test]
fn sandboxes_get_distinct_channels() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let mk = |label: &str| {
        profile(&c, label, "/usr/bin/python3").args([
            "-I",
            "-c",
            "import os; os.write(3, os.environ['TESSERA_AGENT_ID'].encode())",
        ])
    };
    let mut a = l.spawn(&mk("agent-a")).unwrap();
    let mut b = l.spawn(&mk("agent-b")).unwrap();
    let mut buf = [0u8; 64];
    let mut ca = File::from(a.take_broker_channel().unwrap());
    let mut cb = File::from(b.take_broker_channel().unwrap());
    let n = ca.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"agent-a");
    let n = cb.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"agent-b");
    assert_ne!(a.record().cgroup, b.record().cgroup);
    a.wait().unwrap();
    b.wait().unwrap();
}

fn tick_stops_after_stop(l: &Launcher, c: &Ctx, label: &str) {
    let p = profile(c, label, "/bin/sh").arg("-c").arg(
        "(setsid sh -c 'while :; do date +%s%N > /workspace/tick; sleep 0.02; done' &) ; \
         (while :; do sleep 0.02; done &) ; exec sleep 1000",
    );
    let p = p.stdio(StdioMode::Null, StdioMode::Null, StdioMode::Null);
    let mut h = l.spawn(&p).unwrap();
    let tick = c.ws.path().join("tick");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !tick.exists() {
        assert!(Instant::now() < deadline, "workload never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let cg = h.record().cgroup.clone();
    h.stop().unwrap();
    let before = fs::read_to_string(&tick).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(400));
    let after = fs::read_to_string(&tick).unwrap_or_default();
    assert_eq!(before, after, "a detached descendant survived stop()");
    if let Some(cg) = cg {
        assert!(!Path::new(&cg).exists(), "cgroup leaf not removed");
    }
}

#[test]
fn stop_kills_whole_tree_via_cgroup() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    tick_stops_after_stop(&l, &c, "stop-cg");
}

#[test]
fn stop_kills_whole_tree_without_cgroup_under_opt_out() {
    let Some(probe_l) = launcher() else { return };
    // Simulate a host without delegation, with an explicit operator opt-out.
    let mut report: FeatureReport = probe_l.report().clone();
    report.cgroup.usable = false;
    report.cgroup.reason = Some("simulated: no delegation".into());
    let cfg = LauncherConfig {
        cgroup: CgroupRequirement::AllowMissing {
            operator_reason: "integration test: PID-namespace teardown path".into(),
        },
        ..config()
    };
    let l = Launcher::with_report(cfg, report).unwrap();
    let c = ctx();
    let p = profile(&c, "optout", "/bin/true");
    let mut h = l.spawn(&p).unwrap();
    assert!(h.record().cgroup.is_none());
    assert_eq!(
        h.record().cgroup_opt_out_reason.as_deref(),
        Some("integration test: PID-namespace teardown path")
    );
    h.wait().unwrap();
    tick_stops_after_stop(&l, &c, "stop-nocg");
}

#[test]
fn refuses_without_cgroup_delegation_by_default() {
    let Some(probe_l) = launcher() else { return };
    let mut report = probe_l.report().clone();
    report.cgroup.usable = false;
    match Launcher::with_report(config(), report.clone()) {
        Err(LaunchError::MissingMandatoryControl(m)) => {
            assert_eq!(m[0].control, "cgroup_v2_delegation")
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    // An opt-out without a reason is rejected too.
    let cfg = LauncherConfig {
        cgroup: CgroupRequirement::AllowMissing {
            operator_reason: "  ".into(),
        },
        ..config()
    };
    assert!(matches!(
        Launcher::with_report(cfg, report),
        Err(LaunchError::InvalidProfile(_))
    ));
}

#[test]
fn refuses_when_bwrap_or_init_missing() {
    let cfg = LauncherConfig {
        bwrap_path: "/nonexistent/bwrap".into(),
        ..config()
    };
    match Launcher::new(cfg) {
        Err(LaunchError::MissingMandatoryControl(m)) => {
            assert!(m.iter().any(|m| m.control == "bubblewrap"), "{m:?}")
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    let cfg = LauncherConfig {
        init_path: "/nonexistent/tessera-sandbox-init".into(),
        ..config()
    };
    match Launcher::new(cfg) {
        Err(LaunchError::MissingMandatoryControl(m)) => {
            assert!(m.iter().any(|m| m.control == "sandbox_init"), "{m:?}")
        }
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn pids_limit_enforced() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let p = profile(&c, "pidslimit", "/usr/bin/python3")
        .args([
            "-I",
            "-c",
            "import os, time\nok=0\nfor i in range(64):\n  try:\n    pid=os.fork()\n  except OSError:\n    continue\n  if pid==0:\n    time.sleep(30); os._exit(0)\n  ok+=1\nprint(ok)",
        ])
        .limits(ResourceLimits {
            pids_max: Some(16),
            ..ResourceLimits::default()
        });
    let mut h = l.spawn(&p).unwrap();
    let cg = PathBuf::from(h.record().cgroup.clone().unwrap());
    assert_eq!(
        fs::read_to_string(cg.join("pids.max")).unwrap().trim(),
        "16"
    );
    assert_eq!(
        fs::read_to_string(cg.join("memory.max")).unwrap().trim(),
        (2u64 << 30).to_string()
    );
    let mut out = String::new();
    h.take_stdout()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap_or(0);
    // python exits after printing; forked sleepers keep the tree alive -> stop.
    h.stop().unwrap();
    let forked: u32 = out
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("bad output {out:?}"));
    assert!(forked < 16, "forked {forked} processes despite pids.max=16");
}

#[test]
fn unsafe_profiles_rejected() {
    let Some(l) = launcher() else { return };
    let home = std::env::var("HOME").unwrap();
    let a = || AgentLabel::new("bad").unwrap();
    let cases = vec![
        LaunchProfile::new(a(), "/bin/true").workspace("/"),
        LaunchProfile::new(a(), "/bin/true").workspace(&home),
        LaunchProfile::new(a(), "/bin/true").workspace("/home"),
        LaunchProfile::new(a(), "/bin/true").workspace("/run"),
        LaunchProfile::new(a(), "/bin/true").workspace("/proc/self"),
        LaunchProfile::new(a(), "/bin/true").ro_bind(&home, "/data"),
        LaunchProfile::new(a(), "/bin/true").ro_bind("/etc", "/data"),
        LaunchProfile::new(a(), "/bin/true").ro_bind("/usr/share", "/usr/share"),
        LaunchProfile::new(a(), "/bin/true").ro_bind("/usr/share", "/workspace/x"),
        LaunchProfile::new(a(), "/bin/true").ro_bind("/usr/share", "/opt/../usr"),
        LaunchProfile::new(a(), "/bin/true").env("TESSERA_BROKER_FD", "7"),
        LaunchProfile::new(a(), "/bin/true").env("BAD=KEY", "x"),
        LaunchProfile::new(a(), "bin/true"),
        LaunchProfile::new(a(), "/bin/../bin/true"),
    ];
    for p in cases {
        match l.spawn(&p) {
            Err(LaunchError::InvalidProfile(_)) => {}
            other => panic!("profile {p:?} not rejected: {other:?}"),
        }
    }
}

#[test]
fn bwrap_args_contain_mandatory_flags() {
    let Some(l) = launcher() else { return };
    let c = ctx();
    let args: Vec<String> = l
        .bwrap_args(&profile(&c, "args", "/bin/true"))
        .unwrap()
        .into_iter()
        .map(|s| s.into_string().unwrap())
        .collect();
    let joined = args.join(" ");
    for flag in [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop ALL",
        "--clearenv",
        "--proc /proc",
        "--dev /dev",
        "--tmpfs /tmp",
        "--add-seccomp-fd",
        "--remount-ro /",
        "--landlock required",
    ] {
        assert!(joined.contains(flag), "missing {flag}: {joined}");
    }
    for forbidden in ["--bind / ", "/run/user", "--share-net", "--ro-bind / /"] {
        assert!(!joined.contains(forbidden), "unexpected {forbidden}");
    }
    let home = std::env::var("HOME").unwrap();
    assert!(
        !args
            .iter()
            .any(|a| a == "/home" || *a == home || a.starts_with("/run"))
    );
}
