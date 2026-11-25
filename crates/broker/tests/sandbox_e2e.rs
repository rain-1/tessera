//! End-to-end with two *real* sandboxes (bubblewrap + seccomp + Landlock +
//! cgroup launcher) running a shell loop that drives the real `tessera` CLI
//! over the launcher-created broker channel (fd 3): approval, read,
//! delegation, revocation, an agent-spawned third sandbox that discovers a
//! delegated capability by listing, isolation from the admin socket and
//! from the other sandbox, and cascade termination of the spawn tree.
//!
//! Skips loudly (prints `SKIPPED`) when the host lacks a mandatory sandbox
//! control; it never runs a weaker profile.

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout};
use std::sync::{Arc, Mutex};

use common::*;
use tessera_broker::{
    AdapterExecutor, AdminRequest, AdminResponse, AgentSpawnProfile, AuditLog, Broker,
    BrokerConfig, CgroupLimit, LauncherSpawner, MonotonicClock, ProfileSpec, Services,
};
use tessera_capability_core::AgentId;
use tessera_journal::{Journal, JournalOptions};
use tessera_launcher::{LaunchError, LauncherConfig};

/// The cargo profile directory (`target/debug`) holding the workspace's
/// binaries. Test executables live at `target/debug/deps/` (older cargo) or
/// `target/debug/build/<pkg>/<hash>/out/` (newer layouts), so walk up from
/// this executable to the first directory that has both `build/` and
/// `incremental/` (true of every cargo profile directory).
fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .skip(1)
        .find(|d| d.join("build").is_dir() && d.join("incremental").is_dir())
        .unwrap_or_else(|| panic!("no cargo profile directory above {}", exe.display()))
        .to_path_buf()
}

/// Make sure the in-sandbox binaries exist (they belong to other packages,
/// so `cargo test -p tessera-broker` does not build them by itself).
fn ensure_bins(dir: &Path) {
    let need = ["tessera", "tessera-sandbox-init"];
    if need.iter().all(|b| dir.join(b).exists()) {
        return;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let st = std::process::Command::new(cargo)
        .args([
            "build",
            "-p",
            "tessera-cli",
            "-p",
            "tessera-launcher",
            "--bins",
        ])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .status()
        .unwrap();
    assert!(st.success(), "building tessera CLI / launcher shim failed");
    // A missing binary is a test failure, never a skip.
    for b in need {
        assert!(
            dir.join(b).is_file(),
            "{} missing after build: this test would not run",
            dir.join(b).display()
        );
    }
}

type Pipes = Arc<Mutex<HashMap<AgentId, (ChildStdin, BufReader<ChildStdout>)>>>;
/// Host-side facts about each sandbox: (outer pid, cgroup leaf).
type Facts = Arc<Mutex<HashMap<AgentId, (u32, Option<PathBuf>)>>>;

struct Sandbox {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Sandbox {
    /// Run one `tessera --json ...` line inside the sandbox; return
    /// (exit code, stdout JSON lines).
    fn run(&mut self, args: &str) -> (i32, serde_json::Value) {
        writeln!(self.stdin, "{args}").unwrap();
        self.stdin.flush().unwrap();
        let mut last = serde_json::Value::Null;
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "sandbox exited"
            );
            if let Some(code) = line.trim().strip_prefix("EXIT ") {
                return (code.parse().unwrap(), last);
            }
            if let Ok(v) = serde_json::from_str(line.trim()) {
                last = v;
            }
        }
    }

    /// Run a shell command inside the sandbox; return (exit code, output).
    fn sh(&mut self, cmd: &str) -> (i32, String) {
        writeln!(self.stdin, "SH {cmd}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "sandbox exited"
            );
            if let Some(code) = line.trim().strip_prefix("EXIT ") {
                return (code.parse().unwrap(), out);
            }
            out.push_str(&line);
        }
    }

    /// Whether the sandbox's stdout reaches EOF (its process tree died)
    /// within 10 s.
    fn is_dead(&mut self) -> bool {
        use std::io::Read;
        use std::os::fd::AsFd;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut buf = [0u8; 4096];
        loop {
            // Drain anything buffered first.
            if !self.stdout.buffer().is_empty() {
                let n = self.stdout.buffer().len();
                self.stdout.consume(n);
                continue;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            let ts = rustix::time::Timespec {
                tv_sec: left.as_secs() as _,
                tv_nsec: left.subsec_nanos() as _,
            };
            let fd = self.stdout.get_ref().as_fd();
            let mut fds = [rustix::event::PollFd::new(
                &fd,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut fds, Some(&ts)) {
                Ok(0) => return false,
                Ok(_) => match self.stdout.get_mut().read(&mut buf) {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return true,
                },
                Err(_) => continue,
            }
        }
    }
}

/// Parse the CLI's `<epoch-hex>:<serial>` agent form.
fn parse_agent(s: &str) -> AgentId {
    let (e, n) = s.split_once(':').unwrap();
    AgentId::new(u64::from_str_radix(e, 16).unwrap(), n.parse().unwrap())
}

fn take(pipes: &Pipes, a: AgentId) -> Sandbox {
    let (stdin, stdout) = pipes.lock().unwrap().remove(&a).expect("pipes");
    Sandbox { stdin, stdout }
}

fn create(b: &Broker, pipes: &Pipes) -> (AgentId, Sandbox) {
    let AdminResponse::Agent(a) = b.admin(AdminRequest::CreatePrincipal {
        profile: "agent".into(),
    }) else {
        panic!("spawn failed")
    };
    (a, take(pipes, a))
}

#[test]
fn two_real_sandboxes_read_delegate_revoke_via_tessera_cli() {
    let bin = target_dir();
    ensure_bins(&bin);
    let workspaces = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(workspaces.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let lc = LauncherConfig {
        init_path: bin.join("tessera-sandbox-init"),
        ..LauncherConfig::default()
    };
    // `SH cmd` runs a shell command (isolation probes); anything else is a
    // `tessera` invocation.
    let script = "while IFS= read -r line; do \
                  case \"$line\" in \
                  'SH '*) eval \"${line#SH }\" 2>&1 ;; \
                  *) eval \"/opt/tessera/tessera --json --approval-timeout 60 $line\" 2>/dev/null ;; \
                  esac; echo \"EXIT $?\"; done";
    let profile = ProfileSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        workspace: Some(workspaces.path().to_path_buf()),
        ro_binds: vec![(bin.join("tessera"), "/opt/tessera/tessera".into())],
        env: vec![],
        memory_max_bytes: Some(CgroupLimit::Max(256 << 20)),
        pids_max: Some(CgroupLimit::Max(64)),
        piped_stdio: true,
    };
    let mut spawner = match LauncherSpawner::new(lc, HashMap::from([("agent".into(), profile)])) {
        Ok(s) => s,
        Err(LaunchError::MissingMandatoryControl(m)) => {
            // Only a missing *kernel/host* control may skip; a missing
            // in-repo binary (the init shim) is a broken test setup.
            assert!(
                m.iter().all(|c| c.control != "sandbox_init"),
                "init shim missing: {m:?}"
            );
            eprintln!("\n!!!!!!!! SKIPPED: mandatory sandbox control missing: {m:?} !!!!!!!!\n");
            return;
        }
        Err(e) => panic!("launcher: {e}"),
    };
    let pipes: Pipes = Arc::default();
    let facts: Facts = Arc::default();
    let (p2, f2) = (Arc::clone(&pipes), Arc::clone(&facts));
    spawner.on_spawn = Some(Box::new(move |agent, h| {
        let i = h.take_stdin().unwrap();
        let o = BufReader::new(h.take_stdout().unwrap());
        p2.lock().unwrap().insert(agent, (i, o));
        f2.lock()
            .unwrap()
            .insert(agent, (h.pid(), h.cgroup().map(|c| c.path().to_path_buf())));
    }));

    let mut h = Harness::new();
    let journal = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    // Agents may spawn profile 1 (the same shell loop), with no baseline.
    let config = BrokerConfig {
        spawn_profiles: std::collections::BTreeMap::from([(
            1,
            AgentSpawnProfile {
                profile: "agent".into(),
                baseline: vec![],
            },
        )]),
        ..BrokerConfig::default()
    };
    let b = Broker::start(
        journal,
        config,
        Services {
            executor: AdapterExecutor::new(Some(h.root.path())).unwrap().shared(),
            spawner: Some(Box::new(spawner)),
            audit: AuditLog::memory(),
            clock: Arc::new(MonotonicClock::default()),
            fault: None,
        },
    )
    .unwrap();
    h.enroll(&b);
    let admin_dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(admin_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let admin_sock = admin_dir.path().join("admin.sock");
    b.serve_admin(&admin_sock).unwrap();
    let obj = register_file(&b, "notes.txt");
    let (_a_id, mut a) = create(&b, &pipes);
    let (b_id, mut bb) = create(&b, &pipes);
    let b_arg = format!("{:x}:{}", b_id.epoch(), b_id.serial());

    // Operator approves one non-delegatable read for A (software key).
    let approver = std::thread::scope(|s| {
        let t = s.spawn(|| {
            a.run(&format!(
                "request --file {obj} --rights read --budget 1 --depth 0"
            ))
        });
        let r = h.approve(&b);
        (t.join().unwrap(), r)
    });
    let ((code, j), AdminResponse::Capability(once)) = approver else {
        panic!("approval failed")
    };
    assert_eq!(code, 0, "{j}");
    let once_hex = j["cap_id"].as_str().unwrap().to_owned();
    assert_eq!(u128::from_str_radix(&once_hex, 16).unwrap(), once);

    let (code, j) = a.run(&format!("read --cap {once_hex}"));
    assert_eq!(code, 0, "{j}");
    assert_eq!(j["body_utf8"], "top secret notes");
    let (code, j) = a.run(&format!("read --cap {once_hex}"));
    assert_eq!(code, 1, "second read denied: {j}");
    assert_eq!(j["error"]["code"], "InsufficientBudget");
    // B cannot use A's copied capability id.
    let (code, j) = bb.run(&format!("read --cap {once_hex}"));
    assert_eq!(code, 1);
    assert_eq!(j["error"]["code"], "UnknownCapability");

    // Second grant: 3 uses, depth 1; A delegates 2 to B.
    let ((code, j), r) = std::thread::scope(|s| {
        let t = s.spawn(|| {
            a.run(&format!(
                "request --file {obj} --rights read --budget 3 --depth 1"
            ))
        });
        let r = h.approve(&b);
        (t.join().unwrap(), r)
    });
    assert_eq!(code, 0, "{j}");
    let AdminResponse::Capability(parent) = r else {
        panic!()
    };
    let parent_hex = j["cap_id"].as_str().unwrap().to_owned();
    let (code, j) = a.run(&format!(
        "delegate --cap {parent_hex} --to {b_arg} --file {obj} --rights read --budget 2 --depth 0"
    ));
    assert_eq!(code, 0, "{j}");
    let child = j["child_cap_id"].as_str().unwrap().to_owned();
    let (code, j) = bb.run(&format!("read --cap {child}"));
    assert_eq!(code, 0, "{j}");
    assert_eq!(j["body_utf8"], "top secret notes");

    // Operator revokes A's capability: B's child stops authorizing.
    assert_eq!(
        b.admin(AdminRequest::Revoke { capability: parent }),
        AdminResponse::Ok
    );
    let (code, j) = bb.run(&format!("read --cap {child}"));
    assert_eq!(code, 1);
    assert_eq!(j["error"]["code"], "Revoked");

    // ---- Agent spawn, discovery by listing, owner revoke ----------------
    let ((code, j), r) = std::thread::scope(|s| {
        let t = s.spawn(|| {
            a.run(&format!(
                "request --file {obj} --rights read --budget 4 --depth 1 \
                 --description 'hand two reads to my worker'"
            ))
        });
        let r = h.approve(&b);
        (t.join().unwrap(), r)
    });
    assert_eq!(code, 0, "{j}");
    assert!(matches!(r, AdminResponse::Capability(_)));
    let p3 = j["cap_id"].as_str().unwrap().to_owned();
    let (code, j) = a.run("spawn --profile 1 --request-id 5");
    assert_eq!(code, 0, "{j}");
    let c_arg = j["agent"].as_str().unwrap().to_owned();
    let c_id = parse_agent(&c_arg);
    // Same request id: the same child, no second sandbox.
    let (code, j) = a.run("spawn --profile 1 --request-id 5");
    assert_eq!((code, j["agent"].as_str()), (0, Some(c_arg.as_str())));
    let mut c = take(&pipes, c_id);
    assert!(
        pipes.lock().unwrap().is_empty(),
        "exactly one sandbox launched"
    );
    // The child starts with nothing (baseline only; this profile has none).
    let (code, j) = c.run("list");
    assert_eq!(code, 0, "{j}");
    assert_eq!(j["caps"].as_array().unwrap().len(), 0);
    let (code, j) = a.run(&format!(
        "delegate --cap {p3} --to {c_arg} --file {obj} --rights read --budget 2 --depth 0"
    ));
    assert_eq!(code, 0, "{j}");
    // The child finds the delegation itself; no id passed out of band.
    let (code, j) = c.run("list");
    assert_eq!(code, 0, "{j}");
    let found = j["caps"][0]["cap_id"].as_str().unwrap().to_owned();
    assert_eq!(j["caps"][0]["parent"].as_str(), Some(p3.as_str()));
    let (code, j) = c.run(&format!("read --cap {found}"));
    assert_eq!(code, 0, "{j}");
    assert_eq!(j["body_utf8"], "top secret notes");
    // The child cannot use its parent's capability by copying the id.
    let (code, j) = c.run(&format!("read --cap {p3}"));
    assert_eq!(
        (code, j["error"]["code"].as_str()),
        (1, Some("UnknownCapability"))
    );
    // The owner revokes its grant: the child's delegated read stops.
    let (code, j) = a.run(&format!("revoke --cap {p3}"));
    assert_eq!(code, 0, "{j}");
    let (code, j) = c.run(&format!("read --cap {found}"));
    assert_eq!((code, j["error"]["code"].as_str()), (1, Some("Revoked")));

    // ---- Isolation: admin socket and the other sandbox's channel --------
    assert_eq!(a.sh("echo first > /workspace/marker").0, 0);
    assert_eq!(bb.sh("test ! -e /workspace/marker").0, 0);
    assert_eq!(c.sh("test ! -e /workspace/marker").0, 0);
    assert_eq!(bb.sh("echo second > /workspace/marker").0, 0);
    assert_eq!(a.sh("cat /workspace/marker").1.trim(), "first");
    assert_eq!(bb.sh("cat /workspace/marker").1.trim(), "second");
    let sock = admin_sock.display().to_string();
    let (code, out) = a.sh(&format!("test -e '{sock}' && echo VISIBLE || echo HIDDEN"));
    assert_eq!((code, out.trim()), (0, "HIDDEN"), "admin socket visible");
    let (code, j) = a.run(&format!("--socket '{sock}' list"));
    assert_ne!(code, 0, "admin socket reachable from a sandbox: {j}");
    let b_pid = facts.lock().unwrap()[&b_id].0;
    let (_, out) = a.sh(&format!(
        "ls /proc/{b_pid}/fd >/dev/null 2>&1 && echo SEEN || echo UNSEEN"
    ));
    assert_eq!(out.trim(), "UNSEEN", "B's process visible from A");
    let (code, j) = a.run(&format!("--socket /proc/{b_pid}/fd/3 list"));
    assert_ne!(code, 0, "B's channel reachable from A: {j}");
    // A's own channel still works after the probes.
    let (code, _) = a.run("list");
    assert_eq!(code, 0);

    // ---- Cascade termination ------------------------------------------
    let c_leaf = facts.lock().unwrap()[&c_id].1.clone();
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: _a_id }),
        AdminResponse::Ok
    );
    assert!(a.is_dead(), "A's sandbox survived termination");
    assert!(
        c.is_dead(),
        "spawned child survived its parent's termination"
    );
    if let Some(leaf) = c_leaf {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while leaf.exists() {
            assert!(std::time::Instant::now() < deadline, "{leaf:?} not removed");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    // B, in another domain, is unaffected.
    let (code, _) = bb.run("list");
    assert_eq!(code, 0);

    // Terminating a principal stops its sandbox and closes its channel.
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: b_id }),
        AdminResponse::Ok
    );
    assert!(bb.is_dead());
    drop(b);
}
