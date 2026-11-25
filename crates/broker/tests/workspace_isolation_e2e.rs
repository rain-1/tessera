//! Security review finding 1 (High): every principal launched from one
//! profile shared one writable workspace, which gave two sandboxes a Unix
//! socket rendezvous: A could pass its broker channel (fd 3) to B with
//! SCM_RIGHTS (identity theft) or plant scripts for B.
//!
//! Regression with *real* sandboxes (bubblewrap + seccomp + Landlock +
//! cgroups) launched by the broker from one profile: A runs the corpus probe
//! `tests/adversarial/cross_principal/sender.py`, B runs `receiver.py`, and B
//! must not reach any of A's sockets or files. As a control, the receiver
//! run inside A must detect A's own rendezvous points (the probe is not
//! vacuous). Host side: each principal has its own fresh 0700 directory.
//!
//! Skips loudly (prints `SKIPPED`) when the host lacks a mandatory sandbox
//! control; it never runs a weaker profile.

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout};
use std::sync::{Arc, Mutex};

use common::Harness;
use tessera_broker::{
    AdapterExecutor, AdminRequest, AdminResponse, AuditLog, Broker, BrokerConfig, CgroupLimit,
    LauncherSpawner, MonotonicClock, ProfileSpec, Services,
};
use tessera_capability_core::AgentId;
use tessera_journal::{Journal, JournalOptions};
use tessera_launcher::{LaunchError, LauncherConfig};

fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .skip(1)
        .find(|d| d.join("build").is_dir() && d.join("incremental").is_dir())
        .unwrap_or_else(|| panic!("no cargo profile directory above {}", exe.display()))
        .to_path_buf()
}

fn ensure_init(dir: &Path) {
    if dir.join("tessera-sandbox-init").exists() {
        return;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let st = std::process::Command::new(cargo)
        .args(["build", "-p", "tessera-launcher", "--bins"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .status()
        .unwrap();
    assert!(st.success(), "building the launcher shim failed");
    assert!(dir.join("tessera-sandbox-init").is_file());
}

type Pipes = Arc<Mutex<HashMap<AgentId, (ChildStdin, BufReader<ChildStdout>)>>>;

struct Sandbox {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Sandbox {
    /// Run a shell command inside the sandbox; return (exit code, output).
    fn sh(&mut self, cmd: &str) -> (i32, String) {
        writeln!(self.stdin, "{cmd}").unwrap();
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
}

fn create(b: &Broker, pipes: &Pipes) -> (AgentId, Sandbox) {
    let AdminResponse::Agent(a) = b.admin(AdminRequest::CreatePrincipal {
        profile: "agent".into(),
    }) else {
        panic!("spawn failed")
    };
    let (stdin, stdout) = pipes.lock().unwrap().remove(&a).expect("pipes");
    (a, Sandbox { stdin, stdout })
}

#[test]
fn sandboxes_from_one_profile_share_no_workspace_socket_or_file() {
    let bin = target_dir();
    ensure_init(&bin);
    let probes = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/adversarial/cross_principal"
    ))
    .canonicalize()
    .unwrap();
    let workspaces = tempfile::tempdir().unwrap();
    std::fs::set_permissions(workspaces.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let lc = LauncherConfig {
        init_path: bin.join("tessera-sandbox-init"),
        ..LauncherConfig::default()
    };
    let script = "while IFS= read -r line; do eval \"$line\" 2>&1; \
                  rc=$?; printf '\\nEXIT %s\\n' \"$rc\"; done";
    let profile = ProfileSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        workspace: Some(workspaces.path().to_path_buf()),
        ro_binds: vec![(probes, "/probes".into())],
        env: vec![],
        memory_max_bytes: Some(CgroupLimit::Max(256 << 20)),
        pids_max: Some(CgroupLimit::Max(64)),
        piped_stdio: true,
    };
    let mut spawner = match LauncherSpawner::new(lc, HashMap::from([("agent".into(), profile)])) {
        Ok(s) => s,
        Err(LaunchError::MissingMandatoryControl(m)) => {
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
    let p2 = Arc::clone(&pipes);
    spawner.on_spawn = Some(Box::new(move |agent, h| {
        let i = h.take_stdin().unwrap();
        let o = BufReader::new(h.take_stdout().unwrap());
        p2.lock().unwrap().insert(agent, (i, o));
    }));
    let h = Harness::new();
    let journal = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let b = Broker::start(
        journal,
        BrokerConfig::default(),
        Services {
            executor: AdapterExecutor::new(Some(h.root.path())).unwrap().shared(),
            spawner: Some(Box::new(spawner)),
            audit: AuditLog::memory(),
            clock: Arc::new(MonotonicClock::default()),
            fault: None,
        },
    )
    .unwrap();
    let (a_id, mut a) = create(&b, &pipes);
    let (b_id, mut bb) = create(&b, &pipes);

    // Host side: a fresh, private, distinct directory per principal.
    let dirs: Vec<PathBuf> = std::fs::read_dir(workspaces.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(dirs.len(), 2, "{dirs:?}");
    for d in &dirs {
        let md = std::fs::metadata(d).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.mode() & 0o777, 0o700, "{}", d.display());
        assert_eq!(md.uid(), rustix::process::geteuid().as_raw());
    }
    let tag = format!("tessera-cross-{}", std::process::id());

    // A offers its broker channel on every rendezvous it can create.
    let (code, out) = a.sh(&format!(
        "CROSS_WAIT=20 python3 -I /probes/sender.py {tag} > /workspace/sender.log 2>&1 & \
         for i in $(seq 100); do grep -q READY /workspace/sender.log 2>/dev/null && break; \
         sleep 0.1; done; cat /workspace/sender.log"
    ));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("READY"), "sender not ready: {out}");

    // Control: inside A the receiver does find A's sockets and files, and
    // is handed A's channel.
    let (code, out) = a.sh(&format!("python3 -I /probes/receiver.py {tag}"));
    assert_eq!(code, 1, "probe is vacuous inside A: {out}");
    assert!(out.contains("BREACH"), "{out}");
    let (_, log) = a.sh("cat /workspace/sender.log");
    let sent_to_self = log.matches("BREACH-SENT").count();
    assert!(sent_to_self >= 1, "{log}");

    // B, launched from the same profile, reaches none of it.
    let (code, out) = bb.sh(&format!("python3 -I /probes/receiver.py {tag}"));
    assert_eq!(code, 0, "cross-principal channel: {out}");
    assert!(out.contains("CONTAINED"), "{out}");
    // And B can neither name A's workspace on the host nor plant into it.
    for d in &dirs {
        let (_, out) = bb.sh(&format!(
            "test -e '{}' && echo SEEN || echo UNSEEN",
            d.display()
        ));
        assert_eq!(out.trim(), "UNSEEN", "{}", d.display());
    }
    // A was only ever reached by its own control run, never by B.
    let (_, log) = a.sh("cat /workspace/sender.log");
    assert_eq!(log.matches("BREACH-SENT").count(), sent_to_self, "{log}");

    // Retention policy (ADR-0031): the directories stay after termination,
    // are never reused, and a restart's principals get new ones.
    for agent in [a_id, b_id] {
        assert_eq!(
            b.admin(AdminRequest::TerminatePrincipal { agent }),
            AdminResponse::Ok
        );
    }
    for d in &dirs {
        assert!(d.is_dir(), "{} removed", d.display());
    }
    drop(b);
}
