//! End-to-end with two *real* sandboxes (bubblewrap + seccomp + Landlock +
//! cgroup launcher) running a shell loop that drives the real `tessera` CLI
//! over the launcher-created broker channel (fd 3).
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
    AdapterExecutor, AdminRequest, AdminResponse, AuditLog, Broker, BrokerConfig, LauncherSpawner,
    MonotonicClock, ProfileSpec, Services,
};
use tessera_capability_core::AgentId;
use tessera_journal::{Journal, JournalOptions};
use tessera_launcher::{LaunchError, LauncherConfig};

fn target_dir() -> PathBuf {
    // .../target/debug/deps/sandbox_e2e-<hash>
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
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
}

type Pipes = Arc<Mutex<HashMap<AgentId, (ChildStdin, BufReader<ChildStdout>)>>>;

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
fn two_real_sandboxes_read_delegate_revoke_via_tessera_cli() {
    let bin = target_dir();
    ensure_bins(&bin);
    let lc = LauncherConfig {
        init_path: bin.join("tessera-sandbox-init"),
        ..LauncherConfig::default()
    };
    let script = "while IFS= read -r line; do \
                  eval \"/opt/tessera/tessera --json --approval-timeout 60 $line\" 2>/dev/null; \
                  echo \"EXIT $?\"; done";
    let profile = ProfileSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        workspace: None,
        ro_binds: vec![(bin.join("tessera"), "/opt/tessera/tessera".into())],
        env: vec![],
        memory_max_bytes: Some(256 << 20),
        pids_max: Some(64),
        piped_stdio: true,
    };
    let mut spawner = match LauncherSpawner::new(lc, HashMap::from([("agent".into(), profile)])) {
        Ok(s) => s,
        Err(LaunchError::MissingMandatoryControl(m)) => {
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

    let mut h = Harness::new();
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
    h.enroll(&b);
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

    // Terminating a principal stops its sandbox and closes its channel.
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: b_id }),
        AdminResponse::Ok
    );
    drop(b);
}
