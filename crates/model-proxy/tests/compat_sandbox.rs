//! Real-sandbox integration test of compatibility mode (WP6, spec §12.3).
//!
//! A stub harness (`tests/harness/stub_harness.py`) runs in a Tessera
//! sandbox launched with a `ModelRoute`: empty network namespace, the model
//! proxy's Unix socket bound in, and `tessera-netshim` on one loopback port
//! that Landlock opens for bind+connect. Traffic flows
//! harness → shim → proxy → local fake TLS upstream with the injected key.
//! The test asserts that direct networking and other ports fail, that the
//! credential is nowhere inside the sandbox, and that a compromised harness
//! stays contained. If a mandatory sandbox control is missing on the host,
//! the test prints a loud SKIPPED banner (as the launcher tests do).

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::*;
use tessera_launcher::{
    AgentLabel, LandlockRequirement, LaunchError, LaunchProfile, Launcher, LauncherConfig,
    LoopbackShim, ModelRoute, StdioMode,
};

const NETSHIM: &str = env!("CARGO_BIN_EXE_tessera-netshim");
const PORT: u16 = 18080;

/// `tessera-sandbox-init` from the same target directory, (re)built with
/// the same cargo (a no-op when `cargo test --workspace` already built it).
fn init_binary() -> PathBuf {
    let dir = Path::new(NETSHIM).parent().unwrap();
    let target_dir = dir.parent().unwrap();
    let profile = dir.file_name().unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.args([
        "build",
        "-q",
        "-p",
        "tessera-launcher",
        "--bin",
        "tessera-sandbox-init",
    ])
    .arg("--target-dir")
    .arg(target_dir)
    .current_dir(env!("CARGO_MANIFEST_DIR"));
    if profile == "release" {
        cmd.arg("--release");
    }
    let st = cmd.status().expect("run cargo");
    assert!(st.success(), "building tessera-sandbox-init failed");
    dir.join("tessera-sandbox-init")
}

/// `model_socket_dir`: the private directory holding the proxy socket
/// (model sockets outside it are refused).
fn launcher(landlock: LandlockRequirement, model_socket_dir: &Path) -> Option<Launcher> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(model_socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = LauncherConfig {
        init_path: init_binary(),
        landlock,
        model_socket_dir: Some(model_socket_dir.to_path_buf()),
        ..LauncherConfig::default()
    };
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

fn harness_dir() -> PathBuf {
    std::fs::canonicalize(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/harness")).unwrap()
}

fn route(socket: &Path) -> ModelRoute {
    ModelRoute {
        host_socket: socket.to_path_buf(),
        loopback: Some(LoopbackShim {
            port: PORT,
            netshim_path: NETSHIM.into(),
        }),
    }
}

fn run_stub(mode: &str) -> Option<(Output, Harness)> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let h = rt.block_on(start(|_| {}));
    let l = launcher(LandlockRequirement::Required, h.socket.parent().unwrap())?;
    let ws = tempfile::tempdir().unwrap();
    let profile = LaunchProfile::new(
        AgentLabel::new(format!("compat-{mode}")).unwrap(),
        "/usr/bin/python3",
    )
    .args([
        "-I".to_string(),
        "/harness/stub_harness.py".into(),
        mode.into(),
        h.upstream.addr.port().to_string(),
        // A host binary that must not be reachable from inside.
        NETSHIM.into(),
        "sk-test-".into(),
    ])
    .workspace(ws.path())
    .ro_bind(harness_dir(), "/harness")
    .env("ANTHROPIC_BASE_URL", format!("http://127.0.0.1:{PORT}"))
    .stdio(StdioMode::Null, StdioMode::Piped, StdioMode::Piped)
    .model_route(route(&h.socket));
    let handle = l.spawn(&profile).unwrap_or_else(|e| panic!("spawn: {e}"));
    let rec = handle.record().clone();
    assert_eq!(rec.confinement.landlock, "full");
    assert!(rec.model_route.is_some());
    let out = handle.wait_with_output().unwrap();
    eprintln!("{}", String::from_utf8_lossy(&out.stdout));
    // Keep the runtime (proxy + upstream) alive until the sandbox is done.
    drop(rt);
    Some((out, h))
}

fn show(o: &Output) -> String {
    format!(
        "status={:?}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn check_common(o: &Output, h: &Harness) {
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        o.status.success() && stdout.contains("RESULT: contained") && !stdout.contains("BREACH"),
        "{}",
        show(o)
    );
    assert!(!stdout.contains(SECRET) && !stderr.contains(SECRET));
    assert!(stdout.contains("TCP-SHIM-RESPONSE 200"), "{}", show(o));
    assert!(stdout.contains("UNIX-RESPONSE 200"), "{}", show(o));
    // The upstream echoed the injected key; the sandbox saw only redaction.
    assert!(stdout.contains("[REDACTED-BY-TESSERA]"), "{}", show(o));
    // Upstream got exactly the allowed requests, each with the host key and
    // none of the sandbox's fake credentials.
    let seen = h.upstream.seen();
    let targets: Vec<&str> = seen.iter().map(|s| s.target.as_str()).collect();
    assert_eq!(
        targets,
        ["/v1/messages?beta=true", "/v1/models"],
        "{seen:?}"
    );
    for s in &seen {
        assert!(s.head.contains(&format!("x-api-key: {SECRET}")));
        assert!(!s.head.contains("sandbox-fake"));
    }
}

#[test]
fn compat_sandbox_reaches_model_only_through_proxy() {
    let Some((o, h)) = run_stub("model") else {
        return;
    };
    check_common(&o, &h);
}

#[test]
fn compromised_harness_stays_contained() {
    let Some((o, h)) = run_stub("escape") else {
        return;
    };
    check_common(&o, &h);
    let stdout = String::from_utf8_lossy(&o.stdout);
    for expect in [
        "harness rewrote its own permission settings",
        "unshare new userns",
        "exec host binary outside sandbox",
        "host path not visible",
        "unlink model socket refused",
        "overwrite netshim refused",
        "direct egress after escape attempts refused",
    ] {
        assert!(stdout.contains(expect), "missing {expect:?}\n{}", show(&o));
    }
}

#[test]
fn loopback_port_requires_required_landlock() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let h = rt.block_on(start(|_| {}));
    let Some(l) = launcher(LandlockRequirement::BestEffort, h.socket.parent().unwrap()) else {
        return;
    };
    let p = LaunchProfile::new(AgentLabel::new("compat-weak").unwrap(), "/bin/true")
        .model_route(route(&h.socket));
    match l.spawn(&p) {
        Err(LaunchError::InvalidProfile(m)) => assert!(m.contains("Required"), "{m}"),
        other => panic!("expected refusal, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn model_socket_must_be_private_socket() {
    let dir = tempfile::tempdir().unwrap();
    let Some(l) = launcher(LandlockRequirement::Required, dir.path()) else {
        return;
    };
    // A regular file.
    let f = dir.path().join("not-a-socket");
    std::fs::write(&f, b"x").unwrap();
    // A world-accessible socket.
    let s = dir.path().join("open.sock");
    let _l = std::os::unix::net::UnixListener::bind(&s).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o666)).unwrap();
    for bad in [
        f.as_path(),
        s.as_path(),
        Path::new("/nonexistent/model.sock"),
    ] {
        let p = LaunchProfile::new(AgentLabel::new("compat-bad").unwrap(), "/bin/true")
            .model_route(ModelRoute {
                host_socket: bad.into(),
                loopback: None,
            });
        assert!(
            matches!(l.spawn(&p), Err(LaunchError::InvalidProfile(_))),
            "{bad:?} accepted"
        );
    }
}
