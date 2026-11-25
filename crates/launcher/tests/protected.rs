//! `LauncherConfig::protected_host_paths` (security review 2026-11-25, #6):
//! a workspace, bind source, model socket or netshim that is a protected
//! path, lies inside one, or contains one is refused. Checked through
//! `Launcher::bwrap_args`, which validates a profile without spawning.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use tessera_launcher::{
    AgentLabel, LaunchError, LaunchProfile, Launcher, LauncherConfig, LoopbackShim, ModelRoute,
};

const INIT: &str = env!("CARGO_BIN_EXE_tessera-sandbox-init");

fn launcher(protected: Vec<PathBuf>) -> Option<Launcher> {
    match Launcher::new(LauncherConfig {
        init_path: INIT.into(),
        protected_host_paths: protected,
        ..LauncherConfig::default()
    }) {
        Ok(l) => Some(l),
        Err(LaunchError::MissingMandatoryControl(m)) => {
            eprintln!("\n!!!!!!!! SKIPPED: mandatory sandbox control missing: {m:?} !!!!!!!!\n");
            None
        }
        Err(e) => panic!("{e}"),
    }
}

fn base() -> LaunchProfile {
    LaunchProfile::new(AgentLabel::new("prot").unwrap(), "/bin/true")
}

fn refused(l: &Launcher, p: &LaunchProfile, what: &str) {
    match l.bwrap_args(p) {
        Err(LaunchError::InvalidProfile(_)) => {}
        other => panic!(
            "{what}: expected InvalidProfile, got {:?}",
            other.map(|_| ())
        ),
    }
}

fn private_socket(dir: &Path) -> (PathBuf, UnixListener) {
    let s = dir.join("model.sock");
    let l = UnixListener::bind(&s).unwrap();
    std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o600)).unwrap();
    (s, l)
}

#[test]
fn ancestors_descendants_and_equal_paths_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let state = root.join("state");
    let inside = state.join("inside");
    let sibling = root.join("sibling");
    for d in [&state, &inside, &sibling] {
        std::fs::create_dir_all(d).unwrap();
    }
    let secret = sibling.join("api-key");
    std::fs::write(&secret, "x").unwrap();
    let Some(l) = launcher(vec![state.clone(), secret.clone()]) else {
        return;
    };

    // Baseline: an unrelated sibling directory is fine.
    let other = root.join("other");
    std::fs::create_dir(&other).unwrap();
    l.bwrap_args(&base().workspace(&other)).unwrap();
    l.bwrap_args(&base().ro_bind(&other, "/data")).unwrap();

    for (path, what) in [
        (&state, "equal"),
        (&inside, "descendant"),
        (&root, "ancestor"),
        (&sibling, "ancestor of protected file"),
        (&secret, "protected file"),
    ] {
        if path.is_dir() {
            refused(&l, &base().workspace(path), &format!("workspace {what}"));
        }
        refused(&l, &base().ro_bind(path, "/data"), &format!("bind {what}"));
    }
    // A symlink alias into the protected tree is resolved first.
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&inside, &alias).unwrap();
    refused(&l, &base().workspace(&alias), "symlink alias");
}

#[test]
fn model_route_cannot_point_into_protected_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let admin = root.join("admin");
    let free = root.join("free");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(&free).unwrap();
    // A private socket that *looks* like a model socket but is the broker's
    // admin socket (protected): refused.
    let (admin_sock, _a) = private_socket(&admin);
    let (free_sock, _f) = private_socket(&free);
    let Some(l) = launcher(vec![admin.clone()]) else {
        return;
    };
    let route = |s: &Path| ModelRoute {
        host_socket: s.to_path_buf(),
        loopback: None,
    };
    l.bwrap_args(&base().model_route(route(&free_sock)))
        .unwrap();
    refused(&l, &base().model_route(route(&admin_sock)), "admin socket");

    let shim = admin.join("netshim");
    std::fs::write(&shim, "#!/bin/sh\n").unwrap();
    refused(
        &l,
        &base().model_route(ModelRoute {
            host_socket: free_sock.clone(),
            loopback: Some(LoopbackShim {
                port: 18080,
                netshim_path: shim,
            }),
        }),
        "netshim in protected dir",
    );
}
