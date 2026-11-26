//! Re-review 2026-11-26 N2 (`docs/security-review-2026-11-25.md`): the model
//! route check accepted any private socket owned by the launcher's user,
//! including the GnuPG agent (`S.gpg-agent`, `S.gpg-agent.ssh`) and the SSH
//! agent in `$XDG_RUNTIME_DIR`. A model socket must now lie inside the
//! operator's dedicated `LauncherConfig::model_socket_dir`, and no path
//! component may name a credential agent. Checked through
//! `Launcher::bwrap_args`, which validates a profile without spawning.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use tessera_launcher::{
    AgentLabel, LaunchError, LaunchProfile, Launcher, LauncherConfig, ModelRoute,
};

const INIT: &str = env!("CARGO_BIN_EXE_tessera-sandbox-init");

/// `Ok(None)`: a mandatory control is missing on this host (skip).
fn launcher(model_socket_dir: Option<&Path>) -> Result<Option<Launcher>, LaunchError> {
    match Launcher::new(LauncherConfig {
        init_path: INIT.into(),
        model_socket_dir: model_socket_dir.map(Path::to_path_buf),
        ..LauncherConfig::default()
    }) {
        Ok(l) => Ok(Some(l)),
        Err(LaunchError::MissingMandatoryControl(m)) => {
            eprintln!("\n!!!!!!!! SKIPPED: mandatory sandbox control missing: {m:?} !!!!!!!!\n");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn private_dir(p: &Path) -> PathBuf {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p.to_path_buf()
}

fn private_socket(p: &Path) -> UnixListener {
    if let Some(d) = p.parent() {
        private_dir(d);
    }
    let l = UnixListener::bind(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    l
}

fn profile(socket: &Path) -> LaunchProfile {
    LaunchProfile::new(AgentLabel::new("e1.s1").unwrap(), "/bin/sh").model_route(ModelRoute {
        host_socket: socket.to_path_buf(),
        loopback: None,
    })
}

fn refused(l: &Launcher, socket: &Path) {
    match l.bwrap_args(&profile(socket)) {
        Err(LaunchError::InvalidProfile(_)) => {}
        other => panic!(
            "model socket {} accepted: {:?}",
            socket.display(),
            other.map(|_| ())
        ),
    }
}

#[test]
fn host_agent_sockets_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let models = private_dir(&tmp.path().canonicalize().unwrap().join("models"));
    let good = models.join("claude-1").join("model.sock");
    let _g = private_socket(&good);
    let Some(l) = launcher(Some(&models)).unwrap() else {
        return;
    };
    l.bwrap_args(&profile(&good)).unwrap();

    // The PoC's paths (whichever exist on this host) and their neighbours.
    let uid = rustix::process::getuid().as_raw();
    let run = PathBuf::from(format!("/run/user/{uid}"));
    for p in [
        run.join("gnupg/S.gpg-agent"),
        run.join("gnupg/S.gpg-agent.ssh"),
        run.join("gnupg/S.gpg-agent.extra"),
        run.join("openssh_agent"),
        run.join("keyring/ssh"),
        run.join("bus"),
    ] {
        refused(&l, &p);
    }
    if let Some(s) = std::env::var_os("SSH_AUTH_SOCK") {
        refused(&l, Path::new(&s));
    }
    // A private socket outside the model socket directory.
    let outside = tmp.path().join("outside/model.sock");
    let _o = private_socket(&outside);
    refused(&l, &outside);
    // Inside the directory, but named like a credential agent.
    let mut keep = Vec::new();
    for rel in [
        "gnupg/S.gpg-agent",
        "x/S.gpg-agent.ssh",
        "openssh_agent",
        "keyring/control",
        ".ssh/agent.sock",
    ] {
        let p = models.join(rel);
        keep.push(private_socket(&p));
        refused(&l, &p);
    }
    // A symlink inside the directory to a socket outside it.
    let alias = models.join("alias.sock");
    std::os::unix::fs::symlink(&outside, &alias).unwrap();
    refused(&l, &alias);
}

#[test]
fn model_routes_need_a_model_socket_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().canonicalize().unwrap().join("m/model.sock");
    let _s = private_socket(&sock);
    let Some(l) = launcher(None).unwrap() else {
        return;
    };
    refused(&l, &sock);
}

#[test]
fn model_socket_dir_must_be_private_and_dedicated() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    // Skip early on hosts without the mandatory controls.
    let ok = private_dir(&root.join("ok"));
    if launcher(Some(&ok)).unwrap().is_none() {
        return;
    }
    let open = root.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let file = root.join("file");
    std::fs::write(&file, "x").unwrap();
    let gnupg = private_dir(&root.join("gnupg"));
    let mut bad = vec![open, file, gnupg, root.join("missing"), PathBuf::from("/")];
    // The review's misconfiguration: the user's runtime directory itself.
    bad.extend(std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from));
    bad.extend(std::env::var_os("HOME").map(PathBuf::from));
    for dir in bad {
        match launcher(Some(&dir)) {
            Err(LaunchError::InvalidProfile(_)) => {}
            other => panic!(
                "model_socket_dir {} accepted: {:?}",
                dir.display(),
                other.map(|_| ())
            ),
        }
    }
}
