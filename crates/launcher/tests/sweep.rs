//! Startup sweep of stale sandbox cgroups (spec §11: stop existing sandbox
//! trees across a broker restart).
//!
//! Needs cgroup v2 delegation; prints a loud `SKIPPED` banner otherwise.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use tessera_launcher::{LaunchError, Launcher, LauncherConfig};

const INIT: &str = env!("CARGO_BIN_EXE_tessera-sandbox-init");

/// Start `sleep` already inside `leaf` (same trick as the launcher).
fn sleeper_in(leaf: &Path) -> std::process::Child {
    Command::new("/bin/sh")
        .arg("-c")
        .arg("echo 0 > \"$0/cgroup.procs\" || exit 125; exec sleep 1000")
        .arg(leaf)
        .spawn()
        .unwrap()
}

fn wait_in_cgroup(leaf: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_to_string(leaf.join("cgroup.procs"))
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        assert!(Instant::now() < deadline, "sleeper never entered {leaf:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn stale_leaves_are_killed_and_removed_own_kept() {
    let group = format!("tessera.sweeptest-{}", std::process::id());
    let cfg = LauncherConfig {
        init_path: INIT.into(),
        cgroup_group_name: group.clone(),
        ..LauncherConfig::default()
    };
    let launcher = match Launcher::new(cfg) {
        Ok(l) => l,
        Err(LaunchError::MissingMandatoryControl(m)) => {
            eprintln!("\n!!!!!!!! SKIPPED: mandatory sandbox control missing: {m:?} !!!!!!!!\n");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let root = launcher
        .report()
        .cgroup
        .delegation_root
        .clone()
        .expect("delegation root");
    let gdir = Path::new(&root).join(&group);
    fs::create_dir_all(&gdir).unwrap();

    // A leaf from a "previous broker" (pid 1 never runs a launcher here),
    // with a live process and a nested child cgroup holding another one.
    let stale = gdir.join("e1.s1-1-0-abc");
    fs::create_dir(&stale).unwrap();
    let nested = stale.join("inner");
    fs::create_dir(&nested).unwrap();
    let mut s1 = sleeper_in(&stale);
    let mut s2 = sleeper_in(&nested);
    wait_in_cgroup(&stale);
    wait_in_cgroup(&nested);
    // A leaf named with our own pid: created by this process, kept.
    let own = gdir.join(format!("e2.s1-{}-0-abc", std::process::id()));
    fs::create_dir(&own).unwrap();

    let removed = launcher.sweep_stale_cgroups().unwrap();
    assert_eq!(removed, vec![stale.clone()]);
    assert!(!stale.exists(), "stale leaf removed");
    assert!(own.exists(), "own leaf kept");
    // Both processes were SIGKILLed by cgroup.kill.
    for s in [&mut s1, &mut s2] {
        let st = s.wait().unwrap();
        assert!(!st.success(), "sleeper killed: {st:?}");
    }

    // Sweeping again finds nothing; a missing group is not an error.
    assert!(launcher.sweep_stale_cgroups().unwrap().is_empty());
    fs::remove_dir(&own).unwrap();
    fs::remove_dir(&gdir).unwrap();
    assert!(
        tessera_launcher::sweep_cgroup_group(Path::new(&root), &group)
            .unwrap()
            .is_empty()
    );
    assert!(tessera_launcher::sweep_cgroup_group(Path::new(&root), "../x").is_err());
}
