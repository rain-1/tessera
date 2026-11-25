//! `tesserad --config FILE`: the Tessera broker daemon.
//!
//! Opens (or creates) the journal in the broker-owned state directory,
//! recovers, begins a new authority epoch (fail closed), registers the
//! configured endpoints, probes the launcher if launch profiles are
//! configured (refusing to start if a mandatory control is missing, R10),
//! and serves the operator socket. Agents reach the broker only through the
//! per-sandbox channels the launcher creates.
#![forbid(unsafe_code)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;

use tessera_broker::config::DaemonConfig;
use tessera_broker::{
    AdapterExecutor, AuditLog, Broker, BrokerConfig, LauncherSpawner, MonotonicClock,
    SandboxSpawner, Services,
};
use tessera_journal::Journal;
use tessera_launcher::{CgroupRequirement, LandlockRequirement, LauncherConfig};

fn main() {
    if let Err(e) = run() {
        eprintln!("tesserad: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let cfg_path = match (args.next().as_deref(), args.next()) {
        (Some("--config"), Some(p)) => p,
        _ => return Err("usage: tesserad --config FILE".into()),
    };
    let cfg = DaemonConfig::load(cfg_path.as_ref())?;

    // Broker-owned state directory: never group/world accessible.
    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| e.to_string())?;
    let md = std::fs::metadata(&cfg.state_dir).map_err(|e| e.to_string())?;
    if md.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "{} is not owned by the broker user",
            cfg.state_dir.display()
        ));
    }
    if md.mode() & 0o077 != 0 {
        std::fs::set_permissions(&cfg.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }

    let journal = Journal::open(&cfg.state_dir.join("journal")).map_err(|e| e.to_string())?;
    let audit = AuditLog::open(&cfg.state_dir.join("audit.jsonl")).map_err(|e| e.to_string())?;
    let executor = AdapterExecutor::new(cfg.file_root.as_deref())?.shared();

    let spawner: Option<Box<dyn SandboxSpawner>> = if cfg.profiles.is_empty() {
        None
    } else {
        let mut lc = LauncherConfig::default();
        if let Some(p) = &cfg.launcher.bwrap_path {
            lc.bwrap_path = p.clone();
        }
        if let Some(p) = &cfg.launcher.init_path {
            lc.init_path = p.clone();
        }
        if let Some(r) = &cfg.launcher.cgroup_opt_out_reason {
            lc.cgroup = CgroupRequirement::AllowMissing {
                operator_reason: r.clone(),
            };
        }
        lc.landlock = match cfg.launcher.landlock.as_deref() {
            None | Some("required") => LandlockRequirement::Required,
            Some("best_effort") => LandlockRequirement::BestEffort,
            Some("disabled") => LandlockRequirement::Disabled,
            Some(o) => return Err(format!("unknown landlock mode {o:?}")),
        };
        Some(Box::new(
            LauncherSpawner::new(lc, cfg.profiles.clone())
                .map_err(|e| format!("launcher refused to start: {e}"))?,
        ))
    };

    let config = BrokerConfig {
        require_user_verification: cfg.require_user_verification,
        endpoints: cfg.resolved_endpoints()?,
        ..BrokerConfig::default()
    };
    let broker = Broker::start(
        journal,
        config,
        Services {
            executor,
            spawner,
            audit,
            clock: Arc::new(MonotonicClock::default()),
            fault: None,
        },
    )
    .map_err(|e| e.to_string())?;
    broker
        .serve_admin(&cfg.admin_socket)
        .map_err(|e| format!("admin socket: {e}"))?;
    eprintln!(
        "tesserad: serving operator socket {}",
        cfg.admin_socket.display()
    );
    let reason = broker.wait();
    Err(format!("broker stopped: {reason:?}"))
}
