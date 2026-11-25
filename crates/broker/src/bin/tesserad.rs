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

use tessera_broker::admin::prepare_socket_path;
use tessera_broker::config::DaemonConfig;
use tessera_broker::{
    AdapterExecutor, AuditLog, AuditSync, Broker, BrokerConfig, LauncherSpawner, MonotonicClock,
    SandboxSpawner, Services,
};
use tessera_journal::{Journal, JournalOptions, TailPolicy};

const USAGE: &str = "usage: tesserad --config FILE [--truncate-unverifiable-final-record]";
use tessera_launcher::{CgroupRequirement, LandlockRequirement, LauncherConfig};

fn main() {
    if let Err(e) = run() {
        eprintln!("tesserad: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut cfg_path = None;
    let mut tail_policy = TailPolicy::Strict;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => cfg_path = args.next(),
            // Explicit operator override (see TailPolicy): only after
            // investigating a journal that refuses to open.
            "--truncate-unverifiable-final-record" => {
                tail_policy = TailPolicy::TruncateUnverifiableFinalRecord;
            }
            _ => return Err(USAGE.into()),
        }
    }
    let Some(cfg_path) = cfg_path else {
        return Err(USAGE.into());
    };
    let cfg = DaemonConfig::load(cfg_path.as_ref())?;
    cfg.check()?;

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
    let admin_socket =
        prepare_socket_path(&cfg.admin_socket).map_err(|e| format!("admin socket: {e}"))?;

    let journal = Journal::open_with(
        &cfg.state_dir.join("journal"),
        JournalOptions {
            tail_policy,
            ..JournalOptions::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if tail_policy != TailPolicy::Strict {
        let r = journal.recovery_report();
        eprintln!(
            "tesserad: WARNING: journal opened with --truncate-unverifiable-final-record \
             (recovery: {r:?}); an acknowledged record may have been discarded"
        );
    }
    let audit_sync: AuditSync = match &cfg.audit_fsync {
        Some(s) => s.parse()?,
        None => AuditSync::default(),
    };
    let audit = AuditLog::open_with(&cfg.state_dir.join("audit.jsonl"), audit_sync)
        .map_err(|e| e.to_string())?;
    let executor = AdapterExecutor::new(cfg.file_root.as_deref())?.shared();

    let spawner: Option<Box<dyn SandboxSpawner>> = if cfg.profiles.is_empty() {
        None
    } else {
        let mut lc = LauncherConfig::default();
        // Host paths no profile may expose (ancestor or descendant):
        // broker state, protected file root, the admin socket and its
        // directory, broker-held endpoint secrets and CA files, and
        // operator-listed paths such as the model proxy's credential file.
        let endpoint_files = cfg.endpoints.iter().flat_map(|e| {
            e.secret_header
                .iter()
                .map(|s| &s.value_file)
                .chain(&e.ca_pem_file)
        });
        for path in std::iter::once(&cfg.state_dir)
            .chain(&cfg.file_root)
            .chain(endpoint_files)
            .chain(&cfg.launcher.protected_paths)
        {
            lc.protected_host_paths.push(
                path.canonicalize()
                    .map_err(|e| format!("protected path {}: {e}", path.display()))?,
            );
        }
        lc.protected_host_paths.push(admin_socket.clone());
        if let Some(dir) = admin_socket.parent() {
            lc.protected_host_paths.push(dir.to_path_buf());
        }
        if let Some(p) = &cfg.launcher.bwrap_path {
            lc.bwrap_path = p.clone();
        }
        if let Some(p) = &cfg.launcher.init_path {
            lc.init_path = p.clone();
        }
        lc.cgroup_group_name = cfg
            .launcher
            .cgroup_group
            .clone()
            .unwrap_or_else(|| "tesserad".into());
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
        let sp = LauncherSpawner::new(lc, cfg.profiles.clone())
            .map_err(|e| format!("launcher refused to start: {e}"))?;
        // Fail closed: sandboxes of an earlier epoch must not survive.
        let swept = sp
            .sweep_stale_cgroups()
            .map_err(|e| format!("stale sandbox sweep failed, refusing to start: {e}"))?;
        for p in &swept {
            eprintln!(
                "tesserad: killed and removed stale sandbox cgroup {}",
                p.display()
            );
        }
        Some(Box::new(sp))
    };

    let d = BrokerConfig::default();
    let l = &cfg.limits;
    let config = BrokerConfig {
        require_user_verification: cfg.require_user_verification,
        endpoints: cfg.resolved_endpoints()?,
        spawn_profiles: cfg.agent_spawn_profiles.clone(),
        max_children_per_agent: l.max_children_per_agent.unwrap_or(d.max_children_per_agent),
        max_spawn_depth: l.max_spawn_depth.unwrap_or(d.max_spawn_depth),
        max_domain_agents: l.max_domain_agents.unwrap_or(d.max_domain_agents),
        max_in_flight_per_agent: l
            .max_in_flight_per_agent
            .unwrap_or(d.max_in_flight_per_agent),
        agent_rate_per_sec: l.agent_rate_per_sec.unwrap_or(d.agent_rate_per_sec),
        agent_rate_burst: l.agent_rate_burst.unwrap_or(d.agent_rate_burst),
        ledger_quotas: l.ledger_quotas,
        ..d
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
