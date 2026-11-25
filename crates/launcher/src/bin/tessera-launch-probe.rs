//! Prints the host feature report as JSON, plus the R10 evaluation under the
//! default (strict) policy. Exit status: 0 if a default launcher could start,
//! 2 if a mandatory control is missing.
#![forbid(unsafe_code)]

use tessera_launcher::{FeatureReport, LauncherConfig};

fn main() {
    let config = LauncherConfig::default();
    let report = FeatureReport::probe(&config);
    let missing = report.missing_mandatory(&config.cgroup, config.landlock);
    let out = serde_json::json!({
        "tessera_launcher_version": env!("CARGO_PKG_VERSION"),
        "policy": {
            "cgroup": config.cgroup,
            "landlock": config.landlock,
            "min_bwrap_version": tessera_launcher::MIN_BWRAP_VERSION,
            "required_landlock_abi": tessera_launcher::REQUIRED_LANDLOCK_ABI,
        },
        "report": report,
        "launch_allowed": missing.is_empty(),
        "missing_mandatory": missing,
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("serialize"));
    std::process::exit(if missing.is_empty() { 0 } else { 2 });
}
