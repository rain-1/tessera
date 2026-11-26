//! Development/test front end: runs one command in a Tessera sandbox.
//!
//! ```text
//! tessera-launch-run [--agent LABEL] [--workspace DIR] [--ro-bind HOST:DEST]...
//!     [--env K=V]... [--landlock required|best_effort|disabled]
//!     [--allow-no-cgroup REASON] [--init PATH] [--record] [--broker-echo]
//!     [--model-socket-dir DIR --model-socket PATH [--model-port PORT --netshim PATH]]
//!     -- PROGRAM [ARGS]...
//! ```
//!
//! `--model-socket-dir` is the operator's private (0700) directory of model
//! proxy sockets; `--model-socket` must lie inside it.
//!
//! Exits with the workload's exit code (128+signal if killed), 2 on usage
//! errors, 3 if the launch was refused because a mandatory control is
//! missing (R10) and 4 for any other launch failure.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

use tessera_launcher::{
    AgentLabel, CgroupRequirement, LandlockRequirement, LaunchError, LaunchProfile, Launcher,
    LauncherConfig, LoopbackShim, ModelRoute, StdioMode,
};

fn usage(msg: &str) -> ! {
    eprintln!("tessera-launch-run: {msg}");
    std::process::exit(2);
}

fn main() {
    let mut it = std::env::args_os().skip(1);
    let mut config = LauncherConfig::default();
    let mut agent = "cli".to_string();
    let mut workspace: Option<PathBuf> = None;
    let mut binds = Vec::new();
    let mut env = Vec::new();
    let mut record = false;
    let mut echo = false;
    let mut model_socket: Option<PathBuf> = None;
    let mut model_port: Option<u16> = None;
    let mut netshim: Option<PathBuf> = None;
    let mut cmd: Vec<OsString> = Vec::new();
    let str_arg = |v: Option<OsString>, f: &str| -> String {
        v.and_then(|s| s.into_string().ok())
            .unwrap_or_else(|| usage(&format!("{f} needs a UTF-8 value")))
    };
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--agent") => agent = str_arg(it.next(), "--agent"),
            Some("--workspace") => workspace = Some(str_arg(it.next(), "--workspace").into()),
            Some("--ro-bind") => {
                let v = str_arg(it.next(), "--ro-bind");
                let (h, d) = v
                    .split_once(':')
                    .unwrap_or_else(|| usage("--ro-bind HOST:DEST"));
                binds.push((PathBuf::from(h), PathBuf::from(d)));
            }
            Some("--env") => {
                let v = str_arg(it.next(), "--env");
                let (k, val) = v.split_once('=').unwrap_or_else(|| usage("--env K=V"));
                env.push((k.to_string(), val.to_string()));
            }
            Some("--landlock") => {
                config.landlock = match str_arg(it.next(), "--landlock").as_str() {
                    "required" => LandlockRequirement::Required,
                    "best_effort" => LandlockRequirement::BestEffort,
                    "disabled" => LandlockRequirement::Disabled,
                    _ => usage("bad --landlock"),
                }
            }
            Some("--allow-no-cgroup") => {
                config.cgroup = CgroupRequirement::AllowMissing {
                    operator_reason: str_arg(it.next(), "--allow-no-cgroup"),
                }
            }
            Some("--init") => config.init_path = str_arg(it.next(), "--init").into(),
            Some("--model-socket-dir") => {
                config.model_socket_dir = Some(str_arg(it.next(), "--model-socket-dir").into())
            }
            Some("--model-socket") => {
                model_socket = Some(str_arg(it.next(), "--model-socket").into())
            }
            Some("--model-port") => {
                model_port = Some(
                    str_arg(it.next(), "--model-port")
                        .parse()
                        .unwrap_or_else(|_| usage("bad --model-port")),
                )
            }
            Some("--netshim") => netshim = Some(str_arg(it.next(), "--netshim").into()),
            Some("--record") => record = true,
            Some("--broker-echo") => echo = true,
            Some("--") => {
                cmd = it.collect();
                break;
            }
            _ => usage(&format!("unexpected argument {a:?}")),
        }
    }
    if cmd.is_empty() {
        usage("missing -- PROGRAM");
    }
    let label = AgentLabel::new(agent).unwrap_or_else(|e| usage(&e.to_string()));
    let mut profile = LaunchProfile::new(label, PathBuf::from(&cmd[0]))
        .args(cmd[1..].iter().cloned())
        .stdio(StdioMode::Inherit, StdioMode::Inherit, StdioMode::Inherit);
    if let Some(ws) = workspace {
        profile = profile.workspace(ws);
    }
    for (h, d) in binds {
        profile = profile.ro_bind(h, d);
    }
    for (k, v) in env {
        profile = profile.env(k, v);
    }
    match (model_socket, model_port, netshim) {
        (None, None, None) => {}
        (Some(host_socket), port, shim) => {
            let loopback = match (port, shim) {
                (None, None) => None,
                (Some(port), Some(netshim_path)) => Some(LoopbackShim { port, netshim_path }),
                _ => usage("--model-port and --netshim go together"),
            };
            profile = profile.model_route(ModelRoute {
                host_socket,
                loopback,
            });
        }
        _ => usage("--model-port/--netshim need --model-socket"),
    }
    let fail = |e: LaunchError| -> ! {
        eprintln!("tessera-launch-run: {e}");
        std::process::exit(match e {
            LaunchError::MissingMandatoryControl(_) => 3,
            _ => 4,
        })
    };
    let launcher = Launcher::new(config).unwrap_or_else(|e| fail(e));
    let mut handle = launcher.spawn(&profile).unwrap_or_else(|e| fail(e));
    if record {
        eprintln!(
            "{}",
            serde_json::to_string(handle.record()).expect("serialize record")
        );
    }
    let broker = handle.take_broker_channel();
    if let (true, Some(fd)) = (echo, broker) {
        std::thread::spawn(move || {
            let mut f = File::from(fd);
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = f.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                if f.write_all(&reply).is_err() {
                    break;
                }
            }
        });
    }
    let status = handle.wait().unwrap_or_else(|e| {
        eprintln!("tessera-launch-run: wait: {e}");
        std::process::exit(3)
    });
    std::process::exit(
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
    );
}
