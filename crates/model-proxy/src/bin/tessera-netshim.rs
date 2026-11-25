//! `tessera-netshim --listen 127.0.0.1:PORT --socket PATH [-- PROGRAM ARGS...]`
//!
//! In-sandbox loopback-to-Unix-socket forwarder (untrusted plumbing). With a
//! program, the shim binds first, then runs the program and exits with its
//! status; without one it forwards until killed.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use tessera_model_proxy::shim;

const USAGE: &str =
    "usage: tessera-netshim --listen 127.0.0.1:PORT --socket PATH [-- PROGRAM [ARGS...]]";

fn main() -> ExitCode {
    let mut listen: Option<SocketAddr> = None;
    let mut socket: Option<PathBuf> = None;
    let mut program: Vec<OsString> = Vec::new();
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--listen") => listen = args.next().and_then(|v| v.to_str()?.parse().ok()),
            Some("--socket") => socket = args.next().map(PathBuf::from),
            Some("--") => {
                program.extend(args.by_ref());
                break;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(listen), Some(socket)) = (listen, socket) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tessera-netshim: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let listener = match shim::bind_loopback(listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tessera-netshim: bind {listen}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let forward = tokio::spawn(shim::run(listener, socket));
        let Some((prog, rest)) = program.split_first() else {
            let _ = forward.await;
            return ExitCode::FAILURE;
        };
        let status = tokio::process::Command::new(prog).args(rest).status().await;
        forward.abort();
        match status {
            Ok(s) => match s.code() {
                Some(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
                None => ExitCode::from(128 + 9),
            },
            Err(e) => {
                eprintln!("tessera-netshim: {}: {e}", prog.to_string_lossy());
                ExitCode::from(127)
            }
        }
    })
}
