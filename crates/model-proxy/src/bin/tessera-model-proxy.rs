//! `tessera-model-proxy --config FILE [--check]`
//!
//! Trusted host-side model API proxy for Tessera compatibility mode. See the
//! library documentation and `docs/compat.md`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use tessera_model_proxy::{Credential, ModelProxy, ProxyConfig, Upstream, audit};

const USAGE: &str = "usage: tessera-model-proxy --config FILE [--check]";

fn main() -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut check = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--config") => config = args.next().map(PathBuf::from),
            Some("--check") => check = true,
            Some("-h" | "--help") => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(config) = config else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(config, check) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tessera-model-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: PathBuf, check: bool) -> Result<(), String> {
    let cfg = ProxyConfig::from_file(&path).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    let credential = Credential::from_file(&cfg.credential.file, cfg.credential.inject)?;
    let upstream = Upstream::new(&cfg.upstream).map_err(|e| e.to_string())?;
    let sink = match &cfg.audit_log {
        Some(p) => audit::file_sink(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => audit::stderr_sink(),
    };
    let proxy = ModelProxy::new(&cfg, credential, upstream, sink).map_err(|e| e.to_string())?;
    if check {
        println!("configuration OK");
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let mut tasks = Vec::new();
        for s in &cfg.sandboxes {
            let l = proxy
                .bind(s)
                .map_err(|e| format!("{}: {e}", s.socket.display()))?;
            eprintln!(
                "tessera-model-proxy: sandbox {} listening on {} -> {}:{}",
                l.label(),
                l.path().display(),
                cfg.upstream.host,
                cfg.upstream.port
            );
            let p = proxy.clone();
            tasks.push(tokio::spawn(async move { p.serve(l).await }));
        }
        for t in tasks {
            match t.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.to_string()),
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    })
}
