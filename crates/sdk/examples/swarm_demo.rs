//! `swarm_demo`: a minimal capability-aware harness for the multi-agent
//! research swarm of spec §12.2, from the agents' side.
//!
//! ```text
//! A: request_grant(100 HTTPS requests to endpoint E, depth 2)   [operator approves]
//! A: spawn B, spawn C
//! A: delegate 30 -> B (depth 1), delegate 20 -> C (depth 0)      A keeps 50
//! B: spawn D, delegate 10 -> D (depth 0)                         B keeps 20
//! D: uses 3                                                      100 -> 97 overall
//! ```
//!
//! Every agent is a separate sandbox with its own broker channel
//! (`TESSERA_BROKER_FD`). Each role is one invocation of this binary:
//!
//! ```text
//! swarm_demo coordinator --endpoint 7 --worker-profile 2
//! swarm_demo worker --cap <hex> [--sub-profile 3 --give 10] [--use 0] [--path /search]
//! ```
//!
//! **Handoff.** A delegate learns the child capability id, but the recipient
//! does not: protocol v1 has no message that tells a principal which
//! capabilities it received. Capability ids are references, not secrets, so
//! the coordinator prints `HANDOFF <agent> <cap>` lines. Whatever starts the
//! workers (an operator, or a profile that reads a shared mailbox) passes the
//! id to the worker as `--cap`.
//!
//! The flow functions below take a `Client` each. The SDK test-suite drives
//! them against a mock ledger with four separate channels, to check
//! conservation (100 -> 97) and the effect of revoking B.

#![allow(clippy::print_stdout)]

use tessera_sdk::wire::{WireBudget, WireMethodSet, WireScope};
use tessera_sdk::{AgentId, CapId, Client, Error, HttpsRequest, Terms, format_id, parse_id};

/// Scope: GET requests to one registered endpoint.
pub fn search_scope(endpoint: u64) -> WireScope {
    WireScope::Https {
        endpoint_id: endpoint,
        methods: WireMethodSet {
            get: true,
            ..Default::default()
        },
        max_body_bytes: 0,
    }
}

/// Print and return the remaining balance of `cap` (owner-visible only).
pub fn log_balance(label: &str, client: &Client, cap: CapId) -> Result<u64, Error> {
    let v = client.inspect(cap)?;
    let n = match v.budget_remaining {
        WireBudget::Finite(n) => n,
        WireBudget::Unlimited => u64::MAX,
    };
    println!(
        "[{label}] cap {} root {} remaining {:?} depth {:?} status {:?}",
        format_id(cap),
        format_id(v.root_id),
        v.budget_remaining,
        v.depth,
        v.status
    );
    Ok(n)
}

/// The capabilities A holds or created.
#[derive(Debug, Clone, Copy)]
pub struct Allocation {
    /// A's root grant (keeps the undelegated balance).
    pub root: CapId,
    /// Child given to B.
    pub b: CapId,
    /// Child given to C.
    pub c: CapId,
}

/// Agent A: ask for the root grant and split it between B and C.
pub fn coordinator(a: &Client, endpoint: u64, b: AgentId, c: AgentId) -> Result<Allocation, Error> {
    let scope = search_scope(endpoint);
    println!("[A] requesting 100 HTTPS requests, depth 2: waiting for operator approval…");
    let root = a.request_grant(
        Terms::new(scope, 100).depth(2),
        Some("research swarm: 100 search requests shared by workers"),
    )?;
    log_balance("A", a, root)?;
    let cb = a.delegate(root, b, Terms::new(scope, 30).depth(1))?;
    println!("[A] delegated 30 to B ({b}) as {}", format_id(cb));
    let cc = a.delegate(root, c, Terms::new(scope, 20).depth(0))?;
    println!("[A] delegated 20 to C ({c}) as {}", format_id(cc));
    log_balance("A", a, root)?;
    Ok(Allocation { root, b: cb, c: cc })
}

/// A worker passes `give` of its balance on to `to` with depth 0.
pub fn worker_delegate(
    label: &str,
    w: &Client,
    cap: CapId,
    to: AgentId,
    give: u64,
) -> Result<CapId, Error> {
    let v = w.inspect(cap)?;
    let child = w.delegate(cap, to, Terms::new(v.scope, give).depth(0))?;
    println!("[{label}] delegated {give} to {to} as {}", format_id(child));
    log_balance(label, w, cap)?;
    Ok(child)
}

/// A worker spends `n` units, one HTTPS request each. Stops at the first
/// denial and returns how many requests it issued.
pub fn worker_use(label: &str, w: &Client, cap: CapId, n: u32, path: &str) -> Result<u32, Error> {
    for i in 0..n {
        match w.https_request(cap, HttpsRequest::get(path)) {
            Ok(r) => println!("[{label}] request {} -> HTTP {}", i + 1, r.status),
            Err(e) => {
                println!("[{label}] request {} denied: {e}", i + 1);
                return if i == 0 { Err(e) } else { Ok(i) };
            }
        }
    }
    log_balance(label, w, cap)?;
    Ok(n)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn num(args: &[String], name: &str) -> Result<Option<u64>, String> {
    arg(args, name)
        .map(|v| v.parse().map_err(|_| format!("{name}: not a number: {v}")))
        .transpose()
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: swarm_demo coordinator --endpoint E --worker-profile P\n       \
                 swarm_demo worker --cap CAP [--sub-profile P --give N] [--use N] [--path /p]";
    let role = args.first().ok_or(usage)?;
    let client = Client::from_env().map_err(|e| e.to_string())?;
    match role.as_str() {
        "coordinator" => {
            let endpoint = num(args, "--endpoint")?.ok_or(usage)?;
            let profile = num(args, "--worker-profile")?.ok_or(usage)?;
            let b = client.spawn(profile).map_err(|e| e.to_string())?;
            let c = client.spawn(profile).map_err(|e| e.to_string())?;
            println!("[A] spawned B = {b}, C = {c}");
            let alloc = coordinator(&client, endpoint, b, c).map_err(|e| e.to_string())?;
            println!("HANDOFF {b} {}", format_id(alloc.b));
            println!("HANDOFF {c} {}", format_id(alloc.c));
        }
        "worker" => {
            let cap = parse_id(&arg(args, "--cap").ok_or(usage)?).map_err(|e| e.to_string())?;
            let path = arg(args, "--path").unwrap_or_else(|| "/".into());
            log_balance("W", &client, cap).map_err(|e| e.to_string())?;
            if let (Some(p), Some(give)) = (num(args, "--sub-profile")?, num(args, "--give")?) {
                let d = client.spawn(p).map_err(|e| e.to_string())?;
                println!("[W] spawned sub-worker {d}");
                let child =
                    worker_delegate("W", &client, cap, d, give).map_err(|e| e.to_string())?;
                println!("HANDOFF {d} {}", format_id(child));
            }
            let n = u32::try_from(num(args, "--use")?.unwrap_or(0)).map_err(|e| e.to_string())?;
            worker_use("W", &client, cap, n, &path).map_err(|e| e.to_string())?;
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("swarm_demo: {e}");
        std::process::exit(1);
    }
}
