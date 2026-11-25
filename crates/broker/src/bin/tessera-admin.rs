//! `tessera-admin`: the operator CLI for the broker's admin socket.
//!
//! Approval: `tessera-admin approve TICKET` shows the broker-normalized
//! request, recomputes its digest locally and checks it against the
//! challenge, asks for confirmation, then obtains the FIDO2 assertion from
//! the configured authenticator (`--key FILE`: development software key;
//! `--fido2 DEVICE`: hardware token via libfido2 tools, feature `fido2-cli`,
//! untested against hardware) and submits it. The broker verifies it and
//! mints exactly the signed request.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use tessera_approval as ap;
use tessera_approval::Authenticator;
use tessera_broker::admin::{AdminClient, AdminRequest, AdminResponse, CapView};
use tessera_broker::convert::{hex, parse_agent};
use tessera_broker::softkey::FileAuthenticator;
use tessera_capability_core::AgentId;
use tessera_protocol::{WireBudget, WireDepth, WireFileRights, WireScope};

const USAGE: &str = "\
usage: tessera-admin [--socket PATH] <command>

  status | principals | tree | accounts | checkpoint | emergency-stop
  enroll (--key FILE | --fido2 DEVICE) [--rp-id ID] [--operator HEX]
  register-file NAME [--max-read N] [--max-write N]
  register-endpoint ID --spec FILE.json
  create-principal PROFILE
  terminate AGENT
  baseline AGENT --file OBJ [--rights read,replace] --budget N|unlimited [--depth N] [--expiry-ms N]
  pending
  approve TICKET (--key FILE | --fido2 DEVICE) [--budget N] [--depth N] [--yes]
  deny TICKET
  revoke CAP | inspect CAP | lineage CAP
  reservations [--uncertain]
  audit [--since N] [--limit N]
  audit checkpoint                      print SEQ:HASH of the last audit event (keep it off-host)
  audit verify --file PATH [--checkpoint SEQ:HASH]
                                        verify the audit hash chain offline (no broker needed)

AGENT is e<epoch>.s<serial> or <epoch-hex>:<serial>; CAP is hex.
The socket defaults to $TESSERA_ADMIN_SOCKET or /run/tessera/admin.sock.
";

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("tessera-admin: {e}");
            std::process::exit(1);
        }
    }
}

struct Args {
    pos: Vec<String>,
    opts: BTreeMap<String, String>,
    flags: Vec<String>,
}

fn parse_args() -> Args {
    let mut pos = Vec::new();
    let mut opts = BTreeMap::new();
    let mut flags = Vec::new();
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if matches!(name, "yes" | "uncertain" | "json") {
                flags.push(name.to_owned());
            } else if let Some(v) = it.next() {
                opts.insert(name.to_owned(), v);
            }
        } else {
            pos.push(a);
        }
    }
    Args { pos, opts, flags }
}

fn agent(s: &str) -> Result<AgentId, String> {
    if let Some(a) = parse_agent(s) {
        return Ok(a);
    }
    let (e, n) = s.split_once(':').ok_or("bad AGENT")?;
    Ok(AgentId::new(
        u64::from_str_radix(e, 16).map_err(|_| "bad AGENT epoch")?,
        n.parse().map_err(|_| "bad AGENT serial")?,
    ))
}

fn cap(s: &str) -> Result<u128, String> {
    let t = s.trim_start_matches("0x");
    u128::from_str_radix(t, 16).map_err(|_| format!("{s:?} is not a hex capability id"))
}

fn num(o: &BTreeMap<String, String>, k: &str) -> Result<Option<u64>, String> {
    o.get(k)
        .map(|v| v.parse().map_err(|_| format!("--{k}: not a number")))
        .transpose()
}

fn authenticator(o: &BTreeMap<String, String>) -> Result<Box<dyn Authenticator>, String> {
    if let Some(k) = o.get("key") {
        eprintln!("WARNING: software authenticator ({k}); no physical presence is proven");
        return Ok(Box::new(
            FileAuthenticator::open(k.as_ref()).map_err(|e| e.to_string())?,
        ));
    }
    if let Some(_d) = o.get("fido2") {
        #[cfg(feature = "fido2-cli")]
        return Ok(Box::new(ap::authenticator::Fido2CliAuthenticator::new(_d)));
        #[cfg(not(feature = "fido2-cli"))]
        return Err("built without the fido2-cli feature".into());
    }
    Err("give --key FILE or --fido2 DEVICE".into())
}

fn call(c: &mut AdminClient, r: AdminRequest) -> Result<AdminResponse, String> {
    match c.call(&r).map_err(|e| e.to_string())? {
        AdminResponse::Error(e) => Err(e),
        ok => Ok(ok),
    }
}

fn run() -> Result<(), String> {
    let a = parse_args();
    let socket: PathBuf = a
        .opts
        .get("socket")
        .cloned()
        .or_else(|| std::env::var("TESSERA_ADMIN_SOCKET").ok())
        .unwrap_or_else(|| "/run/tessera/admin.sock".into())
        .into();
    let Some(cmd) = a.pos.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(());
    };
    let arg = |i: usize| {
        a.pos
            .get(i)
            .map(String::as_str)
            .ok_or(format!("{cmd}: missing argument"))
    };
    if cmd == "audit" && a.pos.get(1).map(String::as_str) == Some("verify") {
        return audit_verify(&a.opts);
    }
    let mut c = AdminClient::connect(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    let o = &a.opts;
    let out = match cmd {
        "status" => call(&mut c, AdminRequest::Status)?,
        "principals" => call(&mut c, AdminRequest::ListPrincipals)?,
        "tree" => call(&mut c, AdminRequest::Tree)?,
        "accounts" => call(&mut c, AdminRequest::Accounts)?,
        "checkpoint" => call(&mut c, AdminRequest::Checkpoint)?,
        "emergency-stop" => call(&mut c, AdminRequest::EmergencyStop)?,
        "pending" => call(&mut c, AdminRequest::ListPending)?,
        "enroll" => {
            let mut auth = authenticator(o)?;
            let operator = match o.get("operator") {
                Some(h) => u128::from_str_radix(h, 16).map_err(|_| "--operator: hex")?,
                None => {
                    let mut b = [0u8; 16];
                    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
                    u128::from_be_bytes(b)
                }
            };
            let req = ap::CredentialRequest {
                rp_id: o
                    .get("rp-id")
                    .cloned()
                    .unwrap_or_else(|| "tessera.local".into()),
                operator: ap::OperatorId(operator),
                user_name: "tessera-operator".into(),
                algorithm: ap::CoseAlgorithm::Es256,
                require_user_verification: false,
            };
            let e = ap::enroll(auth.as_mut(), &req).map_err(|e| e.to_string())?;
            call(
                &mut c,
                AdminRequest::Enroll {
                    enrollment: e.encode(),
                },
            )?
        }
        "register-file" => call(
            &mut c,
            AdminRequest::RegisterFile {
                name: arg(1)?.into(),
                max_read_bytes: num(o, "max-read")?.unwrap_or(64 * 1024),
                max_write_bytes: num(o, "max-write")?.unwrap_or(64 * 1024),
            },
        )?,
        "register-endpoint" => {
            let id = arg(1)?.parse().map_err(|_| "ID: number")?;
            let f = o.get("spec").ok_or("--spec FILE")?;
            let s = std::fs::read_to_string(f).map_err(|e| e.to_string())?;
            let spec = serde_json::from_str(&s).map_err(|e| e.to_string())?;
            call(&mut c, AdminRequest::RegisterEndpoint { id, spec })?
        }
        "create-principal" => call(
            &mut c,
            AdminRequest::CreatePrincipal {
                profile: arg(1)?.into(),
            },
        )?,
        "terminate" => call(
            &mut c,
            AdminRequest::TerminatePrincipal {
                agent: agent(arg(1)?)?,
            },
        )?,
        "baseline" => {
            let rights = o.get("rights").map(String::as_str).unwrap_or("read");
            let scope = WireScope::File {
                object_id: num(o, "file")?.ok_or("--file OBJ")?,
                rights: WireFileRights {
                    read_snapshot: rights.split(',').any(|r| r == "read"),
                    replace_content: rights.split(',').any(|r| r == "replace"),
                },
            };
            let budget = match o.get("budget").map(String::as_str) {
                Some("unlimited") => WireBudget::Unlimited,
                Some(n) => WireBudget::Finite(n.parse().map_err(|_| "--budget")?),
                None => return Err("--budget N|unlimited".into()),
            };
            call(
                &mut c,
                AdminRequest::InstallBaseline {
                    agent: agent(arg(1)?)?,
                    scope,
                    budget,
                    depth: WireDepth::Finite(
                        num(o, "depth")?
                            .unwrap_or(0)
                            .try_into()
                            .map_err(|_| "--depth")?,
                    ),
                    expiry_ms: num(o, "expiry-ms")?,
                },
            )?
        }
        "approve" => approve(&mut c, arg(1)?, o, a.flags.iter().any(|f| f == "yes"))?,
        "deny" => call(
            &mut c,
            AdminRequest::Deny {
                ticket: arg(1)?.parse().map_err(|_| "TICKET: number")?,
            },
        )?,
        "revoke" => call(
            &mut c,
            AdminRequest::Revoke {
                capability: cap(arg(1)?)?,
            },
        )?,
        "inspect" => call(
            &mut c,
            AdminRequest::Inspect {
                capability: cap(arg(1)?)?,
            },
        )?,
        "lineage" => call(
            &mut c,
            AdminRequest::Lineage {
                capability: cap(arg(1)?)?,
            },
        )?,
        "reservations" => call(
            &mut c,
            AdminRequest::Reservations {
                only_uncertain: a.flags.iter().any(|f| f == "uncertain"),
            },
        )?,
        "audit" if a.pos.get(1).map(String::as_str) == Some("checkpoint") => {
            call(&mut c, AdminRequest::AuditCheckpoint)?
        }
        "audit" => call(
            &mut c,
            AdminRequest::Audit {
                since: num(o, "since")?.unwrap_or(0),
                limit: num(o, "limit")?.unwrap_or(100).min(10_000) as u32,
            },
        )?,
        _ => return Err(format!("unknown command {cmd:?}\n{USAGE}")),
    };
    print_response(&out);
    Ok(())
}

fn audit_verify(o: &BTreeMap<String, String>) -> Result<(), String> {
    use tessera_broker::audit::{AuditCheckpoint, verify_file};
    let file = o.get("file").ok_or("audit verify: --file PATH")?;
    let cp = o
        .get("checkpoint")
        .map(|c| AuditCheckpoint::parse(c))
        .transpose()?;
    let v = verify_file(file.as_ref(), cp)?;
    println!(
        "ok: {} events, chain intact{}{}",
        v.events,
        match v.head {
            Some(h) => format!(", head {h}"),
            None => String::new(),
        },
        match cp {
            Some(c) => format!(", checkpoint {} matches", c.seq),
            None => ", no external checkpoint given (prefix rewrite undetectable)".into(),
        }
    );
    if v.torn_tail_bytes > 0 {
        println!(
            "note: {} bytes of a torn final line ignored",
            v.torn_tail_bytes
        );
    }
    Ok(())
}

fn active_pending(
    c: &mut AdminClient,
    ticket: u64,
) -> Result<tessera_broker::admin::PendingView, String> {
    let AdminResponse::Pending(p) = call(c, AdminRequest::ListPending)? else {
        return Err("unexpected response".into());
    };
    p.into_iter()
        .find(|p| p.ticket == ticket && p.active)
        .ok_or(format!("ticket {ticket} is not awaiting a touch"))
}

fn approve(
    c: &mut AdminClient,
    ticket: &str,
    o: &BTreeMap<String, String>,
    yes: bool,
) -> Result<AdminResponse, String> {
    let ticket: u64 = ticket.parse().map_err(|_| "TICKET: number")?;
    // Optional narrowing (never widening; the broker re-checks).
    if o.contains_key("budget") || o.contains_key("depth") {
        let pv = active_pending(c, ticket)?;
        let req = ap::GrantRequest::decode(&pv.request).map_err(|e| format!("{e:?}"))?;
        let mut f = req.fields().clone();
        if let Some(b) = num(o, "budget")? {
            f.budget.amount = ap::BudgetAmount::Finite(b);
        }
        if let Some(d) = num(o, "depth")? {
            f.depth = ap::Depth::Finite(d.try_into().map_err(|_| "--depth")?);
        }
        let n = ap::GrantRequest::new(f).map_err(|e| e.to_string())?;
        call(
            c,
            AdminRequest::Narrow {
                ticket,
                request: n.encode(),
            },
        )?;
    }
    let AdminResponse::Challenge(ch) = call(c, AdminRequest::Challenge { ticket })? else {
        return Err("unexpected response".into());
    };
    let pv = active_pending(c, ticket)?;
    let shown = ap::GrantRequest::decode(&pv.request).map_err(|e| format!("{e:?}"))?;
    if pv.request != ch.request || shown.digest().0 != ch.client_data_hash {
        return Err("challenge digest does not match the request shown; refusing".into());
    }
    // The broker renders these exact terms using its epoch-relative clock.
    print!("{}", pv.rendered);
    println!("digest: {}", hex(&ch.client_data_hash));
    if !yes {
        print!("Approve exactly this grant? Type 'yes': ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if line.trim() != "yes" {
            return call(c, AdminRequest::Deny { ticket });
        }
    }
    let mut auth = authenticator(o)?;
    let asr = auth
        .get_assertion(&ap::AssertionRequest {
            rp_id: ch.rp_id,
            client_data_hash: ch.client_data_hash,
            credential_id: ch.credential_id,
            require_user_verification: ch.require_user_verification,
        })
        .map_err(|e| e.to_string())?;
    call(
        c,
        AdminRequest::Approve {
            ticket,
            credential_id: asr.credential_id,
            authenticator_data: asr.authenticator_data,
            signature: asr.signature,
        },
    )
}

fn print_tree(caps: &[CapView]) {
    let ids: std::collections::BTreeSet<u128> = caps.iter().map(|c| c.id).collect();
    let mut children: BTreeMap<Option<u128>, Vec<&CapView>> = BTreeMap::new();
    for c in caps {
        // Nodes whose parent is not in the list are shown as roots.
        let p = c.parent.filter(|p| ids.contains(p));
        children.entry(p).or_default().push(c);
    }
    fn walk(n: &CapView, depth: usize, ch: &BTreeMap<Option<u128>, Vec<&CapView>>) {
        println!(
            "{}{}cap {:x}  owner e{}.s{}  {}  budget {}  depth {}  expiry {}  [{}{}]",
            "  ".repeat(depth),
            if depth == 0 { "" } else { "└─ " },
            n.id,
            n.owner.epoch(),
            n.owner.serial(),
            n.scope,
            n.budget,
            n.depth,
            n.expiry,
            n.status,
            if n.parent.is_none() {
                format!(", {} root {:x}", n.root_kind, n.root)
            } else {
                String::new()
            }
        );
        for c in ch.get(&Some(n.id)).into_iter().flatten() {
            walk(c, depth + 1, ch);
        }
    }
    for r in children.get(&None).into_iter().flatten() {
        walk(r, 0, &children);
    }
}

fn print_response(r: &AdminResponse) {
    match r {
        AdminResponse::Ok => println!("ok"),
        AdminResponse::Error(e) => println!("error: {e}"),
        AdminResponse::Object(o) => println!("id {o}"),
        AdminResponse::Agent(a) => println!(
            "agent e{}.s{} ({:032x}:{})",
            a.epoch(),
            a.serial(),
            a.epoch(),
            a.serial()
        ),
        AdminResponse::Capability(c) => println!("capability {c:x}"),
        AdminResponse::Caps(c) => print_tree(c),
        AdminResponse::Pending(p) => {
            for v in p {
                println!(
                    "ticket {} ({}) from e{}.s{}\n{}",
                    v.ticket,
                    if v.active { "awaiting touch" } else { "queued" },
                    v.agent.epoch(),
                    v.agent.serial(),
                    v.rendered
                );
            }
            if p.is_empty() {
                println!("no pending approvals");
            }
        }
        AdminResponse::AuditCheckpoint { seq, hash } => println!("{seq}:{hash}"),
        AdminResponse::Audit(ev) => {
            for e in ev {
                println!("{}", serde_json::to_string(e).unwrap_or_default());
            }
        }
        other => println!(
            "{}",
            serde_json::to_string_pretty(other).unwrap_or_else(|_| format!("{other:?}"))
        ),
    }
}
