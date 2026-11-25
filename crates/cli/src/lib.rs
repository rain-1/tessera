//! `tessera`: the in-sandbox agent CLI.
//!
//! A thin, **untrusted** front end over [`tessera_sdk`]. It talks to the
//! broker over the sandbox's channel (`TESSERA_BROKER_FD`) and can only ask.
//! It has no access to authority storage and sends no identity claim.
//!
//! Exit codes: `0` success; `1` the broker denied or failed the request;
//! `2` usage error; `3` outcome uncertain (timeout or lost channel; retry
//! with `--request-id`); `4` other failure (protocol, configuration, I/O).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};
use tessera_sdk::wire::{
    HttpMethod, WireBudget, WireCapStatus, WireDepth, WireExpiry, WireFileRights, WireMethodSet,
    WireReservationStatus, WireScope,
};
use tessera_sdk::{
    AgentId, CapId, CapabilityView, Client, ClientConfig, Consumed, Error, HttpsRequest, RequestId,
    Terms, format_id, parse_id,
};

/// Usage text.
pub const USAGE: &str = "\
usage: tessera [--json] [--timeout SECS] [--approval-timeout SECS] <command> [options]

commands:
  request   ask the operator for a new capability (blocks until approved/denied)
            SCOPE TERMS [--description TEXT]
  read      read one bounded snapshot of a file      --cap CAP [--max-bytes N] [--out FILE]
  replace   atomically replace a file's content      --cap CAP (--from FILE | --stdin)
  http      issue one HTTPS request                  --cap CAP [--method M] [--path P]
            [-H 'Name: value']... [--data TEXT | --data-file FILE] [--out FILE]
  delegate  give a child capability to an agent      --cap CAP --to AGENT SCOPE TERMS
  attenuate shrink a capability in place             --cap CAP SCOPE TERMS
  transfer  move a capability to another agent       --cap CAP --to AGENT
  drop      discard a capability's remaining balance --cap CAP
  inspect   show a capability you own                --cap CAP
  spawn     launch a child sandbox (trusted profile) --profile N
  revoke    revoke a capability subtree (revokers)   --cap CAP

SCOPE: --file OBJECT_ID [--rights read,replace]
     | --https ENDPOINT_ID [--methods get,head,post,put,patch,delete] [--max-body BYTES]
TERMS: --budget N|unlimited [--depth N|unlimited] [--expiry inherit|DURATION]
       DURATION: e.g. 90s, 5m, 2h, 1500ms

Every mutating command accepts --request-id HEX. Repeating a command with
the same request id never performs the effect twice: the broker reports the
status of the earlier request instead. After a timeout, retry with the id
that was printed.

CAP and request ids are hex. AGENT is <epoch-hex>:<serial>, as printed by spawn.
";

/// Exit codes.
pub mod exit {
    /// Success.
    pub const OK: i32 = 0;
    /// Broker denial or failure.
    pub const DENIED: i32 = 1;
    /// Usage error.
    pub const USAGE: i32 = 2;
    /// Outcome uncertain.
    pub const UNCERTAIN: i32 = 3;
    /// Other failure.
    pub const FAILURE: i32 = 4;
}

/// Where request bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A file.
    File(PathBuf),
    /// Standard input.
    Stdin,
    /// Inline text.
    Inline(Vec<u8>),
}

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `request`
    Request {
        /// Terms.
        terms: Terms,
        /// Untrusted description.
        description: Option<String>,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `read`
    Read {
        /// Capability.
        cap: CapId,
        /// Upper bound.
        max_bytes: u64,
        /// Output file (default stdout).
        out: Option<PathBuf>,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `replace`
    Replace {
        /// Capability.
        cap: CapId,
        /// New content.
        source: Source,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `http`
    Http {
        /// Capability.
        cap: CapId,
        /// Method.
        method: HttpMethod,
        /// Path.
        path: String,
        /// Headers.
        headers: Vec<(String, Vec<u8>)>,
        /// Body.
        body: Option<Source>,
        /// Output file (default stdout).
        out: Option<PathBuf>,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `delegate`
    Delegate {
        /// Parent.
        cap: CapId,
        /// Recipient.
        to: AgentId,
        /// Child terms.
        terms: Terms,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `attenuate`
    Attenuate {
        /// Capability.
        cap: CapId,
        /// Reduced terms.
        terms: Terms,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `transfer`
    Transfer {
        /// Capability.
        cap: CapId,
        /// Recipient.
        to: AgentId,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `drop`
    Drop {
        /// Capability.
        cap: CapId,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `inspect`
    Inspect {
        /// Capability.
        cap: CapId,
    },
    /// `spawn`
    Spawn {
        /// Launch profile.
        profile: u64,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `revoke`
    Revoke {
        /// Capability.
        cap: CapId,
        /// Explicit request id.
        request_id: Option<RequestId>,
    },
    /// `help`
    Help,
}

/// Global options plus command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Machine-readable output.
    pub json: bool,
    /// Override for ordinary calls.
    pub timeout: Option<Duration>,
    /// Override for `request`.
    pub approval_timeout: Option<Duration>,
    /// Command.
    pub command: Command,
}

/// Usage error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

type Parse<T> = Result<T, UsageError>;

fn usage<T>(msg: impl Into<String>) -> Parse<T> {
    Err(UsageError(msg.into()))
}

/// Remaining arguments of a subcommand, consumed by name.
struct Opts {
    args: Vec<(String, Option<String>)>,
}

impl Opts {
    /// Pair each `--flag` with its value. Flags listed in `switches` take
    /// none.
    fn new(raw: &[String], switches: &[&str]) -> Parse<Self> {
        let mut args = Vec::new();
        let mut it = raw.iter();
        while let Some(a) = it.next() {
            if !a.starts_with('-') {
                return usage(format!("unexpected argument {a:?}"));
            }
            if switches.contains(&a.as_str()) {
                args.push((a.clone(), None));
            } else {
                let v = it
                    .next()
                    .ok_or_else(|| UsageError(format!("{a} needs a value")))?;
                args.push((a.clone(), Some(v.clone())));
            }
        }
        Ok(Self { args })
    }

    fn take(&mut self, name: &str) -> Parse<Option<String>> {
        let matches: Vec<usize> = (0..self.args.len())
            .filter(|i| self.args[*i].0 == name)
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [i] => Ok(self.args.remove(*i).1),
            _ => usage(format!("{name} given more than once")),
        }
    }

    fn take_all(&mut self, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        self.args.retain(|(n, v)| {
            if n == name {
                out.extend(v.clone());
                false
            } else {
                true
            }
        });
        out
    }

    fn switch(&mut self, name: &str) -> bool {
        let before = self.args.len();
        self.args.retain(|(n, _)| n != name);
        before != self.args.len()
    }

    fn need(&mut self, name: &str) -> Parse<String> {
        self.take(name)?
            .ok_or_else(|| UsageError(format!("missing {name}")))
    }

    fn finish(self) -> Parse<()> {
        match self.args.first() {
            None => Ok(()),
            Some((n, _)) => usage(format!("unknown or misplaced option {n}")),
        }
    }

    fn cap(&mut self) -> Parse<CapId> {
        id(&self.need("--cap")?)
    }

    fn request_id(&mut self) -> Parse<Option<RequestId>> {
        self.take("--request-id")?.map(|s| id(&s)).transpose()
    }

    fn agent(&mut self) -> Parse<AgentId> {
        self.need("--to")?
            .parse()
            .map_err(|e: Error| UsageError(e.to_string()))
    }
}

fn id(s: &str) -> Parse<u128> {
    parse_id(s).map_err(|e| UsageError(e.to_string()))
}

fn number(name: &str, s: &str) -> Parse<u64> {
    s.parse()
        .map_err(|_| UsageError(format!("{name}: {s:?} is not a non-negative integer")))
}

/// Parse `90s`, `5m`, `2h`, `1500ms` or bare seconds.
pub fn parse_duration(s: &str) -> Parse<Duration> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else {
        (s, 1000)
    };
    let n = number("duration", num)?;
    n.checked_mul(mult)
        .map(Duration::from_millis)
        .ok_or_else(|| UsageError(format!("duration {s:?} too large")))
}

fn parse_method(s: &str) -> Parse<HttpMethod> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "HEAD" => HttpMethod::Head,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        _ => return usage(format!("unsupported HTTP method {s:?}")),
    })
}

fn scope(o: &mut Opts) -> Parse<WireScope> {
    match (o.take("--file")?, o.take("--https")?) {
        (Some(obj), None) => {
            let mut rights = WireFileRights::default();
            let list = o.take("--rights")?.unwrap_or_else(|| "read".into());
            for r in list.split(',') {
                match r.trim() {
                    "read" => rights.read_snapshot = true,
                    "replace" => rights.replace_content = true,
                    other => return usage(format!("unknown file right {other:?}")),
                }
            }
            Ok(WireScope::File {
                object_id: number("--file", &obj)?,
                rights,
            })
        }
        (None, Some(ep)) => {
            let mut methods = WireMethodSet::default();
            let list = o.take("--methods")?.unwrap_or_else(|| "get".into());
            for m in list.split(',') {
                match parse_method(m.trim())? {
                    HttpMethod::Get => methods.get = true,
                    HttpMethod::Head => methods.head = true,
                    HttpMethod::Post => methods.post = true,
                    HttpMethod::Put => methods.put = true,
                    HttpMethod::Patch => methods.patch = true,
                    HttpMethod::Delete => methods.delete = true,
                }
            }
            let max_body_bytes = match o.take("--max-body")? {
                Some(v) => number("--max-body", &v)?,
                None => 0,
            };
            Ok(WireScope::Https {
                endpoint_id: number("--https", &ep)?,
                methods,
                max_body_bytes,
            })
        }
        (None, None) => usage("missing scope: --file OBJECT_ID or --https ENDPOINT_ID"),
        (Some(_), Some(_)) => usage("give exactly one of --file and --https"),
    }
}

fn terms(o: &mut Opts) -> Parse<Terms> {
    let scope = scope(o)?;
    let budget = match o.need("--budget")?.as_str() {
        "unlimited" => WireBudget::Unlimited,
        n => WireBudget::Finite(number("--budget", n)?),
    };
    let depth = match o.take("--depth")?.as_deref() {
        None => WireDepth::Finite(0),
        Some("unlimited") => WireDepth::Unlimited,
        Some(n) => WireDepth::Finite(
            u32::try_from(number("--depth", n)?)
                .map_err(|_| UsageError("--depth too large".into()))?,
        ),
    };
    let expiry = match o.take("--expiry")?.as_deref() {
        None | Some("inherit") => WireExpiry::Inherit,
        Some(d) => WireExpiry::WithinMillis(
            u64::try_from(parse_duration(d)?.as_millis())
                .map_err(|_| UsageError("--expiry too large".into()))?,
        ),
    };
    Ok(Terms {
        scope,
        budget,
        depth,
        expiry,
    })
}

fn header(s: &str) -> Parse<(String, Vec<u8>)> {
    let (n, v) = s
        .split_once(':')
        .ok_or_else(|| UsageError(format!("header {s:?} must look like 'Name: value'")))?;
    Ok((n.trim().to_string(), v.trim_start().as_bytes().to_vec()))
}

/// Parse a full command line (without the program name).
pub fn parse(args: &[String]) -> Parse<Invocation> {
    let mut json = false;
    let mut timeout = None;
    let mut approval_timeout = None;
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        match args[i].as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                return Ok(Invocation {
                    json,
                    timeout,
                    approval_timeout,
                    command: Command::Help,
                });
            }
            flag @ ("--timeout" | "--approval-timeout") => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| UsageError(format!("{flag} needs a value")))?;
                let d = Some(parse_duration(v)?);
                if flag == "--timeout" {
                    timeout = d;
                } else {
                    approval_timeout = d;
                }
            }
            other => return usage(format!("unknown option {other}")),
        }
        i += 1;
    }
    let Some(cmd) = args.get(i) else {
        return usage("missing command");
    };
    let rest = &args[i + 1..];
    let command = match cmd.as_str() {
        "help" => Command::Help,
        "request" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Request {
                terms: terms(&mut o)?,
                description: o.take("--description")?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "read" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Read {
                cap: o.cap()?,
                max_bytes: match o.take("--max-bytes")? {
                    Some(v) => number("--max-bytes", &v)?,
                    None => 1024 * 1024,
                },
                out: o.take("--out")?.map(PathBuf::from),
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "replace" => {
            let mut o = Opts::new(rest, &["--stdin"])?;
            let cap = o.cap()?;
            let source = match (o.take("--from")?, o.switch("--stdin")) {
                (Some(f), false) => Source::File(f.into()),
                (None, true) => Source::Stdin,
                _ => return usage("give exactly one of --from FILE and --stdin"),
            };
            let c = Command::Replace {
                cap,
                source,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "http" => {
            let mut o = Opts::new(rest, &[])?;
            let cap = o.cap()?;
            let method = parse_method(&o.take("--method")?.unwrap_or_else(|| "GET".into()))?;
            let path = o.take("--path")?.unwrap_or_else(|| "/".into());
            let mut hs = o.take_all("-H");
            hs.extend(o.take_all("--header"));
            let headers = hs.iter().map(|h| header(h)).collect::<Parse<Vec<_>>>()?;
            let body = match (o.take("--data")?, o.take("--data-file")?) {
                (Some(d), None) => Some(Source::Inline(d.into_bytes())),
                (None, Some(f)) => Some(if f == "-" {
                    Source::Stdin
                } else {
                    Source::File(f.into())
                }),
                (None, None) => None,
                _ => return usage("give at most one of --data and --data-file"),
            };
            let c = Command::Http {
                cap,
                method,
                path,
                headers,
                body,
                out: o.take("--out")?.map(PathBuf::from),
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "delegate" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Delegate {
                cap: o.cap()?,
                to: o.agent()?,
                terms: terms(&mut o)?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "attenuate" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Attenuate {
                cap: o.cap()?,
                terms: terms(&mut o)?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "transfer" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Transfer {
                cap: o.cap()?,
                to: o.agent()?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "drop" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Drop {
                cap: o.cap()?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "inspect" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Inspect { cap: o.cap()? };
            o.finish()?;
            c
        }
        "spawn" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Spawn {
                profile: number("--profile", &o.need("--profile")?)?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        "revoke" => {
            let mut o = Opts::new(rest, &[])?;
            let c = Command::Revoke {
                cap: o.cap()?,
                request_id: o.request_id()?,
            };
            o.finish()?;
            c
        }
        other => return usage(format!("unknown command {other:?}")),
    };
    Ok(Invocation {
        json,
        timeout,
        approval_timeout,
        command,
    })
}

/// Client configuration for an invocation.
pub fn config(inv: &Invocation) -> ClientConfig {
    let mut c = ClientConfig::default();
    if let Some(t) = inv.timeout {
        c.call_timeout = t;
    }
    if let Some(t) = inv.approval_timeout {
        c.approval_timeout = t;
    }
    c
}

fn rid(given: Option<RequestId>) -> Result<RequestId, Error> {
    match given {
        Some(r) => Ok(r),
        None => tessera_sdk::new_request_id(),
    }
}

fn read_source(s: &Source, stdin: &mut dyn Read) -> Result<Vec<u8>, Error> {
    match s {
        Source::File(p) => Ok(std::fs::read(p)?),
        Source::Stdin => {
            let mut v = Vec::new();
            stdin.read_to_end(&mut v)?;
            Ok(v)
        }
        Source::Inline(b) => Ok(b.clone()),
    }
}

fn budget_json(b: WireBudget) -> Value {
    match b {
        WireBudget::Finite(n) => json!(n),
        WireBudget::Unlimited => json!("unlimited"),
    }
}

fn depth_json(d: WireDepth) -> Value {
    match d {
        WireDepth::Finite(n) => json!(n),
        WireDepth::Unlimited => json!("unlimited"),
    }
}

fn scope_json(s: &WireScope) -> Value {
    match s {
        WireScope::File { object_id, rights } => json!({
            "kind": "file",
            "object_id": object_id,
            "read_snapshot": rights.read_snapshot,
            "replace_content": rights.replace_content,
        }),
        WireScope::Https {
            endpoint_id,
            methods,
            max_body_bytes,
        } => {
            let names: Vec<&str> = [
                (methods.get, "GET"),
                (methods.head, "HEAD"),
                (methods.post, "POST"),
                (methods.put, "PUT"),
                (methods.patch, "PATCH"),
                (methods.delete, "DELETE"),
            ]
            .into_iter()
            .filter_map(|(on, n)| on.then_some(n))
            .collect();
            json!({
                "kind": "https",
                "endpoint_id": endpoint_id,
                "methods": names,
                "max_body_bytes": max_body_bytes,
            })
        }
    }
}

fn status_str(s: WireCapStatus) -> &'static str {
    match s {
        WireCapStatus::Live => "live",
        WireCapStatus::Expired => "expired",
        WireCapStatus::Revoked => "revoked",
        WireCapStatus::Dropped => "dropped",
    }
}

fn reservation_str(s: WireReservationStatus) -> &'static str {
    match s {
        WireReservationStatus::Reserved => "reserved",
        WireReservationStatus::Dispatched => "dispatched",
        WireReservationStatus::Completed => "completed",
        WireReservationStatus::Unknown => "unknown",
        WireReservationStatus::Failed => "failed",
    }
}

/// JSON rendering of a capability view.
pub fn view_json(v: &CapabilityView) -> Value {
    json!({
        "cap_id": format_id(v.cap_id),
        "root_id": format_id(v.root_id),
        "parent": v.parent.map(format_id),
        "owner": AgentId(v.owner).to_string(),
        "scope": scope_json(&v.scope),
        "budget_remaining": budget_json(v.budget_remaining),
        "depth": depth_json(v.depth),
        "expires_in_millis": v.expires_in_millis,
        "status": status_str(v.status),
    })
}

fn view_human(v: &CapabilityView) -> String {
    let scope = match &v.scope {
        WireScope::File { object_id, rights } => format!(
            "file object {object_id} ({}{})",
            if rights.read_snapshot { "read " } else { "" },
            if rights.replace_content {
                "replace"
            } else {
                ""
            }
        ),
        WireScope::Https {
            endpoint_id,
            max_body_bytes,
            ..
        } => format!(
            "https endpoint {endpoint_id} methods {} max body {max_body_bytes} B",
            scope_json(&v.scope)["methods"]
        ),
    };
    let fmt_b = |b| match b {
        WireBudget::Finite(n) => n.to_string(),
        WireBudget::Unlimited => "unlimited".into(),
    };
    let fmt_d = |d| match d {
        WireDepth::Finite(n) => n.to_string(),
        WireDepth::Unlimited => "unlimited".into(),
    };
    format!(
        "capability {}\n  status     {}\n  scope      {}\n  remaining  {}\n  depth      {}\n  \
         expires    {}\n  owner      {}\n  root       {}\n  parent     {}\n",
        format_id(v.cap_id),
        status_str(v.status),
        scope,
        fmt_b(v.budget_remaining),
        fmt_d(v.depth),
        v.expires_in_millis
            .map(|m| format!("in {:.1}s", m as f64 / 1000.0))
            .unwrap_or_else(|| "with session".into()),
        AgentId(v.owner),
        format_id(v.root_id),
        v.parent.map(format_id).unwrap_or_else(|| "(root)".into()),
    )
}

/// Output streams for one run.
pub struct Io<'a> {
    /// Standard input (for `--stdin`).
    pub stdin: &'a mut dyn Read,
    /// Standard output.
    pub stdout: &'a mut dyn Write,
    /// Standard error.
    pub stderr: &'a mut dyn Write,
}

/// Outcome of executing a command, before rendering.
enum Done {
    Text {
        human: String,
        json: Value,
    },
    Bytes {
        bytes: Vec<u8>,
        json: Value,
        note: Option<String>,
    },
}

fn prior(request_id: RequestId, reservation_id: u128, status: WireReservationStatus) -> Done {
    Done::Text {
        human: format!(
            "request {} was already used: reservation {} is {}. No new effect was performed.\n",
            format_id(request_id),
            format_id(reservation_id),
            reservation_str(status)
        ),
        json: json!({
            "result": "prior_reservation",
            "request_id": format_id(request_id),
            "reservation_id": format_id(reservation_id),
            "status": reservation_str(status),
        }),
    }
}

fn execute(client: &Client, inv: &Invocation, io: &mut Io<'_>) -> Result<Done, Error> {
    Ok(match &inv.command {
        Command::Help => Done::Text {
            human: USAGE.into(),
            json: json!({ "usage": USAGE }),
        },
        Command::Request {
            terms,
            description,
            request_id,
        } => {
            let r = rid(*request_id)?;
            if description.is_some() {
                let _ = writeln!(
                    io.stderr,
                    "note: --description is not carried by protocol v1; the operator sees only \
                     the broker's normalized request"
                );
            }
            let _ = writeln!(
                io.stderr,
                "request id {} — waiting for operator approval… (the operator must approve on \
                 the trusted approval device; this can take minutes)",
                format_id(r)
            );
            let _ = io.stderr.flush();
            let cap = client.request_grant_with_id(r, *terms, description.as_deref())?;
            Done::Text {
                human: format!("granted capability {}\n", format_id(cap)),
                json: json!({ "result": "granted", "cap_id": format_id(cap), "request_id": format_id(r) }),
            }
        }
        Command::Read {
            cap,
            max_bytes,
            out,
            request_id,
        } => {
            let r = rid(*request_id)?;
            let op = tessera_sdk::wire::WireOperation::FileReadSnapshot {
                max_bytes: *max_bytes,
            };
            match client.consume_with_id(r, *cap, op)? {
                Consumed::Prior {
                    reservation_id,
                    status,
                } => prior(r, reservation_id, status),
                Consumed::Executed {
                    reservation_id,
                    result:
                        tessera_sdk::wire::WireOperationResult::FileSnapshot { bytes, truncated },
                } => {
                    let bytes = bytes.into_inner();
                    let mut j = json!({
                        "result": "read",
                        "request_id": format_id(r),
                        "reservation_id": format_id(reservation_id),
                        "len": bytes.len(),
                        "truncated": truncated,
                    });
                    let note = truncated.then(|| {
                        format!("warning: file is longer than {max_bytes} bytes; output truncated")
                    });
                    if let Some(path) = out {
                        std::fs::write(path, &bytes)?;
                        j["written_to"] = json!(path);
                        Done::Text {
                            human: format!(
                                "wrote {} bytes to {}{}\n",
                                bytes.len(),
                                path.display(),
                                if truncated { " (truncated)" } else { "" }
                            ),
                            json: j,
                        }
                    } else {
                        Done::Bytes {
                            bytes,
                            json: j,
                            note,
                        }
                    }
                }
                Consumed::Executed { .. } => {
                    return Err(Error::Protocol("expected a file snapshot result".into()));
                }
            }
        }
        Command::Replace {
            cap,
            source,
            request_id,
        } => {
            let r = rid(*request_id)?;
            let data = read_source(source, io.stdin)?;
            let bytes = tessera_sdk::wire::ContentBytes::new(data)
                .map_err(|e| Error::InvalidArgument(format!("content: {e}")))?;
            let op = tessera_sdk::wire::WireOperation::FileReplaceContent { bytes };
            match client.consume_with_id(r, *cap, op)? {
                Consumed::Prior {
                    reservation_id,
                    status,
                } => prior(r, reservation_id, status),
                Consumed::Executed {
                    reservation_id,
                    result: tessera_sdk::wire::WireOperationResult::FileReplaced { bytes_written },
                } => Done::Text {
                    human: format!("replaced content ({bytes_written} bytes written)\n"),
                    json: json!({
                        "result": "replaced",
                        "request_id": format_id(r),
                        "reservation_id": format_id(reservation_id),
                        "bytes_written": bytes_written,
                    }),
                },
                Consumed::Executed { .. } => {
                    return Err(Error::Protocol("expected a replacement result".into()));
                }
            }
        }
        Command::Http {
            cap,
            method,
            path,
            headers,
            body,
            out,
            request_id,
        } => {
            let r = rid(*request_id)?;
            let body = match body {
                Some(s) => read_source(s, io.stdin)?,
                None => Vec::new(),
            };
            let op = Client::https_operation(HttpsRequest {
                method: *method,
                path: path.clone(),
                headers: headers.clone(),
                body,
            })?;
            match client.consume_with_id(r, *cap, op)? {
                Consumed::Prior {
                    reservation_id,
                    status,
                } => prior(r, reservation_id, status),
                Consumed::Executed {
                    reservation_id,
                    result:
                        tessera_sdk::wire::WireOperationResult::Https {
                            status,
                            headers,
                            body,
                            truncated,
                        },
                } => {
                    let hs: Vec<Value> = headers
                        .as_slice()
                        .iter()
                        .map(|h| {
                            json!([h.name.as_str(), String::from_utf8_lossy(h.value.as_slice())])
                        })
                        .collect();
                    let body = body.into_inner();
                    let mut j = json!({
                        "result": "https",
                        "request_id": format_id(r),
                        "reservation_id": format_id(reservation_id),
                        "status": status,
                        "headers": hs,
                        "body_len": body.len(),
                        "truncated": truncated,
                    });
                    let note = Some(format!(
                        "HTTP {status}{}",
                        if truncated { " (body truncated)" } else { "" }
                    ));
                    if let Some(p) = out {
                        std::fs::write(p, &body)?;
                        j["written_to"] = json!(p);
                        Done::Text {
                            human: format!(
                                "HTTP {status}: wrote {} bytes to {}\n",
                                body.len(),
                                p.display()
                            ),
                            json: j,
                        }
                    } else {
                        Done::Bytes {
                            bytes: body,
                            json: j,
                            note,
                        }
                    }
                }
                Consumed::Executed { .. } => {
                    return Err(Error::Protocol("expected an HTTPS result".into()));
                }
            }
        }
        Command::Delegate {
            cap,
            to,
            terms,
            request_id,
        } => {
            let r = rid(*request_id)?;
            let child = client.delegate_with_id(r, *cap, *to, *terms)?;
            Done::Text {
                human: format!(
                    "delegated child capability {} to {to}\n(pass this id to the recipient; ids are references, not secrets)\n",
                    format_id(child)
                ),
                json: json!({
                    "result": "delegated",
                    "request_id": format_id(r),
                    "child_cap_id": format_id(child),
                    "recipient": to.to_string(),
                }),
            }
        }
        Command::Attenuate {
            cap,
            terms,
            request_id,
        } => {
            let r = rid(*request_id)?;
            client.attenuate_with_id(r, *cap, *terms)?;
            Done::Text {
                human: format!("attenuated {}\n", format_id(*cap)),
                json: json!({ "result": "attenuated", "request_id": format_id(r), "cap_id": format_id(*cap) }),
            }
        }
        Command::Transfer {
            cap,
            to,
            request_id,
        } => {
            let r = rid(*request_id)?;
            client.transfer_with_id(r, *cap, *to)?;
            Done::Text {
                human: format!("transferred {} to {to}\n", format_id(*cap)),
                json: json!({
                    "result": "transferred",
                    "request_id": format_id(r),
                    "cap_id": format_id(*cap),
                    "recipient": to.to_string(),
                }),
            }
        }
        Command::Drop { cap, request_id } => {
            let r = rid(*request_id)?;
            client.drop_with_id(r, *cap)?;
            Done::Text {
                human: format!("dropped the remaining balance of {}\n", format_id(*cap)),
                json: json!({ "result": "dropped", "request_id": format_id(r), "cap_id": format_id(*cap) }),
            }
        }
        Command::Inspect { cap } => {
            let v = client.inspect(*cap)?;
            Done::Text {
                human: view_human(&v),
                json: view_json(&v),
            }
        }
        Command::Spawn {
            profile,
            request_id,
        } => {
            let r = rid(*request_id)?;
            let agent = client.spawn_with_id(r, *profile)?;
            Done::Text {
                human: format!("spawned agent {agent}\n"),
                json: json!({ "result": "spawned", "request_id": format_id(r), "agent": agent.to_string() }),
            }
        }
        Command::Revoke { cap, request_id } => {
            let r = rid(*request_id)?;
            client.revoke_with_id(r, *cap)?;
            Done::Text {
                human: format!("revoked {} and its descendants\n", format_id(*cap)),
                json: json!({ "result": "revoked", "request_id": format_id(r), "cap_id": format_id(*cap) }),
            }
        }
    })
}

fn error_exit(e: &Error) -> i32 {
    if e.outcome_uncertain() {
        exit::UNCERTAIN
    } else if matches!(e, Error::Broker(_) | Error::PriorReservation { .. }) {
        exit::DENIED
    } else {
        exit::FAILURE
    }
}

fn error_json(e: &Error) -> Value {
    json!({
        "error": {
            "message": e.to_string(),
            "code": e.code().map(|c| format!("{c:?}")),
            "request_id": e.request_id().map(format_id),
            "outcome_uncertain": e.outcome_uncertain(),
        }
    })
}

/// Run a parsed invocation against `client`. Returns the exit code.
pub fn run_with(client: &Client, inv: &Invocation, io: &mut Io<'_>) -> i32 {
    match execute(client, inv, io) {
        Ok(Done::Text { human, json }) => {
            let _ = if inv.json {
                writeln!(io.stdout, "{json}")
            } else {
                write!(io.stdout, "{human}")
            };
            exit::OK
        }
        Ok(Done::Bytes { bytes, json, note }) => {
            if inv.json {
                let mut j = json;
                match String::from_utf8(bytes) {
                    Ok(s) => j["body_utf8"] = json!(s),
                    Err(e) => {
                        let hex: String = e.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                        j["body_hex"] = json!(hex);
                    }
                }
                let _ = writeln!(io.stdout, "{j}");
            } else {
                if let Some(n) = note {
                    let _ = writeln!(io.stderr, "{n}");
                }
                let _ = io.stdout.write_all(&bytes);
            }
            exit::OK
        }
        Err(e) => {
            report_error(&e, inv.json, io);
            error_exit(&e)
        }
    }
}

fn report_error(e: &Error, json_mode: bool, io: &mut Io<'_>) {
    let _ = writeln!(io.stderr, "tessera: {e}");
    if e.outcome_uncertain() {
        if let Some(r) = e.request_id() {
            let _ = writeln!(
                io.stderr,
                "tessera: the request may or may not have taken effect. To find out without \
                 risking a second effect, repeat the same command with --request-id {}",
                format_id(r)
            );
        }
    }
    if json_mode {
        let _ = writeln!(io.stdout, "{}", error_json(e));
    }
}

/// Entry point: parse, connect via `TESSERA_BROKER_FD`, run.
pub fn main_with(args: &[String], io: &mut Io<'_>) -> i32 {
    let inv = match parse(args) {
        Ok(i) => i,
        Err(UsageError(m)) => {
            let _ = writeln!(io.stderr, "tessera: {m}\n\n{USAGE}");
            return exit::USAGE;
        }
    };
    if inv.command == Command::Help {
        let _ = write!(io.stdout, "{USAGE}");
        return exit::OK;
    }
    let client = match Client::from_env_with(config(&inv)) {
        Ok(c) => c,
        Err(e) => {
            report_error(&e, inv.json, io);
            return exit::FAILURE;
        }
    };
    run_with(&client, &inv, io)
}
