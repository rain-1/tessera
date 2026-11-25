//! Human-readable terminal rendering of a canonical grant request.
//!
//! Everything in the main body is derived from the normalized, validated
//! request fields. An agent-supplied description, if any, is printed in a
//! separate block labelled UNTRUSTED, with control, bidi and other invisible
//! characters escaped, and truncated.

use std::fmt::Write as _;
use std::num::NonZeroU64;

use crate::codec::hex;
use crate::request::{BudgetAmount, Depth, GrantRequest, Scope, Tick};

/// Max characters of untrusted description shown.
pub const MAX_UNTRUSTED_CHARS: usize = 400;
const DESCRIPTION_LINE_WIDTH: usize = 48;

/// Rendering context supplied by the trusted UI.
#[derive(Clone, Copy, Debug)]
pub struct RenderContext {
    /// Trusted current time.
    pub now: Tick,
    /// If known, converts tick deltas into approximate wall durations.
    pub ticks_per_second: Option<NonZeroU64>,
}

fn duration(ctx: &RenderContext, from: Tick, to: Tick) -> String {
    let Some(delta) = to.0.checked_sub(from.0) else {
        return "ALREADY PASSED".into();
    };
    match ctx.ticks_per_second {
        Some(tps) => {
            let secs = delta / tps;
            let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
            if d > 0 {
                format!("in ~{d}d {h}h {m}m")
            } else if h > 0 {
                format!("in ~{h}h {m}m")
            } else if m > 0 {
                format!("in ~{m}m {s}s")
            } else {
                format!("in ~{s}s")
            }
        }
        None => format!("in {delta} ticks"),
    }
}

/// Escapes everything that could alter terminal state or mislead visually,
/// collapses runs of spaces to one, and truncates.
pub fn escape_untrusted(s: &str) -> String {
    untrusted_tokens(s).collect()
}

/// Characters that are invisible, zero-width, reorder or join text, or
/// otherwise render differently from what they are (security review
/// finding 5). Listed explicitly so that coverage does not depend on the
/// standard library's notion of "printable"; that is applied as well.
fn must_escape(c: char) -> bool {
    if c.is_control() || (c.is_whitespace() && c != ' ') {
        // Cc, and every space other than U+0020 (Zs, Zl U+2028, Zp U+2029,
        // tab and newline): no padding, no line or paragraph breaks.
        return true;
    }
    let explicit = matches!(u32::from(c),
        // Unicode general category Cf (format), Unicode 16.
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891
        | 0x08E2 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064
        | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001
        | 0xE0020..=0xE007F
        // Hangul fillers and other blank-looking letters.
        | 0x115F | 0x1160 | 0x3164 | 0xFFA0 | 0x2800 | 0x17B4 | 0x17B5
        // Combining grapheme joiner, variation selectors (incl. Mongolian
        // free variation selectors), the rest of the tag/supplement plane.
        | 0x034F | 0x180B..=0x180F | 0xFE00..=0xFE0F | 0xE0000..=0xE0FFF
        // Interlinear annotation and object replacement characters.
        | 0xFFF0..=0xFFF8 | 0xFFFC);
    explicit || (!matches!(c, '\'' | '"') && c.escape_debug().next() == Some('\\'))
}

fn untrusted_tokens(s: &str) -> impl Iterator<Item = String> + '_ {
    let mut prev_space = true; // also drops leading spaces
    s.chars()
        .filter(move |c| {
            let space = *c == ' ';
            let keep = !(space && prev_space);
            prev_space = space;
            keep
        })
        .take(MAX_UNTRUSTED_CHARS + 1)
        .enumerate()
        .map(|(i, c)| {
            if i >= MAX_UNTRUSTED_CHARS {
                return " …[truncated]".into();
            }
            match c {
                '\\' => "\\\\".into(),
                c if must_escape(c) => format!("\\u{{{:04x}}}", u32::from(c)),
                c => c.to_string(),
            }
        })
}

/// Every line of the untrusted block starts with `  | ` and is at most
/// [`DESCRIPTION_LINE_WIDTH`] cells wide, so no agent text can start a
/// screen line or pad itself onto one.
fn write_description(out: &mut String, description: &str) {
    let mut width = 0;
    out.push_str("  | ");
    for token in untrusted_tokens(description) {
        // Count every non-ASCII character as up to two terminal cells.
        let columns = token
            .chars()
            .map(|c| if c.is_ascii() { 1 } else { 2 })
            .sum::<usize>();
        if width + columns > DESCRIPTION_LINE_WIDTH {
            out.push_str("\n  | ");
            width = 0;
            if token == " " {
                continue;
            }
        }
        out.push_str(&token);
        width += columns;
    }
    out.push('\n');
}

/// Renders the approval screen text.
pub fn render_request(
    request: &GrantRequest,
    untrusted_description: Option<&str>,
    ctx: &RenderContext,
) -> String {
    let f = request.fields();
    let mut o = String::new();
    let _ = writeln!(o, "=== TESSERA ROOT GRANT APPROVAL ===");
    let _ = writeln!(o, "Installation : {:032x}", f.installation.0);
    let _ = writeln!(o, "Epoch        : {}", f.authority_epoch.0);
    let _ = writeln!(o, "Operator     : {:032x}", f.operator.0);
    let _ = writeln!(
        o,
        "Recipient    : agent {:032x}/{}",
        f.recipient.epoch, f.recipient.serial
    );
    let mut consequences: Vec<String> = Vec::new();
    match f.scope {
        Scope::File { object, rights } => {
            let _ = writeln!(o, "Target       : file object {:032x}", object.0);
            let _ = writeln!(o, "Actions      : {}", rights.names().join(", "));
            for r in rights.names() {
                consequences.push(match r {
                    "read" => "can read the full contents of this file".into(),
                    "replace" => "can OVERWRITE this file's entire contents".into(),
                    "append" => "can append data to this file".into(),
                    "metadata" => "can read this file's metadata".into(),
                    other => other.into(),
                });
            }
        }
        Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => {
            let _ = writeln!(o, "Target       : HTTPS endpoint {:032x}", endpoint.0);
            let _ = writeln!(o, "Actions      : {}", methods.names().join(", "));
            let _ = writeln!(o, "Max body     : {max_body_bytes} bytes per request");
            consequences.push(format!(
                "can send {} requests to this endpoint with bodies up to {max_body_bytes} bytes",
                methods.names().join("/")
            ));
            if max_body_bytes > 0 {
                consequences.push(
                    "data the agent can read may be sent to this endpoint (exfiltration path)"
                        .into(),
                );
            }
        }
    }
    match f.budget.amount {
        BudgetAmount::Finite(n) => {
            let _ = writeln!(o, "Quantity     : {n} {}", f.budget.unit.noun(n));
            consequences.push(if n == 1 {
                format!(
                    "single use: at most 1 {}; a failed attempt still uses it",
                    f.budget.unit.noun(1)
                )
            } else {
                format!("at most {n} {} in total", f.budget.unit.noun(n))
            });
        }
        BudgetAmount::Unlimited => {
            let _ = writeln!(o, "Quantity     : UNLIMITED {}", f.budget.unit.noun(2));
            consequences.push("UNLIMITED use until expiry or revocation".into());
        }
    }
    match f.depth {
        Depth::Finite(0) => {
            let _ = writeln!(o, "Delegation   : none");
            consequences.push("cannot be delegated to any other agent".into());
        }
        Depth::Finite(n) => {
            let _ = writeln!(o, "Delegation   : up to {n} level(s)");
            consequences.push(format!(
                "can be delegated up to {n} level{} (recipient may pass it on{})",
                if n == 1 { "" } else { "s" },
                if n == 1 {
                    "; they cannot pass it further"
                } else {
                    ", and so on"
                }
            ));
        }
        Depth::Unlimited => {
            let _ = writeln!(o, "Delegation   : UNLIMITED depth");
            consequences
                .push("can be delegated to any number of agents WITHOUT DEPTH LIMIT".into());
        }
    }
    let _ = writeln!(
        o,
        "Grant expiry : tick {} ({})",
        f.grant_expires_at.0,
        duration(ctx, ctx.now, f.grant_expires_at)
    );
    let _ = writeln!(
        o,
        "Approve by   : tick {} ({})",
        f.request_expires_at.0,
        duration(ctx, ctx.now, f.request_expires_at)
    );
    let _ = writeln!(o, "Nonce        : {}", hex(&f.nonce.0));
    let _ = writeln!(o, "Digest       : {}", hex(&request.digest().0));
    let _ = writeln!(o, "Consequences :");
    for c in &consequences {
        let _ = writeln!(o, "  - {c}");
    }
    let _ = writeln!(
        o,
        "  - authority lasts until the grant expiry above unless revoked"
    );
    if let Some(desc) = untrusted_description {
        let _ = writeln!(
            o,
            "--- UNTRUSTED agent-supplied description (not verified; may be false) ---"
        );
        write_description(&mut o, desc);
        let _ = writeln!(o, "--- end UNTRUSTED ---");
    }
    let _ = writeln!(
        o,
        "Touch the security key to APPROVE exactly the fields above, or deny."
    );
    o
}
