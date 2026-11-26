# ADR-0032: Security review 2026-11-25 remediation: workspaces, limits, rendering, HTTPS paths, dispatch fairness

- Status: Accepted. Implemented in `crates/broker`, `crates/approval`,
  `adapters/https`; tested.
- Spec: §8.1, §9.1, §9.4, §11. Amends ADR-0024 (launcher details, admission
  control), ADR-0007 (path rules), ADR-0022 (dispatch). Ledger compaction
  (finding 3) is ADR-0031. Finding 6 and the seccomp gaps belong to the
  launcher work package.

## Decision

### Per-principal workspaces (finding 1)
Every principal (operator-created or agent-spawned) gets a fresh directory
`<profile workspace>/e<epoch>.s<serial>`, created by the broker with mode
0700 and `O_EXCL` semantics (an existing directory is an error, never
reused) and bound at `/workspace`. Workspace parents must be broker-owned,
not group/world writable, and may not overlap protected paths, other
workspaces or read-only binds.

**Retention policy.** Directories are kept after the principal terminates
(for the operator's inspection of what an agent left behind) and are never
reused: names include the epoch, which every restart increments, so a new
principal can never be handed an old directory. Removing old directories is
an operator task (`docs/install.md`). A failed launch removes its empty
directory.

### Profile limits (finding 2)
`memory_max_bytes` and `pids_max` are `CgroupLimit`: a number or the exact
string `"unlimited"`. Omitted or `null` keeps the launcher default (2 GiB,
512). Any other value is a configuration error.

### Approval screen (finding 5)
The untrusted description is rendered by `tessera_approval::render_request`
only inside the UNTRUSTED block:
- runs of spaces collapse to one, and a wrapped line never starts with a
  space;
- every other control, format (Cf, from an explicit table), line or
  paragraph separator, non-ASCII space, Hangul filler, blank-looking letter,
  tag character and variation selector is shown as `\u{...}`, as is
  anything the standard library does not consider printable;
- every line starts with `  | ` and is at most 48 cells wide, so no agent
  text starts a screen line.
`tessera-admin` prints the broker's rendering, which uses the broker's clock
(already the case in ADR-0024).

### HTTPS paths (unconfirmed review item)
A request path (and a configured prefix) is refused if it contains `;`
anywhere before the query, an invalid percent escape, or a segment that,
after one round of percent-decoding, still contains a percent escape (double
encoding such as `%252e`, `%25%32%65`) or is `.` or `..`. Encoded dot,
slash, backslash and NUL remain refused. `;` stays allowed in the query.

### Dispatch fairness (unconfirmed review item)
`BrokerConfig::max_dispatch_per_agent` (default 2, with 4 workers) bounds
the jobs one principal has on the dispatch workers. Further jobs of that
principal stay in the broker: reserved and journaled, but without the
`Dispatched` marker. When a job finishes, waiting jobs are released
round-robin across principals, FIFO within each. Before release the
capability is checked again: if it is no longer live (revoked, expired,
owner terminated), the reservation is resolved as failed (no effect; the
unit stays spent, as for every failed dispatch) and the agent receives the
corresponding error. Terminating a principal fails its waiting jobs the same
way. Emergency stop drops them (the epoch bump abandons their reservations,
and having no marker they are reported as not dispatched). A slow endpoint
can therefore hold at most `max_dispatch_per_agent` workers per principal.
Per-domain limits are not implemented (a domain of N principals can hold N ×
the cap, bounded by `max_domain_agents`).

> Amended by [ADR-0033](0033-orchestration-domain-quotas.md): the cap is now
> `max_dispatch_per_domain`, per orchestration domain, and release is
> round-robin across domains (re-review 2026-11-26).

## Evidence
- Finding 1: `crates/broker/tests/workspace_isolation_e2e.rs` (real
  sandboxes from one profile; the corpus probes
  `tests/adversarial/cross_principal/{sender,receiver}.py`: A offers fd 3 on
  workspace, `/tmp`, `/dev/shm` and abstract sockets and plants files; B
  must reach none; the same receiver inside A must detect them; host
  directories distinct, 0700, retained after termination). Reverting to a
  shared directory makes it fail with "connected to '/workspace/x.sock',
  got b'take-my-channel' with 1 fds". `sandbox_e2e` (incl. the spawned
  child); `spawner::tests::each_workspace_is_created_fresh`.
- Finding 2: `spawner::tests::only_an_explicit_unlimited_removes_a_limit`,
  `omitted_limits_inherit_launcher_defaults`.
- Finding 5: `crates/approval` `padded_description_cannot_forge_screen_lines`
  (the `esc` PoC), `every_invisible_or_format_character_is_escaped`,
  `description_wraps_with_prefixes_and_escapes_unicode_format_characters`.
- HTTPS: `adapters/https` `path_rules` (`..;`, `;jsessionid`, `%252e`,
  `%25%32%65`, malformed escapes refused; `100%25`, `;` in query allowed).
- Dispatch: `review_regressions.rs`
  `slow_principal_cannot_hold_every_dispatch_worker`,
  `terminating_a_principal_fails_its_undispatched_jobs`;
  `hardening.rs` `revoke_vs_consume_race_matches_a_serial_order` (no
  dispatch marker after the revoke record; journaled-but-undispatched
  reservations answered `Revoked`).

## Consequences
- A reservation is no longer always dispatched: one that waits for a slot
  can end `Failed` without an adapter call if its authority ends first.
- Workspace directories accumulate until the operator removes them.
