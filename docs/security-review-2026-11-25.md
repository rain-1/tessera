# Independent security review — 2026-11-25 (main @ 7df594b)

No ledger-level authority amplification and no FIDO2-approval bypass were found.
The first table records the original findings. The status table records
how each was resolved, the commit and the regression test. Every proof of
concept the reviewer supplied is now a test in the repository; the
broker-level ones are in `crates/broker/tests/review_regressions.rs`.
Decisions: [ADR-0024](adr/0024-broker-hardening.md) (commit fb583ba),
[ADR-0019](adr/0019-file-object-identity.md),
[ADR-0031](adr/0031-epoch-compaction.md) (ledger compaction) and
[ADR-0032](adr/0032-review-remediation.md) (the remaining remediation,
branch `wp/secfix`) and [ADR-0033](adr/0033-orchestration-domain-quotas.md)
(per-domain admission limits after the re-review, branch `wp/domainfix`).

## Findings as reported

| # | Sev | Where | Finding | Suggested fix |
|---|---|---|---|---|
| 1 | High | broker/src/spawner.rs:140 | Every principal launched from one profile shares one writable workspace. That gives a Unix-socket IPC channel, which allows SCM_RIGHTS transfer of fd 3 (identity theft) and planted scripts. Reproduced. | Per-principal workspace subdirectory; add a corpus probe |
| 2 | Med | broker/src/spawner.rs:151 | A profile with `None` limits overrides the launcher's memory and pid defaults, leaving the sandbox unlimited. Reproduced. | Keep the defaults unless the profile explicitly says "unlimited" |
| 3 | Med | capability-core step.rs:406/535/631 | The global record caps can be exhausted by self-delegation, and this survives restart. Reproduced. | Per-principal and per-root quotas; compact at the epoch boundary |
| 4 | Med | broker reactor.rs:1784 | The approval queue and its rate window are global, so one agent can block everyone's grant requests. Reproduced. | Per-principal pending cap; round-robin |
| 5 | Low/Med | approval/src/render.rs:49 | Whitespace padding and unescaped Cf/tag characters let an agent forge approval-screen lines. Also, tessera-admin renders with now=Tick(0). Reproduced. | Escape Cf/Zl/Zp; prefix-wrap the untrusted block; use the broker's tick |
| 6 | Low/Med | launcher.rs:182 | Nothing stops a misconfiguration from mounting state_dir, file_root or the admin socket into a sandbox. Exposing the admin socket gives the agent the full admin API. Code trace only. | Treat those paths as forbidden trees (both ancestors and descendants) |
| 7 | Low | broker reactor.rs:1896 | Grant requests that expire in the queue get no reply and leak in-flight slots. Reproduced. | Call fail_grant(ApprovalTimeout) for each expired entry |
| 8 | Low | broker reactor.rs:1371/1383 | Denial detail tells a non-owner whether another principal's capability exists. Reproduced. | Constant detail and code for every non-owned target |
| 9 | Low | broker reactor.rs:2398 | reset_session() clears the approval rate window. Code trace only. | Keep the limiter outside the session |
| 10 | Low | broker executor.rs / on_dispatched | The new file identity can be lost after a replace fails or an emergency stop interrupts it, leaving the slot unusable. Code trace only. | Journal the identity before the exchange |

Unconfirmed: HTTPS prefix bypass via `..;` or `%25xx` against normalizing backends (reject `;` and `%25`); the seccomp denylist misses newer syscalls (open_tree_attr, file_getattr/file_setattr, listns) and allows modify_ldt (consider an allowlist); a slow HTTPS endpoint can starve the 4 dispatch workers.

## Status

| # | Status | Fix | Commit | Regression test |
|---|---|---|---|---|
| 1 | **FIXED** | Fresh 0700 `<workspace>/e<epoch>.s<serial>` per principal, operator-created or agent-spawned, created exclusively by the broker; never reused; retained after termination (ADR-0032 retention policy). Workspace parents checked (owner, mode, no overlap with protected paths, other workspaces or binds). | fb583ba; test 60f416f | `crates/broker/tests/workspace_isolation_e2e.rs` with corpus probes `tests/adversarial/cross_principal/{sender,receiver}.py` (real sandboxes from one profile: A offers fd 3 on workspace, `/tmp`, `/dev/shm` and abstract sockets and plants scripts; B reaches none; the same receiver inside A must detect them). Verified to fail on a shared directory (B received fd 3). Also `sandbox_e2e` (spawned child), `spawner::tests::each_workspace_is_created_fresh`. |
| 2 | **FIXED** | Omitted/`null` limits keep the launcher defaults (fb583ba); only the explicit string `"unlimited"` removes a limit, anything else is a configuration error (`CgroupLimit`). | fb583ba, 60f416f | `spawner::tests::only_an_explicit_unlimited_removes_a_limit` (the `limits` PoC's profile JSON), `omitted_limits_inherit_launcher_defaults` |
| 3 | **FIXED** (ledger); journal file not compacted | Per-principal and per-root quotas (ADR-0024, fb583ba). `AdminCommand::CompactEpoch`, journaled at every start after the epoch bump, prunes every earlier-epoch record; spent nonces and id counters kept; pruned pools accounted in `State::retired` and audited (ADR-0031). The journal file itself is not rewritten (history and audit lineage intact; growth per epoch bounded by the quotas). | 299c7d4, 60f416f | `review_regressions::finding3_record_exhaustion_does_not_survive_restart` (the `exhaust` PoC: after the attacker fills the previous epoch, a fresh principal is served after restart, twice); core `compaction_frees_capacity_filled_by_a_previous_epoch`, `compaction_keeps_the_current_epoch`, `compacted_snapshot_is_checked`, model `core_refines_reference_model_with_compaction{,_tight_limits}` |
| 4 | **FIXED** (completed on `wp/domainfix`) | Per **orchestration domain** (an operator-created principal and everything it spawned; ADR-0033): at most `max_pending_approvals_per_domain` (2) and at most the fair share `ceil(17 / live domains)` of the 17 approval slots (queue 16 + active); a domain with a request pending cannot take a slot still needed for the first request of another live domain; round-robin activation across domains; one rate window per domain. The first fix (fb583ba) was per principal, which spawning multiplied (re-review N1). | fb583ba, 8f1be5a | `review_regressions::finding4_one_agent_cannot_fill_the_approval_queue` (the `queue` PoC), `rereview_regressions::n1_spawn_tree_cannot_fill_the_approval_queue` (the `queue_sybil` PoC: attacker + 8 children now hold 2 slots, not 17), `n1_spawn_tree_shares_one_approval_rate_window`, `n1_approval_slots_are_reserved_for_domains_with_nothing_pending`, `hardening::approval_queue_rotates_and_rate_limits_are_per_principal` |
| 5 | **FIXED** | Untrusted block: padding collapsed, Cf (explicit table)/Zl/Zp/non-ASCII spaces/Hangul fillers/tags/variation selectors escaped, every line `  | `-prefixed and ≤ 48 cells; `tessera-admin` shows the broker's rendering made with the broker's clock. | fb583ba, a882e99 | approval `padded_description_cannot_forge_screen_lines` (the `esc` PoC), `every_invisible_or_format_character_is_escaped`; `hardening::approval_queue_rotates_and_rate_limits_are_per_principal` (relative time from the broker clock) |
| 6 | **FIXED** | `LauncherConfig.protected_host_paths` refuses ancestors **and** descendants (after canonicalisation). The launcher applies it to workspaces, binds, the model socket and the netshim. `tesserad` protects state_dir, file_root, the admin socket's directory, every endpoint secret and CA file, and `launcher.protected_paths` (e.g. the model-proxy key). It refuses to start if any of these is missing or overlapped. | wp/compat (merged 38795e9) | `crates/launcher/tests/protected.rs`, broker spawner protected-path test |
| 7 | **FIXED** | Expired queued grants get `fail_grant(ApprovalTimeout)` for every attached correlation, are bound as denied and release their in-flight slots. | fb583ba | `review_regressions::finding7_expired_queued_grants_are_answered_and_release_slots` (the `poc` main), `hardening::queued_grant_timeout_replies_to_every_waiter_and_releases_slots` |
| 8 | **FIXED** | One code and detail (`UnknownCapability`) for unknown and not-owned targets. | fb583ba | `review_regressions::finding8_non_owner_sees_one_answer_for_every_foreign_or_unknown_target` (the `oracle` PoC extended to Consume, Delegate, Attenuate, Transfer, Drop, Revoke, Inspect × unknown, live, revoked, dropped, ancestor-revoked, expired, owner-terminated) |
| 9 | **FIXED** | The rate window (`approval_begins`) is broker state, outside the authenticator session. | fb583ba | `review_regressions::finding9_rate_window_survives_credential_rotation`, `hardening::approval_queue_rotates_and_rate_limits_are_per_principal` (session reset by termination) |
| 10 | **FIXED** | `FileReplacePrepared` journals both identities before the exchange; recovery accepts only those two and journals `FileIdentityRecovered` (ADR-0019). | fb583ba | `reactor::tests::interrupted_replacement_restores_the_verified_occupant` (crash before and after the exchange), `emergency_stop_after_prepare_preserves_the_exchanged_identity`, `replacement_stops_when_the_intent_cannot_be_synced`, `late_outcome_cannot_override_a_newer_file_identity`, `recovery_rejects_a_foreign_displaced_inode` |
| HTTPS `..;` / `%25xx` | **FIXED** (hardening; not confirmed exploitable) | Refuse `;` in the path, malformed escapes, and segments that after one decoding still contain an escape or are dot segments. | 6050055 | `adapters/https` `path_rules` |
| seccomp gaps | **FIXED** | Now denied: `modify_ldt`, `open_tree_attr` (467), `file_getattr` (468), `file_setattr` (469), `listns` (470). A further filter returns ENOSYS for every syscall number > 470, so syscalls from newer kernels are denied by default. The numbers 467–470 are absent from this host's 6.12 headers and `libc`; check them against a ≥ 6.18 syscall table. | wp/compat (merged 38795e9) | launcher seccomp unit test; adversarial probe (EPERM for the five, ENOSYS for 471 and 1000) |
| Dispatch starvation | **FIXED** | `max_dispatch_per_domain` (2 of 4 workers) per orchestration domain, so an agent and its children together hold at most 2 workers: further jobs wait unmarked and are released round-robin across domains, then across a domain's principals; a waiting job whose authority ended (revoke, expiry, termination) is failed, not dispatched. The first fix (60f416f) capped each principal, which spawning multiplied. | 60f416f, 8f1be5a | `review_regressions::slow_principal_cannot_hold_every_dispatch_worker`, `terminating_a_principal_fails_its_undispatched_jobs`, `rereview_regressions::n1_spawn_tree_shares_one_dispatch_cap`, `hardening::revoke_vs_consume_race_matches_a_serial_order` |

## Re-review 2026-11-26

A re-review of the remediation found the items below. Its proofs of
concept are tests in the repository: `queue_sybil` is
`crates/broker/tests/rereview_regressions.rs::n1_spawn_tree_cannot_fill_the_approval_queue`
and `modelsock` is `crates/launcher/tests/model_socket.rs::host_agent_sockets_are_refused`.
Every listed test fails on the commit before its fix (for the launcher tests,
the PoC printed `ACCEPTED` for all three agent sockets).

| # | Sev | Where | Finding | Status | Fix | Commit | Regression test |
|---|---|---|---|---|---|---|---|
| N1 | Low/Med | broker reactor.rs (pending cap, `activate_next`, `on_consume`), `ledger_quota.rs` | Finding 4 was incomplete. Each operator-created principal roots an orchestration domain, and with `agent_spawn_profiles` it can spawn 8 children, each with its own pending cap and rate window: 17 of 18 slots pending, other domains get "approval queue full", and the prompt rate is multiplied. The same applied to the dispatch cap (Low) and, within an epoch, to the global record caps (residual of finding 3). | **FIXED** | Pending cap, round-robin and rate window per domain, with fair share and reservation of approval slots; dispatch cap per domain; `LedgerQuotas.derived_per_domain` (2 048) and `reservations_per_domain` (16 384). All configurable in `tesserad` `limits` (ADR-0033). | 8f1be5a | `rereview_regressions::n1_spawn_tree_cannot_fill_the_approval_queue`, `n1_spawn_tree_shares_one_approval_rate_window`, `n1_approval_slots_are_reserved_for_domains_with_nothing_pending`, `n1_spawn_tree_shares_one_dispatch_cap`, `n1_ledger_quotas_are_per_domain`; `config::tests::domain_limits_parse` |
| N2 | Low | launcher.rs `check_model_route` | The model route socket check accepted `/run/user/$UID/gnupg/S.gpg-agent`, `S.gpg-agent.ssh` and `/run/user/$UID/openssh_agent` (private sockets owned by the user). | **FIXED** | `LauncherConfig.model_socket_dir`: owned by our uid, mode 0700, not `$XDG_RUNTIME_DIR` or `$HOME` or an ancestor of either, otherwise the launcher refuses to start. Without it every model route is refused; a socket must resolve to a path inside it. Defence in depth: any path component containing the words `gnupg`, `gpg`, `keyring(s)`, `ssh` or `openssh`, and `$SSH_AUTH_SOCK` (before and after resolving), are refused. `tesserad`: `launcher.model_socket_dir`, required when a profile has a model route; all routes are validated at start. `tessera-launch-run --model-socket-dir`. Examples and `docs/compat.md` updated. | 812b1e2, de37668 | `crates/launcher/tests/model_socket.rs` (`host_agent_sockets_are_refused`, `model_routes_need_a_model_socket_dir`, `model_socket_dir_must_be_private_and_dedicated`), `protected.rs`, `config::tests::model_routes_need_a_model_socket_dir`, `model-proxy` `compat_sandbox.rs` |
| N3 | Low | broker spawner.rs `prepare_profiles` | Model route socket and netshim paths were checked against protected paths but not against workspace roots (bind sources were). | **FIXED** | Socket and netshim are checked against protected paths and workspace roots (ancestor and descendant, after canonicalisation). | 812b1e2 | `spawner::tests::model_route_must_not_overlap_workspace_roots` |
| Info | — | broker reactor.rs `emergency_stop` | Emergency stop bumped the epoch but did not compact, so the ended epoch kept its record capacity until the next restart. | **FIXED** | `CompactEpoch` is journaled and then applied after the bump, as at startup. It is deferred until no job of the ended epoch is still on a worker, because such a job may still journal a file-replacement intent or an outcome for its reservation. | 8f1be5a | `rereview_regressions::emergency_stop_compacts_the_ended_epoch` (capacity filled, stop, fresh principal served, journal has `CompactEpoch` after each bump, replay reproduces it), `emergency_stop_compaction_waits_for_jobs_on_a_worker`; `reactor::tests::emergency_stop_after_prepare_preserves_the_exchanged_identity` |

## Provenance of commit fb583ba (audited 2026-11-26)

`fb583ba` ("Harden broker isolation, approvals, and recovery") landed directly
on `main` without the orchestrator's co-author trailer. An audit traced it to
an owner-directed OpenAI Codex CLI session (`01a21319-c403-7a43-b516-3a991f7007e3`,
codex-tui 0.172.0). Codex's sandbox could not write `.git`, so the owner ran
Codex's suggested commit-and-push from their own terminal.

**Verdict: benign.** The audit found no backdoors, weakened checks, network or
exfiltration code, dependency or CI changes, or loosened tests. Its
per-principal approval rate limit was weaker in one respect and was superseded
by per-domain limits in `8f1be5a`. Everything else survives on `main` in the
same or a further-hardened form.

**Process note:** agent-suggested `git add -A && commit && push` should not go
straight to `main`. Use a branch with review, signed commits, and branch
protection on the remote.
