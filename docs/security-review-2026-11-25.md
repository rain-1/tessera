# Independent security review — 2026-11-25 (main @ 7df594b)

No ledger-level authority amplification and no FIDO2-approval bypass were found.
The confirmed findings are all in the code around the core. **All findings below are OPEN.**

| # | Sev | Where | Finding | Fix |
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
