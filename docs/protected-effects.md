# Protected-effect inventory (WP0)

Status: **inventory frozen for the MVP (P0–P5). No mediation point is
implemented yet. No test listed here exists yet.**

**WP0 gate:** a reviewer must be able to map every claimed MVP effect to a
planned mediation point. Every claimed effect has a row in §2. Every effect
that is *not* capability-controlled is in §3. Anything not in either list is
**denied** by the baseline profile. If a reviewer finds an effect that is
in neither list, that is a gate failure and the effect must be added.

Mediation kinds:

- **Broker adapter**: the effect happens only inside a trusted adapter, after
  a committed reservation. It costs capability units (spec §5.2, ADR-0012).
- **Broker core**: an authority transition in the ledger. It costs no units
  but is limited by ownership and delegation depth.
- **Approval**: needs a fresh FIDO2 assertion (ADR-0006, ADR-0017).
- **Kernel baseline (denied)**: the launcher's static confinement makes the
  effect impossible (ADR-0005). No capability can enable it in the MVP.
- **Admin only**: available only on the operator's administrative endpoint.

Cost is per attempt. In the MVP, every adapter operation costs 1 unit, and
failure does not refund it.

## 1. Effect classes (spec §2.2)

| Class | Effects in §2 |
|---|---|
| Reading protected bytes | PE-01, PE-03, PE-04 |
| Changing a registered object | PE-02, PE-03, PE-04, PE-05 |
| Sending a request | PE-06, PE-07, PE-08 |
| Accessing credentials | PE-09 |
| Controlling another sandbox | PE-11, PE-12 |
| Acquiring authority | PE-10, PE-13 – PE-19 |
| Weakening confinement / host | PE-20 – PE-23 |

## 2. Claimed MVP protected effects

Test names are *planned* identifiers. `tests/adversarial/` holds the hostile
native workloads (spec §7). Unit and property tests live in the named crate.
"§15" refers to the row in the specification's acceptance matrix.

| ID | Protected effect | Mediation point | Capability cost | Evidencing test (planned) | Phase |
|---|---|---|---|---|---|
| PE-01 | Read the bytes of a registered file (bounded snapshot) | **Broker adapter**: `adapters/file` `ReadSnapshot` via `openat2(RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV)` under a held dir FD (ADR-0019); returns bytes, never an FD | 1 unit of `File{object, ReadSnapshot}` | `adapters/file` tests `read_once_consumes`, `second_read_denied`, `failed_read_not_refunded`; `tests/adversarial/file_read_once` (§12.1 demo) | P4 |
| PE-02 | Replace a registered file's content (logical slot) | **Broker adapter**: `adapters/file` `Replace` (temp file, fsync, `renameat2`, dir fsync) | 1 unit of `File{object, Replace}` | `adapters/file` tests `replace_atomic`, `replace_bounded_size`; `tests/adversarial/symlink_rename_race` (§15) | P4 |
| PE-03 | Open, read, write or mmap a registered file directly from the sandbox | **Kernel baseline (denied)**: the object is outside every sandbox mount namespace; the protected root is owned by the broker uid | n/a (no capability enables it) | `tests/adversarial/direct_protected_access` (§15 "host file aliases") | P4 |
| PE-04 | Reach protected or host files through aliases: `/proc/<pid>/root`, `/proc/self/fd`, inherited FDs, hard links, bind mounts, `open_by_handle_at`, `..` traversal | **Kernel baseline (denied)**: PID namespace + private `/proc`; `close_range` before exec; no host mounts; seccomp denies `open_by_handle_at`/`name_to_handle_at`; hard links impossible across mounts | n/a | `tests/adversarial/alias_paths`, `inherited_fd_scan` (§15) | P4 |
| PE-05 | Change any host file outside the sandbox's own workspace | **Kernel baseline (denied)**: read-only runtime mounts; no other host mounts | n/a | `tests/adversarial/host_write` | P4 |
| PE-06 | Send one HTTPS request to a registered endpoint | **Broker adapter**: `adapters/https` (ADR-0007): fixed endpoint, filtered DNS, no redirects or retries, new connection per attempt | 1 unit of `Https{endpoint, method, max_body_bytes}` | `adapters/https` tests `one_unit_one_request`, `redirect_not_followed`, `no_retry_on_reset`, `private_address_denied`, `dns_rebind_denied`; `tests/adversarial/https_swarm` (§12.2, §15) | P5 |
| PE-07 | Any other network egress: TCP, UDP, DNS, raw/packet sockets, other hosts or ports, CONNECT tunnels | **Kernel baseline (denied)**: separate network namespace containing only `lo`; seccomp limits `socket()` families to `AF_UNIX`/`AF_INET`/`AF_INET6` (which reach only `lo` inside the namespace); all capabilities are dropped, so raw sockets are impossible; the adapter offers no CONNECT | n/a | `tests/adversarial/direct_network`, `proxy_env_bypass` (§15) | P4 |
| PE-08 | Send a request to the model provider | **Baseline route via trusted proxy** (ADR-0020); counted as baseline, see §3 B-10 | 0 units (baseline); endpoint-, size- and rate-limited | `tests/adversarial/model_proxy_only_endpoint` | P5 |
| PE-09 | Obtain credentials: HTTPS adapter secrets, model API key, SSH agent, keyrings, Docker socket, D-Bus, cloud metadata, host env vars | **Kernel baseline (denied)** + **broker-held secrets**: secrets live only in the broker and proxy and are injected server-side; the launcher passes a clean env; no host sockets mounted; seccomp denies `keyctl`/`add_key`; no route to 169.254.169.254 | n/a | `tests/adversarial/credential_hunt`; `adapters/https` test `secret_not_echoed` | P4/P5 |
| PE-10 | Reach the authenticator or the approval UI (input, display, IPC) | **Kernel baseline (denied)**: minimal `/dev` (no hidraw or input); no display or session sockets; the approval service runs under its own uid on a private socketpair | n/a | `tests/adversarial/authenticator_access` (WP4 gate) | P3 |
| PE-11 | Control another sandbox: ptrace, signals, `process_vm_*`, `/proc/<pid>/mem`, pidfd, cgroup migration, shared IPC | **Kernel baseline (denied)**: separate PID, IPC, net and mount namespaces per sandbox; seccomp denies ptrace and `process_vm_*`; cgroup subtree not delegated | n/a | `tests/adversarial/cross_sandbox_control` | P4 |
| PE-12 | Use another principal's broker channel, or pass authority-bearing FDs | **Broker** (ADR-0004): identity = the receiving socketpair; `SO_PEERCRED`/pidfd cross-check; ancillary data rejected; no shared socket path | n/a | `crates/broker` tests `ancillary_rejected`, `peercred_mismatch_kills`; `tests/adversarial/channel_theft` | P2/P4 |
| PE-13 | Mint new root authority (MINT) | **Approval** + **broker core**: fresh FIDO2 assertion over the canonical payload; nonce redeemed and root created in one journal record | 1 touch (UP, optional UV); 0 units | `crates/approval` tests `tamper_each_field_denied`, `replay_denied`, `wrong_key_denied`, `no_up_denied`, `stale_epoch_denied`; model `NoResurrection` (§15 "reuse approval") | P3 |
| PE-14 | Request a grant (REQUEST_GRANT) | **Broker core**: creates no authority; rate-limited; queued for approval | 0 units, no authority | `crates/broker` test `request_grant_creates_nothing` | P3 |
| PE-15 | Use authority: CONSUME | **Broker core** → reservation → adapter (PE-01/02/06) | 1 unit per attempt; request id deduplicated | `crates/capability-core` proptest conservation; `crates/broker` test `thousand_concurrent_one_budget` (§15); model `NoOverspend`, `RequestIdDedup` | P1/P2 |
| PE-16 | Delegate, split, transfer or attenuate authority | **Broker core** (ADR-0013) | Uses delegation depth (DELEGATE: 1 generation); moves units, never creates them | `crates/capability-core` tests `delegate_broader_denied`, `depth_zero_denied`, `finite_parent_no_unlimited_child` (§15) | P1 |
| PE-17 | Use a copied capability id from another principal | **Broker core**: owner check against the channel identity | Denied | `tests/adversarial/copied_cap_id` (§15) | P4 |
| PE-18 | Revoke authority | **Admin only** in the MVP (ADR-0014) | n/a | `crates/broker` test `agent_revoke_rejected`; model `RevokeLinearization` | P2 |
| PE-19 | Spawn a new sandbox principal (`Spawn`) | **Broker core** + **launcher**: trusted profiles only; the child gets baseline authority only; quota counted against the requester's orchestration domain | Baseline only; no inherited grants | `crates/launcher` test `spawn_child_has_no_grants`; `tests/adversarial/spawn_escalation` | P4 |
| PE-20 | Weaken or escape confinement: `unshare`, `setns`, `mount`, `pivot_root`, `bpf`, `io_uring_*`, `perf_event_open`, `userfaultfd`, module load, `kexec`, setuid exec, 32-bit/x32 ABI | **Kernel baseline (denied)**: seccomp allow-list with an arch check; `no_new_privs`; all caps dropped; no setuid binaries in the runtime | n/a | `tests/adversarial/escape_syscalls`; `crates/launcher` seccomp unit tests | P4 |
| PE-21 | Harness changes its own permission mode or asks for an unsandboxed retry | **Kernel baseline**: the outer confinement does not change; there is no API to relax it | n/a | `tests/adversarial/harness_escape_toggle` (§12.3, §15) | P5 |
| PE-22 | Modify broker state, journal, policy or adapter configuration | **Kernel baseline (denied)**: these files are outside sandbox mounts and owned by the broker uid; admin changes go only through the admin endpoint | n/a | `tests/adversarial/journal_access` | P4 |
| PE-23 | Launch with a weaker profile when a mandatory feature is missing | **Launcher** startup probes refuse to launch (R10) | n/a | `crates/launcher` tests `missing_seccomp_refuses`, `landlock_required_missing_refuses`, `cgroup_controller_missing_refuses` (§15) | P4 |

## 3. Unmediated baseline effects (explicit list)

Each sandbox may do the following with no capability cost. None of them
reaches an asset in the threat model (§2 there). A new baseline effect needs
an ADR and an update to this table.

| ID | Baseline effect | Why it cannot reach a protected resource |
|---|---|---|
| B-01 | Read, write, create and delete files in its **own** workspace (per-sandbox bind mount) | The workspace is private to the sandbox. No protected object is ever placed in it. It is not shared with other sandboxes (threat model §7) |
| B-02 | Read and execute the read-only runtime (`/usr`, libraries, toolchain) | Read-only, curated tree. Holds no secrets or protected objects |
| B-03 | Use its own size-limited tmpfs `/tmp` | Private tmpfs per sandbox |
| B-04 | Create processes and threads inside its PID namespace and cgroup | `pids.max`, `memory.max` and `cpu.max` apply. Children share the sandbox identity (spec §9.1) |
| B-05 | Read its own `/proc` (PID-namespace scoped) | Shows only processes in the same sandbox. The host `/proc` is not mounted |
| B-06 | Use `lo` and Unix sockets **inside** its own network namespace | Private network namespace, so abstract sockets are private too |
| B-07 | Use `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` and its own tty | No storage or hardware access |
| B-08 | Read clocks (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`) | Read-only. A timing-channel residual risk (R-6) |
| B-09 | Send bounded frames on its own broker socketpair: Inspect, RequestGrant, and commands that the broker validates | No authority unless the broker validates and commits the command. Rate-limited |
| B-10 | (P5 harness profile only) Send model API requests through the trusted proxy socket | Fixed provider endpoint. Credential injected by the proxy. **Disclosure channel** (R-2): anything the workload has read can leave this way |
| B-11 | Write bounded stdout/stderr to the launcher's log | The log is held by the trusted side. Size-limited |
| B-12 | Use allowed syscalls on its own memory and files (mmap of workspace files, `memfd_create`, futex, etc.) | Covers only objects already inside the sandbox |

## 4. Not claimed in the MVP

These effects have no mediation point because they are **not offered**.
They are denied by the baseline:

- direct (kernel-enforced) finite or unlimited grants on files or sockets
  (BPF LSM is deferred, ADR-0016)
- Git push, email, deployment, payment and cloud adapters
- shared budgets across owners; cascading attenuation
- agent-initiated revocation (ADR-0014)
- cross-sandbox FD passing or shared workspaces
