# Capability Platform for Untrusted Autonomous Agents

**Engineering specification and implementation plan**  
Version 0.1 — 25 November 2026  
Status: Proposed architecture; not implemented, verified, or security-certified.

## 0. Executive summary

Build a Linux execution platform on which arbitrary AI agent harnesses can run without being trusted to enforce their own permissions. A small trusted Rust runtime manages authority as an explicit, consumable, delegable and revocable resource. New root authority is approved through an independent trusted interface and a fresh YubiKey-backed FIDO2 assertion. Linux isolation and mandatory access-control mechanisms prevent the workloads from bypassing that runtime; trusted service adapters mediate operations that require application-level meaning.

The platform is not itself an agent harness. Claude Code, Codex, local models, custom swarms and ordinary native programs are clients. Existing harnesses can run in compatibility mode; capability-aware harnesses can request and distribute authority through an SDK. Neither mode may relax the outer security boundary.

The primary research contribution is a practical, machine-checked authority calculus coupled to an independently enforced execution environment. The initial implementation must favour a small, auditable security boundary over rich policy languages or maximal transparent compatibility.

### 0.1 Design commitments

- Default deny; explicit authority only, except a narrowly documented baseline required to run a workload.
- Physical approval for new privileged root grants; no agent-controlled unsandboxed retry.
- At-most-once, bounded-use and unlimited-use grants; use and delegation are independent dimensions.
- Delegation cannot amplify scope, budget, lifetime or delegation authority.
- Revocation, expiry, provenance and durable consumption are first-class.
- Rust implementation with a Verus-verified authority core; untrusted agents may execute arbitrary native code within the supported boundary.
- Existing kernel primitives are reused; no custom kernel is required for the MVP.

### 0.2 Reading guide

Sections 1–3 establish product boundaries and architecture; 4–7 define the formal model and verification obligations; 8–12 specify implementation interfaces and enforcement; 13 gives the high-level roadmap; 14 gives executable work packages and acceptance gates; 15–17 cover adversarial tests, operations, decisions and references.

## 1. Product scope and requirements

The terms MUST, MUST NOT and SHOULD describe proposed normative requirements, not existing functionality.

| ID | Requirement |
|---|---|
| R1 | A workload MUST NOT be able to weaken, remove or bypass its external confinement through harness options, child processes or configuration changes. |
| R2 | The runtime MUST require an authenticated, fresh human authorization for each new privileged root grant. A narrowly scoped initial baseline policy is installed by the trusted operator and recorded separately. |
| R3 | A capability MUST bind a subject, resource scope, budget, delegation policy, lifetime and provenance. |
| R4 | Finite budgets MUST be conserved across all descendants and concurrent operations; failure MUST NOT refund a spent authorization automatically. |
| R5 | Direct delegation MUST obey scope attenuation and delegation constraints. |
| R6 | Revocation MUST prevent subsequent authorizations through the revoked capability and its descendants. In-flight effects follow documented semantics. |
| R7 | Caller identity MUST be established externally, not by trusting an agent-supplied identifier. |
| R8 | Security decisions MUST be auditable, including the human root grant and delegation path. |
| R9 | Restart or crash MUST NOT restore consumed grants or permit replay. |
| R10 | Unsupported enforcement mechanisms MUST fail closed, not silently downgrade confinement. |
| R11 | The authority core MUST have a small deterministic interface and executable correctness proofs. |
| R12 | Existing harnesses SHOULD run without modification where possible; richer semantic permissions MAY require adapters or SDK support. |

### 1.1 MVP and non-goals

MVP: one Linux host, one trusted operator, local Unix IPC, two isolated shell workloads, a dedicated FIDO2 credential, brokered bounded reads and writes on explicitly registered resources, delegation, revocation, durable audit and a verified ledger. Include one brokered HTTPS operation as a second resource type after file mediation works. Demonstrate a real agent harness only after the shell security tests pass.

Non-goals: a new kernel, full Linux syscall virtualization, arbitrary policy code, global information-flow guarantees, defending against a hostile host administrator or compromised kernel, guaranteed exactly-once effects on remote systems, distributed consensus, and automatic interpretation of arbitrary shell commands as semantic permissions. A later release may add VM isolation, distributed brokers, shared budgets, timed trace policies and service integrations.

## 2. Threat model and security boundary

### 2.1 Adversary

Assume the model, harness, plugins, tool output, dependencies, subprocesses and other agents are hostile. They may execute arbitrary code, forge IPC payloads, race requests, copy identifiers, trigger broker restarts, manipulate paths, attempt to obtain inherited descriptors, and cooperate through allowed communication channels. Prompt injection is simply one mechanism by which a workload becomes hostile.

Trust the host kernel and its enabled enforcement configuration; hardware and firmware; trusted launcher; broker and adapters; approval UI and authenticator library; operator; and verification/build toolchain. A hostile privileged host can invalidate these assumptions. An independent VM boundary is recommended for high-risk security research but is outside the initial proof.

### 2.2 Protected effects

The threat model is expressed in terms of protected effects, not a list of forbidden shell commands: reading protected bytes, changing a registered object, sending a request, accessing credentials, controlling another sandbox, or acquiring authority. Each supported effect needs a defined mediation point and a capability cost. Unmediated baseline effects (e.g. reading the sandbox's own temporary files) must be explicitly listed and must not access protected resources.

A non-delegatable grant prevents direct transfer to another identity; it does not prevent an authorized agent from acting as a deputy for another agent. Similarly, a read capability cannot retract data already learned. Combining read and network authority can enable disclosure. Claims about information flow require additional policies and separate proofs.

## 3. Architecture

```text
          TRUSTED OPERATOR / YUBIKEY
                     |
            Trusted approval UI
                     |
     +---------------v-------------------+
     | Broker: authentication, journal,   |
     | verified authority core, adapters  |
     +---------+---------------+---------+
               |               |
      privileged launcher      | mediated resource operations
               |               v
     +---------v---------+   Protected objects/services
     | Linux confinement |
     | namespaces, LSM,  |
     | seccomp, cgroups  |
     +---------+---------+
               |
       UNTRUSTED WORKLOADS
       harnesses / shells / agents
       | authenticated capability IPC |
       +------------------------------> broker
```

The broker is not in the syscall path for every instruction. Direct access that is safely covered by kernel policy may be permitted inside a sandbox; finite semantic operations go through service adapters. Kernel policy and brokered authority must form a coherent intersection: a grant cannot override an irreversible restriction such as an existing Landlock rule, seccomp filter or absent mount. Never temporarily remove confinement to execute a granted action.

| Component | Responsibility | Trust |
|---|---|---|
| Launcher | Build namespaces, mount layout, cgroups, drop privilege, close FDs, activate policy before exec | Trusted |
| Authority core | Scope checks, budget accounting, identity binding, transitions | Intended Verus-verified |
| Broker | Authenticate IPC, serialize commands, durable commit, dispatch exact effects | Trusted; partially verified over time |
| Approval service | Render canonical request and obtain/verify assertion | Trusted |
| Service adapters | Mediate file, HTTPS, Git or other semantic operations | Trusted per adapter |
| BPF LSM manager | Attach and protect policies; enforce supported direct resource checks | Trusted kernel integration |
| SDK/CLI | Request, delegate, consume and inspect authority | Untrusted client |
| Workload | Agent logic, arbitrary subprocesses | Untrusted |

### 3.1 Compatibility and native mode

Compatibility: `capsandbox run -- claude` launches an unmodified harness with a baseline workspace, explicit model API routing and no ambient host credentials. Internal harness permissions are additional restrictions, not escape permissions. An unsupported dynamic operation remains blocked; a wrapper, local proxy or capability-aware tool is required to request it.

Native: the SDK exposes explicit requests, splitting, transfers and sandbox spawning. A subagent is a separately isolated principal, not merely a prompt, thread or agent label within a shared process. Processes sharing an address space cannot be treated as independently protected principals.

## 4. Formal authority model

### 4.1 Objects and scope

Let O be the universe of canonical protected operations, each with resource identity and typed parameters. A permission P denotes a subset of O. Order permissions by inclusion: P ≤ Q iff P ⊆ Q. Meet and join of the abstract powerset are intersection and union. The concrete scope language need not implement all joins; only a sound, decidable subset relation is required.

For concrete scopes C and P, the implementation must prove:

    subset(C, P) ∧ permits(C, o) ⇒ permits(P, o)

Object identity must be stable and interpreted consistently by the adapter; mutable paths, hostnames and integer PIDs are not intrinsically stable object identities.

### 4.2 Budgets as affine resources

Budgets are N ∪ {∞}. A one-use permission is affine (at most once, not necessarily used). For finite n, splitting conserves budget: n = a + b. Consumption of cost k requires k > 0 and k ≤ n, producing n − k. Unlimited grants remain unlimited after use; finite grants cannot produce unlimited children. Use counts and transfer permissions are separate, so an unlimited grant may be non-delegatable.

Treat resources as a partial commutative monoid: balances compose only where total allocated authority remains within the root limit. This provides a natural interpretation in graded affine logic and resource algebras. Rust's ownership types support the implementation, but are not a substitute for a runtime ledger because identifiers can be copied across IPC.

For MVP, every protected operation costs one unit. Later weighted budgets use explicit typed units (bytes, requests, currency minor units) and checked arithmetic; do not mix incompatible units.

### 4.3 Capability record

    c = (id, root, parent, owner, scope, budget, depth, expiry, status)

IDs are unique and never recycled within an authority epoch. Root identifies the originating authorization. Parent is an immutable provenance edge. Owner is an authenticated sandbox identity. Delegation depth is zero, positive finite, or unlimited. A child must have scope no broader than its parent, expiry no later than its parent, and strictly lower finite depth. An unlimited-depth parent may issue finite- or unlimited-depth children. Status records live or invalidated authority. A zero-balance ancestor may still have live children; exhaustion is not revocation.

For simplicity, each capability has one owner, each non-root node has one parent, and independent grants are not merged. A root can issue many descendants. For a finite root, delegated balances are deducted atomically from the source. An unlimited root may allocate finite descendants; once a finite child is created, its allocation is itself conserved across its subtree.

### 4.4 State and liveness

    S = (principals, capabilities, roots, spent_nonces,
         consumption_ledger, revoked, epoch, sequence, clock)

Live(c,S,t) holds if c exists, its owner is active, its expiry has not elapsed, and neither c nor any ancestor is revoked or expired. Parent owner termination does not implicitly revoke already delegated children unless operator policy explicitly revokes the subtree; define this consistently in implementation. Descendant authority is not conditioned on parent balance. IDs, root lineage and canonical scope remain immutable except scope reduction.

## 5. Operational semantics

The pure core exposes seven authority primitives. All successful transitions are atomic at the ledger's linearization point. A denied command does not change authority state, though it may produce a separate audit event. Administrative principal creation, termination and clock/epoch transitions are also modeled and verified.

| Primitive | Preconditions and effects |
|---|---|
| MINT | Valid fresh approval for exact canonical request; authorized operator credential; active recipient; fresh ID. Atomically redeem nonce and create root. |
| CONSUME | Caller owns live capability; scope permits exact operation; budget sufficient. Deduct cost and issue a single dispatch reservation bound to operation and request ID. |
| SPLIT | Caller owns live delegatable capability; positive allocation; child scope/lifetime/depth attenuated. Deduct finite parent balance, create fresh same-owner child. |
| ATTENUATE | Caller owns live capability; scope, budget, lifetime and depth only decrease; discarded budget accounted for. No effect on already-derived children unless separately revoked. |
| TRANSFER | Caller owns live capability with positive delegation depth; destination active; atomically move ownership and decrement finite depth. Preserve identity and provenance; record transfer event. |
| REVOKE | Trusted operator or explicitly authorized revoker marks node revoked; all descendants cease authorizing new uses. |
| DROP | Owner discards remaining balance; existing descendants remain unless explicitly revoked. |

### 5.1 Delegation API

For a normal delegation, expose one atomic `delegate(parent, recipient, child_scope, quantity, expiry, child_depth)` transaction. It creates a fresh child with the target owner and consumes one delegation generation, not two. Internally implement using shared split/ownership-update logic, not two independent public transactions. Public SPLIT followed by TRANSFER is allowed but consumes the respective depth reductions and can be more restrictive. Non-delegatable grants cannot be split or transferred in the MVP. Same-owner attenuation can reduce depth to zero.

Sharing a budget among multiple owners is deliberately deferred; future design may add explicit ACL-style shared references to a single balance, with atomic spending. Do not implement sharing by duplicating records.

### 5.2 Consumption and effects

“Once” means one authorization to attempt a precisely defined operation, not one guaranteed successful effect. Consume before dispatch and durably record the reservation. No automatic refunds or retries after uncertain failure. A repeated request ID returns status of the previous reservation and MUST NOT dispatch a new effect. The adapter executes at most one dispatch per reservation; after a crash, unresolved reservations are abandoned or reported as unknown, never automatically replayed. Remote servers or clients with internal retries must be configured and tested for the claimed unit; exactly-once remote effects generally require remote idempotency support.

Revocation orders against CONSUME: if revocation linearizes first, deny; if consume first, an already reserved operation may finish. A stricter cancellation guarantee would require adapter-specific protocols and is not claimed. No result can retract information already released.

## 6. Security theorems and proof strategy

### 6.1 Invariants

For every finite root r with initial quantity N_r:

    N_r = U_r + L_r + D_r

U is cumulative consumed units, L is remaining usable/unallocated ledger balance, D is discarded/invalidated balance. Define expiry and revocation accounting explicitly: either transfer invalidated balances to D transactionally or compute D from invalidated balances in the specification. Never double-count. Generalize to every finite allocation boundary descended from an unlimited grant. The clock update and principal termination must preserve the accounting identity.

Inductive proof: MINT establishes the invariant; split redistributes; consume moves L to U; attenuation/drop/revocation/expiry move L to D; transfer changes ownership only. No other transition creates balance. Checked arithmetic links machine integers to mathematical naturals.

| ID | Theorem / precise target | Evidence |
|---|---|---|
| T1 | Every reachable finite allocation preserves accounting; no overspend. | Verus induction over transitions and subtree partition |
| T2 | A child scope is contained in its scope at delegation and in root grant scope; child lifetime bounded by original ancestry. | Scope lemmas, immutable grant snapshots and lineage induction |
| T3 | Every authorized use has an authenticated live owner and a valid root authorization (or explicitly defined baseline). | State invariant plus authentication refinement |
| T4 | No split/transfer/delegate from depth zero; finite delegation depth decreases. | Transition proofs |
| T5 | After revocation, later authorizations through the subtree fail. | Reachability/liveness proof, linearized event order |
| T6 | Expired, terminated or stale-epoch identities cannot authorize new operations. | Time/identity model and integration evidence |
| T7 | Each approval nonce is redeemed at most once; exact request binding is preserved. | Ledger proof plus cryptographic library assumptions |
| T8 | Denial, invalid inputs and arithmetic overflow cannot increase authority. | Total transition or safe denial proof |
| T9 | Concurrent requests refine a serial trace and cannot double-spend. | Single-writer implementation; model check external scheduling |
| T10 | Crash recovery never resurrects spent authority or re-dispatches an uncertain reservation. | Journal protocol proof/model plus fault injection |
| T11 | Every claimed protected effect has a matching authorized reservation or direct-policy witness. | Per-adapter refinement and Linux mediation evidence |

T2 concerns scope at delegation; later narrowing a parent does not automatically narrow existing children. To narrow the entire subtree, revoke and reissue or implement an explicit cascading attenuation primitive later.

### 6.2 Proof stack and limits

Use Verus as the primary tool: executable Rust functions carry preconditions, postconditions and ghost representations of the mathematical ledger. Start with integer bounds, scope inclusion, lineage acyclicity and transition preservation. Keep code that relies on `assume`, external specifications or trusted functions in a reviewed register. Do not describe the whole system as verified just because the core passes.

Use TLA+ or a small exhaustive model for commit/dispatch/revoke/crash interleavings. Lean 4 is optional for independent theory; Iris is relevant if a concurrent resource core becomes necessary. Kani, Loom, proptest and fuzzing supplement proofs rather than replace them. Pin toolchain revisions; CI must run proof checks and ordinary Rust tests.

End-to-end claim is conditional: if the initial isolation is correct, every protected effect is mediated, caller/object mapping is sound, the journal is durable, cryptographic assumptions hold and the adapters refine the model, then protected effects obey the root scope and quantitative limits. No proof of the ledger alone establishes Linux confinement, user intent or absence of kernel bugs.

## 7. Rust engineering specification

```rust
// Proposed data types; illustrative, not compiled.
pub enum Budget { Finite(u64), Unlimited }
pub enum Depth { Finite(u32), Unlimited }
pub struct AgentId { epoch: u128, serial: u64 }
pub struct CapabilityId(u128);
pub struct RootId(u128);
pub struct Capability {
    id: CapabilityId,
    root: RootId,
    parent: Option<CapabilityId>,
    owner: AgentId,
    scope: Scope,
    budget: Budget,
    depth: Depth,
    expires: Expiry,
    status: Status,
}
pub enum Scope {
    File { object: ObjectId, rights: FileRights },
    Https { endpoint: EndpointId, methods: MethodSet,
            max_body_bytes: u64 },
}
```

All security-sensitive fields are private to the core. Deserialized wire types are distinct from validated internal types. No `Clone` for authority-bearing handles unless semantics explicitly support aliases; copying identifiers does not confer ownership. Use explicit enum variants instead of magic numeric infinity. Use checked arithmetic, bounded message sizes and finite maximum graph depth/nodes in MVP. No unsafe Rust in core; isolate unavoidable FFI and system calls in small audited modules.

Core functions: `permits`, `is_subset`, `live`, `validate_command`, `step`, `check_invariant` (test/diagnostic). A transition returns a typed effect/reservation rather than performing I/O. Authentication and trusted time are explicit inputs from the outer runtime, never client fields. Errors are typed; unknown versions, malformed commands, stale IDs and missing policy are denial.

```text
workspace/
  capability-core/        verified data and transition semantics
  capability-proofs/      proof modules/ghost model (or inline in core)
  protocol/               bounded wire schema; no authority creation
  broker/                 single-writer reactor, authentication
  journal/                durable transaction and recovery
  launcher/               namespaces/cgroups/FD setup
  approval-ui/            isolated human request display
  authenticator/          libfido2 binding and enrollment
  adapters/file/          registered file operations
  adapters/https/         constrained HTTP operations
  enforcement/ebpf/       optional dynamic LSM policy
  cli/                    launch, inspect, request, revoke
  sdk/                    untrusted client API
  models/                 concurrency and recovery model
  tests/adversarial/      hostile native workloads and fixtures
  docs/                   threat model, proof register, hook matrix
```

## 8. Human authorization and trusted approval

### 8.1 Enrollment and request binding

Enroll a dedicated FIDO2 credential through an operator-only administrative channel. Store its public key, credential ID, algorithm, relying-party identifier and operator identity. Require user presence on every mint; offer user verification (PIN) as an additional policy for sensitive grants. Support separately enrolled recovery keys, administrative revocation and explicit rotation. A lost key does not silently authorize a weaker method.

The broker builds a canonical grant payload containing protocol version, installation identity, authority epoch, operator, recipient sandbox, full normalized scope, budget and unit, delegation depth, expiry, fresh cryptographically random nonce and request expiration. Use a versioned deterministic encoding with unambiguous field boundaries. Domain-separate its cryptographic digest from all other application messages.

The trusted UI displays the exact payload from which the digest is computed. The UI MUST use the broker's normalized fields, not free-form agent text; any description from the agent is explicitly untrusted. Show subject, target, actions, quantity, delegation, lifetime and practical consequences. Queue one active touch request per authenticator; rate-limit and allow denial. The workload must not have access to the approval UI's input, display, IPC or authenticator device.

```text
Agent -> Broker: REQUEST_GRANT (no authority yet)
Broker -> Approval UI: canonical request + fresh challenge
Operator -> UI: select / narrow / deny
UI -> YubiKey: FIDO2 assertion over bound challenge
Approval service -> Broker: verified evidence + exact request
Broker -> Durable ledger: atomically redeem nonce and mint
Broker -> Agent: new capability handle
```

Use libfido2 rather than custom cryptography. Verify the assertion against the enrolled credential, expected client-data hash, RP ID, signature and signed user-presence flag; require UV when configured. Reject expired, mismatched, replayed or unexpected-epoch challenges. A signature counter may be useful evidence where supported, but nonce redemption is the replay defense. Do not assume every authenticator implements a reliable monotonic signature counter.

### 8.2 Security limitations

A YubiKey touch establishes physical user presence for a cryptographic assertion, not informed consent. The YubiKey lacks a trusted transaction display. The independent UI, operator attention and request-to-signature binding are therefore part of the security boundary. The workload must not be allowed to automate touch requests behind deceptive UI or turn an approval for one scope into a different grant. The trusted broker may narrow a request before approval, but must not expand it afterwards.

Root authority includes explicit administrative setup policy. Initial baseline grants, key enrollment and broker installation are trusted administrative actions, not magically proven to arise from a FIDO2 touch. Changes to baseline policy should require a separately authenticated administrative transaction and invalidate affected sessions.

## 9. IPC, identity and service adapters

### 9.1 Principal lifecycle

A sandbox is a security principal created by the trusted launcher. Allocate a fresh installation/epoch-scoped AgentId before execution and bind it to a dedicated isolation domain. Use kernel-observed peer identity and launcher-maintained membership; a numeric PID alone is insufficient because it can be reused. Prefer a dedicated broker channel per sandbox, with verified membership and carefully controlled descriptor inheritance; evaluate kernel peer credentials, pidfds and cgroup membership on the pinned kernel. Do not allow clients to migrate between managed cgroups or obtain another principal's channel. Termination invalidates the subject's remaining grants and closes its channel; descendants in independently created sandboxes follow the explicit delegation policy.

If arbitrary IPC or FD passing between principals is permitted, a principal could indirectly lend access to its channel. Deny cross-principal descriptor transfers and access to other sandbox IPC namespaces unless a separately mediated mechanism is provided. The design must document all allowed communication, including files or brokers that can act as deputies. A fork within a sandbox inherits the same authority identity; `spawn_agent` creates a distinct sandbox.

### 9.2 Protocol sketch

Use local Unix IPC (a bounded framed protocol, preferably a transport that preserves message boundaries where supported). Version messages. Authenticate all calls before dispatch. Request IDs are scoped to the authenticated principal and epoch; bind them to canonical request content. Enforce size, nesting, count, timeout and rate limits before expensive parsing. Never accept a caller's claimed identity as authorization. Reject unsolicited file descriptors and ancillary messages.

```text
RequestGrant { request_id, requested_scope, budget, depth, expiry }
Consume      { request_id, cap_id, operation }
Delegate     { request_id, cap_id, recipient, child_scope,
               child_budget, child_depth, child_expiry }
Attenuate    { request_id, cap_id, reduced_scope, budget, depth, expiry }
Transfer     { request_id, cap_id, recipient }
Drop         { request_id, cap_id }
Inspect      { cap_id }
Spawn        { request_id, launch_profile }
Revoke       { request_id, cap_id }  // admin or designated revoker
```

`Spawn` is restricted to trusted profiles, resource quotas and the requester's own authorized orchestration domain. A child receives baseline authority only, not automatic access to the parent's protected resources. An administrative endpoint separate from agent IPC handles operator policy, emergency stop, enrollment and global inspection. Capability IDs are references, not secrets that independently authorize actions. Inspection returns only metadata visible to the authenticated owner or administrator.

### 9.3 File adapter (first implementation)

Register protected files outside sandbox mounts through the trusted administrator. Store an adapter-managed stable object handle and its identity. Initial scope is exact file identity with rights such as read snapshot or replace content, not arbitrary path globs. Limit maximum request/response size; use a fixed trusted root and robust relative path resolution where paths are unavoidable. Evaluate `openat2` resolution constraints, no-follow behavior and validation of filesystem type, ownership and file identity. Do not open arbitrary agent-supplied absolute paths or device nodes.

A read grant authorizes one bounded snapshot returned as bytes, not an unrestricted descriptor or mapping. A replace grant authorizes one bounded atomic replacement; define the target as a registered logical slot if rename-based replacement changes the inode. Hold trusted directory descriptors and prevent uncontrolled changes to the registered object's parent directory. Record operation digest, target and byte count; avoid logging sensitive contents. Test symlink/rename races and malicious concurrent writers. Direct raw FD access is not used for finite permissions in the MVP.

### 9.4 HTTPS adapter (second implementation)

A grant names a registered endpoint, allowed method(s), path constraints if supported, and maximum request/response sizes. Treat one authorization as one outbound HTTP request attempt, not a TCP connection. Disable automatic redirects and retries unless separately authorized; validate TLS identity; control DNS resolution and address classes; reject unauthorized destination changes and agent-selected proxy configuration. Prevent access to loopback, link-local and private/internal services unless deliberately registered and approved. Do not implement arbitrary CONNECT tunnelling as a semantic request capability. Use secrets from a broker-owned credential store rather than returning tokens to the agent.

Later adapters may mediate Git push, email, deployments, payment or cloud operations. Each must define its own unit, side effects, retry/idempotency semantics, object identity and scope-inclusion proof. A generic shell command is not equivalent to a narrow application capability.

## 10. Linux confinement and eBPF

### 10.1 Baseline isolation

Use Bubblewrap or an equivalent trusted launcher to create a controlled mount namespace, PID namespace, IPC namespace and network namespace as appropriate; supply a minimal read-only runtime and explicitly mounted workspace. Drop capabilities, set no-new-privileges, close inherited descriptors, restrict device nodes and mount `/proc` only for the workload's namespace if required. Prevent access to host sockets, desktop session, SSH agent, Docker socket, credential stores, authenticator devices, privileged service endpoints and other workload resources. Configure cgroup v2 CPU/memory/PID limits and process-tree cleanup. Enforce a restricted syscall surface with seccomp; initially exclude interfaces that have not been audited, such as `io_uring`, unneeded namespace operations, ptrace and BPF administration. Check architecture and syscall variants. Landlock may provide defense in depth, but cannot be dynamically relaxed; choose its baseline to remain compatible with intended brokered operations.

Start with no direct external network route. Provide narrowly scoped model API connectivity through a trusted proxy or an explicitly documented baseline endpoint; never inject unrestricted host API credentials into the workload. Treat model context as a disclosure channel. An agent with permission to send arbitrary prompts to an external model can exfiltrate data it can read; this is not solved by endpoint restriction alone.

### 10.2 Dynamic policy path (after broker MVP)

BPF LSM can enforce mandatory checks at kernel security hooks. Use a privileged manager, protected BPF map/link lifecycle, and a pinned tested Linux configuration with BPF LSM enabled. Programs should be small, bounded and default-deny for managed subjects. Identify managed sandboxes using kernel-observed, lifetime-aware identities (e.g. cgroup membership under trusted control, with generation and cleanup discipline); validate resource identity and map semantics on the chosen kernel. Do not treat raw inode or PID numbers as permanent identities. Preserve prior LSM denials and do not rely on BPF to override other controls.

Initial BPF policies should support only carefully audited unlimited-use direct resource classes. Finite operations continue to use the broker. Dynamic direct permissions need a distinct authorization point and a clear contract: an allowed open or connect is not one bounded read or HTTP request. Deny or otherwise account for existing file descriptors, memory mappings, inherited sockets, aliases and asynchronous operations. Revocation of direct access may require object lifetime controls or closing/killing the workload; if future mediated use cannot be guaranteed, label that direct capability as non-revocable for its issued lease and do not present it as strictly revocable.

| Candidate hook / subsystem | Intended check | Coverage caveat |
|---|---|---|
| `file_open`, `file_permission` | File access | mmap, splice, existing FDs, kernel-mediated paths require audit |
| `file_receive`, IPC policy | Descriptor receipt | Inheritance, reopening and other acquisition paths |
| `mmap_file`, `file_mprotect` | Mapping/protection | Existing mappings may persist |
| inode mutation hooks | Rename, unlink and related mutations | Alternate names, directory topology and all mutation routes |
| `socket_connect`, `socket_sendmsg` | Network effects | Already-connected sockets, protocols, implicit sends and namespace routing |
| `bprm_check_security` | Execution | Interpreters and executable mappings require separate consideration |
| task/ptrace hooks | Cross-process control | Signals, procfs, pidfds, shared identity and IPC |
| cgroups / seccomp / namespaces | Identity and baseline constraints | Not substitutes for complete resource mediation |

This table is a candidate audit inventory, not a validated hook coverage claim. Confirm hook availability, argument semantics, attachment, LSM stacking and return behavior in the target kernel source; trace each protected effect through all relevant code paths. Record tested kernel build, enabled LSMs, BTF availability, feature probe and policy version. Block launch if mandatory controls are unavailable or cannot attach. Keep the broker-only configuration supported where BPF LSM is unavailable; it must preserve the same protected-effect semantics through stronger baseline isolation.

### 10.3 Policy updates and split-brain prevention

For any direct policy, maintain an explicit authoritative desired-state generation and an installed-policy generation. Do not authorize direct use on stale or partially installed generations. Prefer fail-closed staged installation with an activation gate and removal before acknowledgement of revocation. On broker/manager failure, stop the affected workloads or ensure a kernel-enforced fail-closed lease expires; do not assume a dead broker automatically removes pinned policy. Never maintain independent finite counters in both BPF and Rust. Prove or model the update protocol before supporting dynamic direct grants.

## 11. Persistence, audit and recovery

A single writer serializes ledger transactions. Separate untrusted request parsing from the verified transition core. Before releasing a grant, reservation or externally visible authorization, commit the corresponding state change and request identity to durable storage. A database transaction with correctly configured durability or an append-only write-ahead log may implement this; select one after fault-injection evaluation. Do not claim power-loss durability solely because a library reports success without verifying storage assumptions.

Recommended MVP recovery policy: fail closed across broker restart. Stop existing sandbox trees, invalidate all live session grants, change the authority epoch, preserve spent/nonces and historical audit, and require new human approvals for new privileged sessions. Do not restore live grants until a separate recovery proof and trusted-clock policy exist. Never replay uncertain dispatches. This is simpler than recovering active capabilities and avoids wall-clock rollback extending their lifetime. Use a monotonic time source for in-session expiries; specify behavior across suspend and fail closed if time is invalid. Host rollback of storage or a hostile administrator is outside the MVP threat model; stronger rollback protection would need external durable state or hardware support.

Audit events include sequence, epoch, timestamp, authenticated principal, command/request digest, capability/root/parent IDs, scope summary, budget before/after, policy generation, outcome and adapter effect status. A hash chain can help detect accidental corruption or tampering relative to an externally retained checkpoint; it does not protect against an administrator rewriting the entire history. Avoid storing secret content. Provide an operator-facing lineage view and report uncertain effects distinctly from successful effects.

## 12. Operational examples and expected semantics

### 12.1 One file read

Operator authorizes agent A to read registered object F once, non-delegatable, five-minute expiry. The runtime commits the grant after FIDO2 approval. A requests a bounded snapshot; its balance moves from one to zero before the adapter reads. A second request, a copied identifier used by B, or a transfer to B is denied. If the read fails, the budget remains spent. A may retain bytes it received.

### 12.2 Multi-agent research swarm

Operator grants A 100 HTTPS requests to endpoint E, depth two. A delegates 30 to B and 20 to C, retaining 50. B delegates 10 of its 30 to D with depth zero, retaining 20. Across A, B, C and D the finite budget remains 100. After D uses 3, remaining balance is 97. Revoking B invalidates the remaining B and D balances, without affecting C. The audit identifies the root approval for each attempt. Shared budgets are not necessary for this example.

### 12.3 Compromised harness

A harness changes its own permission mode or requests an unsandboxed retry. Its child remains in the external isolation domain and has no path to protected host files, devices or external network outside the broker. The outer sandbox still denies unauthorized effects. This is an intended integration acceptance test, not a demonstrated guarantee today.

### 12.4 Comparison with conventional tools

Bubblewrap supplies isolation; the platform supplies dynamic, quantitative, delegable authority and independent authorization. Existing systems can implement many individual features with additional proxies, policy management and audit infrastructure. The differentiator is the unified semantics and intended machine-checked implementation, not an assertion that no existing sandbox can provide similar protections. The added privileged runtime is itself an attack surface. For short tasks, a static sandbox may remain simpler and preferable.

## 13. High-level implementation roadmap

| Phase | Goal | Exit gate |
|---|---|---|
| P0 | Freeze threat model and target host | Protected-effect inventory, trust diagram, kernel feature report, chosen MVP semantics |
| P1 | Specify and verify pure Rust authority core | T1–T8 proofs for supported transitions, negative tests, no undocumented proof assumptions |
| P2 | Build durable local broker | Authenticated IPC, serialized spending, replay defense, crash tests and epoch invalidation |
| P3 | Integrate independent hardware approval | Real YubiKey grant, tamper/replay/timeout tests, protected UI channel |
| P4 | Deliver isolated shell demo and file adapter | Two sandboxes, one-use read, bounded delegation, revocation; direct access denied |
| P5 | Add HTTPS and harness compatibility | Controlled requests, no arbitrary network bypass, unmodified harness containment demo |
| P6 | Evaluate BPF LSM direct grants | Hook matrix, pinned kernel, fail-closed update protocol, adversarial coverage for supported class |
| P7 | Harden and release | Reproducible build, proof and test evidence, independent review, documented residual risks |

P0–P4 form the first useful engineering milestone. P5 is the first agent-facing milestone. P6 is optional for initial security and should not block validation of the capability calculus. P7 is a release gate, not a claim of certification. Do not begin with a large general-purpose eBPF sandbox or distributed swarm scheduler; first demonstrate conservation and independent mediation on a tiny system.

## 14. Detailed implementation plan

### WP0 — Project bootstrap and design freeze (P0)

- Create Rust workspace, architecture decision records (ADRs), threat model, protected-effect inventory and proof obligation register. Pin Rust/Verus and a supported Linux test image; use a disposable VM for hostile tests.
- Enumerate host/kernel prerequisites and startup probes. Record namespace, seccomp, cgroup and LSM support. Select an explicit fallback profile that remains secure without BPF LSM.
- Resolve the open semantic decisions in section 16; implement baseline scope, file object model, at-most-once attempts and restart invalidation as written unless a new ADR changes them.
- Deliverables: repository skeleton, build/test CI, example policy, threat model, formal model draft and feature report. Gate: reviewer can map every claimed MVP effect to a planned mediation point.

### WP1 — Scope and identity types (P1)

- Define opaque newtypes, typed operation/scope enums, finite/infinite budget and depth, immutable root snapshots, and normalized expiry types.
- Implement `permits` and conservative `is_subset` for exact files and registered HTTPS endpoints. Keep scope language small and reject unsupported conversions.
- Verify subset soundness, integer arithmetic, identity uniqueness assumptions and scope normalization. Unit-test every rights bit, boundary and mismatched resource.
- Gate: verifier accepts executable functions and all scope negative tests; no unchecked arithmetic or unchecked deserialization in trusted core.

### WP2 — Ledger and primitive transitions (P1)

- Implement deterministic `step` over state; first MINT/CONSUME/DROP, then SPLIT/DELEGATE/TRANSFER/ATTENUATE/REVOKE, then principal lifecycle and time.
- Track consumed and discarded units and immutable lineage. Maintain parent graph acyclicity, unique IDs and finite-allocation boundaries. Bound memory and graph traversal; reject operations exceeding configured limits.
- Verify invariants for each transition and prove trace induction. Add property-based command sequence tests against a simple reference model. Include infinity, zero balance with live descendants, expired ancestors, finite children of unlimited parents and arithmetic overflow.
- Gate: T1–T8 abstract/core obligations pass for all implemented transitions; unsupported actions fail closed. Publish verifier output and trusted assumptions.

### WP3 — Broker, IPC and durable transactions (P2)

- Implement bounded protocol framing, principal authentication, authenticated command construction and single-writer request queue. Keep admin and workload endpoints separate.
- Implement durable transaction with nonce/request redemption, reservation creation and sequence updates. Build duplicate-request detection and immutable request binding.
- Model serialize/commit/dispatch/crash ordering. Inject failures before/after commit, before/after dispatch and before response. Restart invalidates sessions and does not replay uncertain effects.
- Gate: concurrent attempts against a one-use budget dispatch at most once; restart cannot restore grants. Malformed requests do not crash the broker or expand authority. T9–T10 evidence recorded with persistence assumptions.

### WP4 — Hardware authorization (P3)

- Implement operator-only enrollment, public-key storage, canonical payload encoding, random challenge, expiration and credential selection. Use libfido2 through reviewed bindings.
- Implement isolated approval UI with explicit normalized fields, no agent-provided executable markup, one outstanding touch interaction, and deny/timeout path.
- Verify cryptographic assertion and signed presence flag; optionally require UV. Commit nonce redemption and root creation as one transaction.
- Gate: physical YubiKey touch mints exactly the reviewed grant. Changing any bound field, reusing assertion, wrong key, timeout, absent UP or agent attempts to access device/UI cannot mint authority.

### WP5 — Launcher and first adapter (P4)

- Build trusted launch profile, fresh sandbox principal, restricted mounts, cgroups, namespace boundaries, closed FDs, device denial, seccomp and no direct protected network.
- Implement registered file adapter with bounded read and logical-slot replacement semantics; keep protected objects absent from the workload mount namespace. Ensure only the adapter holds its host-side access.
- Build CLI commands `run`, `request`, `inspect`, `delegate`, `revoke`, `stop` and an operator lineage display. CLI cannot directly modify authority storage.
- Demonstrate two shells: no direct host access; touch grants one file read; single-use consumed; second read denied; finite delegation to another sandbox; revoke parent; deny subsequent child use.
- Gate: hostile shell test corpus passes; T11 mediation evidence for supported file operations is reviewed. Any bypass blocks progression.

### WP6 — HTTPS and agent integration (P5)

- Implement registered endpoint adapter and strict request/response bounds. Reject unauthorized redirects, endpoint changes and automatic retries. Keep credentials broker-side.
- Provide SDK and a minimal capability-aware example harness. Add compatibility profile for one existing agent harness with explicitly approved model connectivity; keep its internal sandbox settings outside the trusted decision path.
- Run swarm demo with shared root allocation split among isolated workers. Log conservation and provenance. Test direct networking, proxy bypass, FD sharing and harness escape toggles.
- Gate: one approved request corresponds to at most one adapter dispatch; no workload reaches unregistered network targets in the supported profile; compatibility limitations documented.

### WP7 — BPF LSM research and incremental integration (P6)

- Feature-probe the target kernel, select one direct capability class, inventory all access paths and define exact authorization/revocation semantics before coding.
- Implement minimal BPF policy programs and privileged Rust manager (evaluate libbpf-rs or Aya; choose based on supported hooks and build tooling). Preserve prior denials; protect BPF objects from workloads. Explicitly handle map capacity and unsupported kernel variants.
- Design policy generation protocol, lifecycle cleanup, failure behavior and revocation acknowledgement. Model update races and manager crash. Avoid finite kernel budgets at this stage.
- Run controlled syscall/FD/mapping/namespace tests and review kernel source for alternate paths. Reject direct capability if complete mediation cannot be established; retain brokered alternative.
- Gate: supported resource class has documented hook coverage, tested fail-closed behavior, measured overhead and stated residual limitations. No blanket claim of complete Linux mediation.

### WP8 — Release engineering and independent review (P7)

- Pin dependency versions, minimize privileged dependencies, isolate FFI/unsafe blocks, produce SBOM and reproducible build instructions, sign release artifacts, document installation and recovery.
- Publish formal specification, proof assumptions, CI proof results, test matrices and kernel compatibility list. Benchmark broker overhead and direct policy path; measure rather than predict.
- Commission independent review of the authority core, approval binding, IPC, persistence, launcher and adapters. Address findings and rerun security gates.
- Gate: release scope is limited to actually verified/tested profiles and supported operations. No unresolved critical bypass or unreviewed change to security-critical assumptions.

## 15. Acceptance tests and security evidence matrix

| Test | Expected result | Evidence |
|---|---|---|
| 1,000 concurrent attempts against budget one | At most one dispatch reservation; zero additional effects from retry | Core proof, concurrency test, adapter log |
| Split finite grant repeatedly across descendants | No increase in remaining + consumed + discarded | T1, model/property tests |
| Delegate broader scope, longer expiry or depth | Deny; authority unchanged | T2/T4, unit and fuzz tests |
| Copy capability ID into another sandbox | Deny wrong principal | T3, integration test |
| Non-delegatable grant split or transfer | Deny | T4 |
| Revoke ancestor with zero remaining balance | All descendants deny new authorizations | T5 |
| Race revoke and consume | Matches serial ordering; in-flight effect semantics documented | Model check and integration trace |
| Expire grant or terminate owner | No new owner authorizations | T6, clock/lifecycle tests |
| Reuse approval or mutate signed payload | Deny; no additional root | T7, real authenticator tests |
| Overflow, malformed IPC, huge graph request | Safe denial; bounded resources | T8, fuzzing |
| Crash around commit, dispatch and response | No resurrected grants or replayed uncertain dispatch | T10, fault injection |
| PID/cgroup reuse and stale epoch | No inherited authority | Identity integration tests |
| Try host file aliases, procfs, inherited FDs, Unix sockets | Protected objects inaccessible outside adapter | T11, hostile native tests |
| Symlink/rename and concurrent file mutation | Operation remains bound to registered object or denies | Adapter review and race tests |
| Try direct network, unauthorized redirects and retries | No unapproved destination or extra dispatch | Network namespace and adapter tests |
| Harness asks to escape its own sandbox | Outer confinement unchanged | End-to-end harness test |
| Broker/manager unavailable, map full or LSM missing | Deny or refuse launch; no silent weaker profile | Startup and failure tests |
| Authorized agent proxies for another | Document whether communication permits this; no false non-delegation claim | Threat-model test |

Use a traceability ledger linking every R and T identifier to source code, proof artifact, test and reviewer sign-off. Track proof coverage separately from dynamic test coverage. Any security regression should reproduce in a minimal non-LLM test. Benchmarks should include p50/p95/p99 authorization latency, throughput under concurrent load, memory per capability, revocation latency, startup overhead and effects of policy size; set performance targets after baseline measurement.

## 16. Decisions, residual risks and future work

| Decision | Proposed MVP choice | Reason / trade-off |
|---|---|---|
| Product boundary | External platform, not trusted agent harness | Harness compromise does not intentionally relax confinement |
| Scope | Small typed exact-resource language | Decidable, sound subset checking; less expressiveness |
| Budget | At-most-once attempt, bounded or unlimited | Clear accounting; failed operations consume budget |
| Delegation | Single owner, split/transfer, bounded depth | Simpler proofs; no shared aliases initially |
| Revocation | Recursive, prospective authorization | In-flight operations and previously learned data remain |
| Attenuation | Does not retroactively narrow existing descendants | Clear immutable derivation semantics; revoke for subtree change |
| Concurrency | Single-writer ledger | Easier linearization and verification; possible bottleneck |
| Restart | Terminate sessions and invalidate grants | Conservative; loses live work on restart |
| Finite enforcement | Brokered adapters only | Avoid duplicated balances and ambiguous kernel operation counts |
| Direct enforcement | Optional, audited BPF LSM classes later | Better transparency/performance; harder mediation and revocation |
| Verification | Verus first; model check external protocol | Proofs close to executable code; toolchain assumptions remain |
| Human approval | FIDO2 UP; optional UV, trusted UI | Hardware-backed but not trusted-display consent |
| Isolation | Pinned Linux profile; VM option | Reuse mature controls; kernel remains in TCB |

Open engineering questions: exact kernel version and distro; launcher integration strategy; peer authentication and channel transfer model; persistence backend and durability assumptions; logical file slot identity; trusted approval UI deployment; model API credential handling; choice of BPF toolchain; independent review resources. These must be resolved through ADRs and testing before corresponding features are advertised.

Research extensions: (1) shared resource budgets and weighted costs with typed units; (2) regular safety trace languages and automata, with concurrency interleaving constraints rather than merely child language inclusion; (3) information-flow tracking and authority closure under composition; (4) stronger revocation and cancellation; (5) distributed authority with explicit trust and consensus assumptions; (6) VM-backed isolation and hardware-backed anti-rollback state; (7) proof-carrying adapter refinement and verified policy compiler. None is required to validate the initial product.

## 17. References and implementation resources

The design synthesizes the preceding discussion. These resources are background and implementation starting points; they do not establish that the proposed platform has been built or proven.

- Dennis and Van Horn, *Programming Semantics for Multiprogrammed Computations* (1966), capability-based computing foundations.
- Girard, *Linear Logic* (1987), resource-sensitive logic.
- Drossopoulou et al., *Permission and Authority Revisited: Towards a Formalization* — https://research.google/pubs/permission-and-authority-revisited-towards-a-formalization/
- Granule, graded resource-sensitive programming — https://granule-project.github.io/granule.html
- Iris, concurrent separation logic — https://iris-project.org/
- Verus tutorial and reference — https://verus-lang.github.io/verus/guide/ (primary implementation verification candidate).
- Linux BPF LSM documentation — https://docs.kernel.org/bpf/prog_lsm.html (verify against the chosen kernel).
- Linux Landlock documentation — https://docs.kernel.org/userspace-api/landlock.html (including limitations and ABI considerations).
- Bubblewrap — https://github.com/containers/bubblewrap
- Yubico libfido2 assertion documentation — https://developers.yubico.com/libfido2/Manuals/fido2-assert.html (client-data hash, relying-party ID and presence verification).
- libfido2 source and examples — https://github.com/Yubico/libfido2

**Completion status:** this document is an engineering specification and handoff package. No Rust implementation, kernel hook coverage, authenticator integration, formal verification run, performance measurement or security certification has been performed for this project. All proposed guarantees are targets subject to the assumptions and acceptance gates above.
