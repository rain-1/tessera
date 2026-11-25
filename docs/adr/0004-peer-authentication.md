# ADR-0004: Peer authentication: a dedicated socketpair per sandbox and a SO_PEERCRED check

- Status: Accepted (design). Not implemented. The kernel behaviour must be
  confirmed on the pinned kernel (kernel feature report).
- Spec: §9.1, §9.2, R7, T3. Resolves the open question "peer authentication
  and channel transfer model".

## Context
The broker must not trust a caller's claimed identity. PIDs can be reused. A
shared listening socket would need per-connection credential checks and
would expose a rendezvous point for every sandbox.

## Decision
- Before it execs the workload, the launcher creates
  `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)`. SEQPACKET preserves
  message boundaries. The broker keeps one end. The other end is
  `dup2`'d to a fixed FD number in the sandbox (`TESSERA_FD=3`). Every other
  FD is closed (`close_range`). The broker binds its end to the AgentId that
  the launcher allocated. **The identity is which socket the message arrived
  on.**
- Cross-check: when the channel is registered and periodically afterwards,
  the broker reads `SO_PEERCRED` and `SO_PEERPIDFD` (where available) and
  checks that the peer pid lies inside the sandbox's cgroup. A mismatch kills
  the sandbox and closes the channel. The cross-check is defence in depth.
  It is never the primary identity.
- No filesystem or abstract socket name exists, so another sandbox cannot
  connect. Each sandbox has its own network namespace, which also isolates
  abstract sockets.
- The broker rejects any message that carries ancillary data (SCM_RIGHTS,
  SCM_CREDENTIALS). It sets no `SO_PASSCRED`. It checks `MSG_CTRUNC` and
  closes the channel when ancillary data appears.
- Every process inside the sandbox (forks, subprocesses) shares the
  sandbox's identity (§9.1). `spawn_agent` creates a new sandbox with a new
  socketpair.
- Lending a channel: a sandbox has no route for passing its FD to another
  sandbox. There is no shared Unix socket, no shared mount and pidfd_getfd
  requires ptrace rights, which seccomp denies. An agent can still *act as
  a deputy* for another agent if a communication channel exists between
  them (see threat model residual risks).

## Consequences
- Identity binding is simple to audit, and works without BPF LSM.
- The broker holds one FD per sandbox. This is fine at MVP scale.
- Evidence (planned): copied capability-id test, PID-reuse and stale-epoch
  test, ancillary-data rejection test, and a test that another sandbox cannot
  connect.
