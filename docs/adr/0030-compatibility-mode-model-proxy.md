# ADR-0030: Compatibility mode: host model proxy, Unix-socket route, loopback shim

- Status: Accepted. Implemented in `crates/model-proxy`
  (`tessera-model-proxy`, `tessera-netshim`), `crates/launcher`
  (`ModelRoute`, `--allow-tcp-port`) and `crates/broker` (`model_route`).
  Tested (unit, local TLS upstream, real sandboxes); not proved; the proxy
  has not been independently reviewed.
- Spec: §3.1, §10.1 (model API connectivity), §12.3, WP6. Implements and
  refines ADR-0020. Threat model R-2, PE-08, PE-09, B-10.

## Context
ADR-0020 chose one baseline route for model API traffic: a Unix socket
bind-mounted into the sandbox, served by a trusted host proxy that holds
the credential. Unmodified harnesses must use it without code changes.
Claude Code can send HTTP over a Unix socket (`ANTHROPIC_UNIX_SOCKET`,
checked against Claude Code 2.1.332). Codex cannot; it needs a TCP
`base_url`. The launcher's Landlock ruleset denied all TCP bind and
connect.

## Decision

1. **Proxy (`tessera-model-proxy`).** One process per host (or per
   session), one 0600 Unix socket per sandbox, checked with
   `SO_PEERCRED` (same uid by default). Plain HTTP/1.1 from the sandbox.
   - Exactly one upstream. The proxy does its own DNS, rejects every
     non-global address (`tessera_adapter_https::is_forbidden`; a mixed
     answer is rejected), validates TLS with webpki roots or an
     operator-supplied CA (never the system store), and opens a fresh
     connection per request with hyper's low-level client. There are no
     redirects, retries, pooling or proxy discovery (as in ADR-0007).
   - It forwards only origin-form requests that match an allowlisted
     method and path (exact or prefix). The query is allowed per route.
     Dot segments, encoded dot/slash/backslash/NUL, absolute-form,
     CONNECT and upgrades are refused.
   - It strips client credentials (`authorization`, `x-api-key`,
     `api-key`, `x-goog-api-key`, `proxy-*`, `cookie`), hop-by-hop,
     forwarding and `accept-encoding` headers. It injects the credential
     as `x-api-key` or `authorization: Bearer`.
   - Responses are streamed (SSE). The proxy drops credential-named
     headers, cookies, `content-encoding`, framing headers, and **any
     header whose value contains the credential**. It forces
     `accept-encoding: identity` upstream so it can scan the body with a
     streaming redactor. The redactor replaces verbatim occurrences, also
     across chunk boundaries, and holds back only a tail that is a prefix
     of the secret.
   - Limits per request: request head size, header count, body size,
     response size, read, connect, header, idle and total time. Limits per
     sandbox: token-bucket rate, concurrency, and lifetime totals for
     requests, request bytes and response bytes. Rate and concurrency
     answer 429. Exhausted lifetime budgets answer 403, so harnesses stop
     retrying.
   - It writes one JSON audit line per request: sandbox label, method,
     path (no query), query length, status, outcome, byte counts,
     SHA-256 digests, upstream peer and redaction count. Bodies, header
     values and the credential are never logged.
2. **Unix-socket route (preferred).** `LaunchProfile::model_route`
   binds the socket read-only at `/.tessera/model.sock` and sets
   `TESSERA_MODEL_SOCKET`. The launcher refuses a socket that is not a
   socket, is not owned by the launcher's uid, has any group or other
   permission bits, or is `SSH_AUTH_SOCK`. This rules out Docker, D-Bus
   and agent sockets. No network change is needed.
3. **Loopback shim (only for harnesses that need TCP).**
   `ModelRoute::loopback = { port, netshim_path }`:
   - The launcher binds `tessera-netshim` at `/.tessera/netshim`.
   - The init shim adds one Landlock `NetPort` rule allowing `BindTcp` and
     `ConnectTcp` on that port only. Every other port stays denied.
   - The workload runs as `netshim --listen 127.0.0.1:PORT --socket
     /.tessera/model.sock -- PROGRAM ARGS`.
   - The netns stays empty, so the port reaches only the loopback
     interface.
   - Fail closed: the launcher refuses a loopback port unless
     `LandlockRequirement::Required` (ABI ≥ 6, fully enforced) is in
     force, and the init shim refuses `--allow-tcp-port` otherwise.
   - The shim is untrusted plumbing and runs as the workload. Replacing
     it gains nothing, because the only destination is the same proxy
     socket.
4. **Broker.** `ProfileSpec.model_route = { socket, loopback_port?,
   netshim_path? }` in the `tesserad` configuration. The launch record
   carries the route.

## Consequences
- **The route is an unmediated, unlimited-use baseline channel.** It
  costs no capability units and needs no approval, and it lasts for the
  life of the sandbox. The budgets are operator resource limits, not
  authority.
- **The model context is a disclosure channel (R-2).** Anything the agent
  can read can be sent to the provider, for example in prompts, tool
  results or file uploads. Restricting the endpoint and the routes does
  not change this. Do not give a compat principal protected reads unless
  that disclosure is acceptable. Two sandboxes on one provider account can
  relay through provider-side state if a route exposes it. The default
  routes do not include files, batches or threads APIs.
- **Residual credential echo risk.** Only verbatim echoes of the
  credential are removed. Header values and the identity-encoded body are
  scanned. An upstream that returns a *transformed* credential (base64,
  split across JSON escapes, hashed, partially masked) is not caught. The
  provider is trusted not to do this. A prefix of the key held back at the
  end of a chunk is released at stream end.
- `UDP` is not restricted by Landlock. In the empty netns it reaches
  nothing.
- Harness-internal permission modes stay outside the trusted path
  (§12.3). `compromised_harness_stays_contained` exercises this.
- The proxy is a new trusted component and needs independent review
  (ADR-0021).
