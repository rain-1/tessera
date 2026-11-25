# Compatibility mode: unmodified agent harnesses

Compatibility mode (spec §3.1, §10.1, WP6; ADR-0020, ADR-0030) runs an
**unmodified** agent harness, such as Claude Code (`claude`) or Codex
(`codex`), inside a Tessera sandbox. The sandbox has:

- an empty network namespace;
- no host credentials, no host sockets and a clean environment;
- one route to the model API: a Unix socket served by the trusted host-side
  **model proxy** (`tessera-model-proxy`), which holds the API key.

```text
 sandbox (empty netns, Landlock, seccomp)            host
 ┌──────────────────────────────────────┐   ┌───────────────────────────────┐
 │ claude ── HTTP over unix socket ─────┼──▶│ tessera-model-proxy           │
 │   ANTHROPIC_UNIX_SOCKET=             │   │  route allowlist, strip auth, │
 │     /.tessera/model.sock             │   │  inject key, limits, audit    │
 │                                      │   │        │ TLS (own DNS,        │
 │ codex ─ TCP 127.0.0.1:18080 ─ netshim┼──▶│        ▼ global addrs only)   │
 │   (Landlock: bind+connect this port) │   │  https://api.anthropic.com    │
 └──────────────────────────────────────┘   └───────────────────────────────┘
```

## Read this first: what this channel is

- **It is an unlimited-use baseline channel.** Model traffic is an
  unmediated baseline effect (B-10, PE-08). It costs no capability units,
  needs no approval and is available for the whole life of the sandbox.
  The proxy's rate and byte budgets are operator resource limits, not
  authority.
- **Model context is a disclosure channel (threat model R-2).** Any data
  the agent can read, such as workspace files or tool output, can be sent
  to the model provider. Restricting the endpoint does not prevent this.
  Do not combine compatibility mode with protected reads unless that
  disclosure is acceptable.
- **The credential never enters the sandbox.** The proxy strips
  client-supplied auth headers and injects the host key. It drops response
  headers containing the key and replaces verbatim echoes of the key in
  response bodies with `[REDACTED-BY-TESSERA]`. Residual risk: an upstream
  that echoes a *transformed* key (base64, hashed, split by escapes) is not
  caught. See ADR-0030.

## Components

| Piece | Where | Trust |
|---|---|---|
| `tessera-model-proxy` | host, one per operator session (or per sandbox) | **trusted**: holds the key, enforces routes and limits |
| `ModelRoute` in `LaunchProfile` | `crates/launcher` | trusted: binds the socket, adds the optional Landlock port rule |
| `model_route` in `ProfileSpec` | `crates/broker` (`tesserad` config) | trusted operator configuration |
| `tessera-netshim` | inside the sandbox, only for TCP-only harnesses | **untrusted plumbing**: no policy, no secret |

### Proxy behaviour (summary)

- Exactly one upstream. The proxy resolves the name itself and refuses any
  loopback, private, link-local, CGNAT, ULA, multicast, documentation or
  other non-global address, unless the operator sets `allow_private` for
  tests or an internal gateway. It validates TLS with webpki roots or a
  configured CA. It opens a new connection per request. There are no
  redirects, retries or proxy discovery.
- It accepts only origin-form requests whose method and path match a
  configured route: `exact`, which is the default, or `prefix`. It refuses
  absolute-form, CONNECT, upgrades, dot segments and encoded separators.
- It strips `authorization`, `x-api-key`, `api-key`, `x-goog-api-key`,
  `proxy-*`, `cookie`, hop-by-hop, forwarding and `accept-encoding`
  headers. It injects `x-api-key: KEY` (`"inject": "x-api-key"`) or
  `authorization: Bearer KEY` (`"inject": "bearer"`).
- It streams responses, including SSE.
- Limits: request body, response body, header bytes and count, timeouts,
  and per-sandbox requests/minute, burst, concurrency, and lifetime
  requests, request bytes and response bytes.
- Audit: one JSON line per request to `audit_log` or stderr. Each line
  records the sandbox label, method, path without query, query length,
  status, outcome, byte counts, SHA-256 digests, upstream peer, number of
  redactions and duration. Bodies, header values and the key are never
  logged.
- Each socket is mode 0600 and peer-checked with `SO_PEERCRED`. By
  default only the proxy's uid may connect. Keep the socket in a 0700
  directory.

Error responses use the Anthropic error shape
`{"type":"error","error":{"type":"tessera_proxy_denied", ...}}` with these
statuses:

| Status | Cause |
|---|---|
| 400 | Bad target |
| 403 | Route or upgrade not allowed, or a lifetime budget is exhausted |
| 413 | Request body too large |
| 429 | Rate or concurrency limit |
| 431 | Request headers too large |
| 502 / 504 | Upstream failure, or upstream timeout |

## Harness recipes

### Claude Code: Unix socket, no TCP

Claude Code supports HTTP over a Unix socket. This was checked against
version 2.1.332 by running it unmodified in a real Tessera sandbox against
a local fake upstream; see "Evidence" below. Set:

| Variable | Value | Why |
|---|---|---|
| `ANTHROPIC_UNIX_SOCKET` | `/.tessera/model.sock` | the bind-mounted proxy socket |
| `ANTHROPIC_BASE_URL` | `http://localhost` | send **plain** HTTP on the socket. With the default `https://` base URL, Claude Code tries TLS over the socket; the proxy refuses this and logs `denied:tls_on_plain_http_socket` |
| `ANTHROPIC_API_KEY` | `tessera-placeholder` | satisfies the login check; the proxy strips it |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_AUTOUPDATER` | `1` | avoid pointless egress attempts (they fail anyway) |

Routes needed: `POST /v1/messages` (with a `?beta=true` query) and
`POST /v1/messages/count_tokens`. `GET /v1/models` is optional. See
`examples/compat/anthropic-proxy.json`.

Run it with `examples/compat/run-claude.sh WORKSPACE -p "..."`. The script
starts the proxy, then calls `tessera-launch-run --model-socket ...`.
With `tesserad`, use the `claude` profile in
`examples/compat/tesserad-profiles.json`.

### Codex: loopback TCP through `tessera-netshim`

Codex has no HTTP-over-Unix-socket option for model providers. The
profile therefore adds a loopback shim:

```json
"model_route": { "socket": "/run/user/1000/tessera/codex-1/model.sock",
                 "loopback_port": 18080,
                 "netshim_path": "/usr/libexec/tessera/tessera-netshim" }
```

and Codex is configured with `examples/compat/codex-config.toml`
(`base_url = "http://127.0.0.1:18080/v1"`, no `env_key`). The proxy uses
`examples/compat/openai-proxy.json` (`"inject": "bearer"`, routes
`POST /v1/responses`, `GET /v1/models`). Only API-key mode is supported.
ChatGPT sign-in uses other hosts and is not routed.

> Status: the shim → proxy → upstream path is tested in a real sandbox
> with a stub harness (`compat_sandbox.rs`). Running the real `codex`
> binary through it has **not** been exercised. Codex's Responses
> streaming against a fake upstream is future work.

## Launcher integration (implemented)

`LaunchProfile::model_route(ModelRoute { host_socket, loopback })` works as
follows.

1. **Socket checks.** The launcher canonicalises `host_socket` and requires
   that it is a socket, owned by the launcher's uid, with
   `mode & 0o077 == 0`, and is not `$SSH_AUTH_SOCK`. If any check fails,
   the launch fails with `InvalidProfile`.
2. **Binding.** bwrap binds the socket read-only at
   `/.tessera/model.sock`. Connecting to a socket on a read-only mount is
   allowed; unlinking or replacing it is not. The launcher sets
   `TESSERA_MODEL_SOCKET=/.tessera/model.sock`.
3. **With `loopback: Some(LoopbackShim { port, netshim_path })`:**
   - The launcher **requires `LandlockRequirement::Required`**, otherwise
     it returns `InvalidProfile`.
   - It binds the netshim read-only at `/.tessera/netshim` and adds that
     path to the init shim's Landlock read and execute set.
   - It passes `--allow-tcp-port PORT` to `tessera-sandbox-init`. The init
     shim keeps handling `BindTcp | ConnectTcp` and adds exactly one
     `NetPort(PORT, BindTcp | ConnectTcp)` rule. It refuses the flag
     unless Landlock is `required`. A `Required` launch still demands a
     `FullyEnforced` ruleset, so a kernel without Landlock network support
     (ABI < 4) fails closed.
   - It runs the workload as `/.tessera/netshim --listen 127.0.0.1:PORT
     --socket /.tessera/model.sock -- PROGRAM ARGS`. The shim binds first,
     then runs the program and exits with the program's status.
   - It sets `TESSERA_MODEL_PORT=PORT`.
   - The network namespace stays empty: `--unshare-net` with loopback
     only. Every other TCP port is denied, both bind and connect, and so
     is every non-loopback destination.
4. **Launch record.** `LaunchRecord.model_route` records the route.

`tessera-launch-run` exposes these as `--model-socket PATH`,
`--model-port PORT` and `--netshim PATH`. In `tesserad`, `ProfileSpec`
has `model_route: { socket, loopback_port?, netshim_path? }`.

## Evidence

| Claim | Test |
|---|---|
| Allowed route forwarded with the injected key; client `authorization`, `x-api-key`, cookies and `Host` replaced; credential echoed by upstream in headers and body is not returned; audit has no body, query or key | `crates/model-proxy/tests/proxy.rs` `allowed_route_forwarded_with_injected_key_and_client_auth_stripped`, `bearer_injection` |
| Disallowed method, path, prefix boundary, dot segments, absolute-form, CONNECT and upgrade are refused and never reach upstream | `disallowed_requests_never_reach_upstream` |
| Non-global upstream refused; wrong CA and wrong name fail TLS | `non_global_upstream_address_refused_by_default`, `tls_validation_wrong_ca_and_wrong_name` |
| Redirects returned, not followed | `redirects_are_returned_not_followed` |
| Request body, head and response size limits; truncated stream does not end cleanly | `size_limits` |
| SSE streamed incrementally | `sse_is_streamed_incrementally` |
| Rate limit, request and byte budgets | `rate_limit_and_budgets` |
| Socket 0600; TLS-on-plain-socket detected | `socket_mode_and_tls_on_plain_socket` |
| Shim forwards bytes both ways with half-close | `tests/shim.rs`, `shim_forwards_to_proxy_end_to_end` |
| Real sandbox: stub harness → shim → proxy → fake TLS upstream with the injected key; direct connect (host upstream port, 1.1.1.1, IPv6), other loopback ports (bind and connect), UDP and DNS all fail; no credential-shaped token in env, `/proc/*/environ`, `/proc/*/cmdline`, files or responses | `tests/compat_sandbox.rs` `compat_sandbox_reaches_model_only_through_proxy` |
| §12.3: the harness rewrites its own permission settings and tries `unshare`, `sudo`, `su`, `nsenter`, a host binary path, unlinking the socket, overwriting the netshim, binding the shim port and direct egress; outer confinement holds | `compromised_harness_stays_contained` |
| Fail closed: loopback port without Required Landlock; non-socket or world-accessible socket | `loopback_port_requires_required_landlock`, `model_socket_must_be_private_socket`; `init.rs` `tcp_port_exception_parsing_and_fail_closed` |
| Unmodified Claude Code 2.1.332 completes `claude -p` in a Tessera sandbox via `ANTHROPIC_UNIX_SOCKET` | manual, `examples/compat/run-claude.sh` with `PROXY_CONFIG` pointing at a local fake TLS upstream (`pinned_addrs: ["127.0.0.1"]`, `allow_private: true`, `ca_pem_file`) and a fake key; never the real API |

## Limitations

- Only verbatim credential echoes are redacted (ADR-0030).
- One TCP connection to the provider per request. There is no pooling, so
  each request pays a TLS handshake.
- The audit log records paths and sizes, not content. It cannot show what
  was disclosed (R-2).
- Provider-side state, such as files or batches APIs, is a relay channel
  between sandboxes on the same account if such routes are enabled. The
  example configs do not enable them.
- The proxy itself has not been independently reviewed (ADR-0021).
