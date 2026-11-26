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
  absolute-form, CONNECT, upgrades, dot segments, encoded separators,
  `;` path parameters, malformed escapes and double encoding
  (`%252e%252e`). The path rules are the HTTPS adapter's
  (`tessera_adapter_https::clean_path`).
- **Request headers are allowlisted.** Only `forward_request_headers` are
  forwarded. The default list is `content-type`, `accept`, `user-agent`,
  `anthropic-version` and `anthropic-beta`. Everything else is dropped,
  including `openai-organization` and `openai-project`, which select the
  billed account. `anthropic-beta` values are filtered again by
  `anthropic_beta_allow`. That list is empty by default, so the header is
  dropped, because betas can enable server-side tools. Credential,
  hop-by-hop, forwarding and `accept-encoding` headers are always
  stripped, even if allowlisted. A request with a `content-encoding`
  other than `identity` is refused with 415: the byte budget would count
  compressed bytes, and the body policy could not read the body. The
  proxy injects `x-api-key: KEY` (`"inject": "x-api-key"`) or
  `authorization: Bearer KEY` (`"inject": "bearer"`).
- Optional **JSON body policy** (`body_policy`). It is on in the shipped
  examples. See below.
- It streams responses, including SSE. If the sandbox stops reading, the
  stream is cut at the idle timeout or the `max_duration` deadline,
  whichever comes first. The upstream connection and the in-flight slot
  are released, and the sandbox connection is closed. A stream that ends
  early never ends with a clean chunked terminator.
- Limits: request body (default 4 MiB), response body, header bytes and
  count, timeouts, and per-sandbox requests/minute, burst, concurrency,
  and lifetime requests, request bytes and response bytes. A request
  takes one of the sandbox's `max_concurrent` in-flight slots **before**
  its body is read. Buffered request bodies are therefore bounded by
  `max_concurrent × max_request_body` per sandbox. Further requests get
  429 without their body being read. `request_header_timeout_ms` (default
  30 s) bounds a request head, including keep-alive idle time.
  `request_read_timeout_ms` (default 60 s) bounds the body.
- Audit: JSON lines to `audit_log` or stderr. Each line records the
  sandbox label, a request `id`, method, path without query, query length,
  status, outcome, byte counts, SHA-256 digests, upstream peer, number of
  redactions and duration. Bodies, header values and the key are never
  logged.
  - An admitted request gets a `forwarded` line **before** anything is
    sent upstream. A completion line with the same `id` follows: `ok`,
    `upstream:<reason>` or `aborted:<reason>`.
  - Refused connections and requests denied locally are rate limited per
    sandbox (`audit_denials_per_second`, default 5; `audit_denials_burst`,
    default 20). Lines over the limit are counted. Every
    `audit_summary_interval_ms` (default 10 s), the proxy writes one
    `suppressed:<outcome>` line per outcome with the count in
    `suppressed`. A sandbox therefore cannot fill the host disk through
    the audit log.
- Each socket is mode 0600 and peer-checked with `SO_PEERCRED`. By
  default only the proxy's uid may connect. Keep the socket in a 0700
  directory.

Error responses use the Anthropic error shape
`{"type":"error","error":{"type":"tessera_proxy_denied", ...}}` with these
statuses:

| Status | Cause |
|---|---|
| 400 | Bad target; body unreadable, too slow, or not a JSON object (body policy) |
| 403 | Route or upgrade not allowed, body policy refusal (`body_policy:<reason>`), or a lifetime budget is exhausted |
| 413 | Request body too large |
| 415 | Request `content-encoding` other than `identity` |
| 429 | Rate or concurrency limit |
| 431 | Request headers too large |
| 502 / 504 | Upstream failure, or upstream timeout. The reason is generic: `destination_forbidden` never carries the resolved address, which only the host audit log records |

### Body policy: defence in depth that depends on provider API shapes

Restricting routes does not stop *provider-side tools*. With them, an
agent can make the **provider** connect to arbitrary hosts on its behalf:

- Anthropic `mcp_servers` (MCP connector);
- Anthropic `web_fetch` / `web_search` / `code_execution` tools;
- OpenAI Responses `mcp` tools (`server_url`) and `web_search`.

That is an egress path that bypasses the empty network namespace.

When `body_policy` is configured, the proxy parses every non-empty
request body on routes with `json_body` (the default). The body is
bounded by `max_request_body` and parsed once. The policy refuses, before
anything is sent upstream:

- a body that is not a single JSON object, or that has a duplicate object
  key (400). Another parser might keep the other value;
- a top-level key in `deny_keys` (default `["mcp_servers"]`);
- any `tools[]` entry whose `type` is present and not in
  `allowed_tool_types` (default `["custom", "function"]`). A tool without
  `type` is a client-side tool and is allowed. `tools` must be an array
  of objects;
- if `max_tokens` is set, a request on a `token_cap` route (the default)
  that carries none of `max_tokens_fields` (default `max_tokens`,
  `max_output_tokens`, `max_completion_tokens`), or one that is not an
  integer at most the cap. Set `"token_cap": false` on routes that
  generate nothing, such as `/v1/messages/count_tokens`;
- if `models` is set, a `model` that is missing or not in the list.

Shipped examples:

- `anthropic-proxy.json` denies `mcp_servers` and `container`, allows
  only `custom` tools and caps `max_tokens` at 64000. Claude Code's own
  tools are client-side. Its `WebSearch` tool uses the server-side
  `web_search` tool and therefore fails, which is intended.
- `openai-proxy.json` denies `prompt` (a stored prompt can carry tools)
  and `web_search_options`, and allows `function`, `custom` and
  `local_shell`. It sets no token cap, because Codex does not send
  `max_output_tokens`.

**Limits of this check.** It knows only the field names and shapes that
providers document today. It is not a parser of the provider's API. A
new provider feature that reaches the network through a different field,
or a provider that accepts a different spelling, is not caught until the
configuration is updated. Treat it as defence in depth on top of the
route allowlist. It does not replace choosing a provider account or
organisation whose server-side tools and connectors are disabled. Keep
`anthropic_beta_allow` short for the same reason.

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
`examples/compat/anthropic-proxy.json`. Its `forward_request_headers`
and `anthropic_beta_allow` list what Claude Code is expected to send.
Betas outside the list are removed silently. If a harness version needs
another beta, check that it does not enable a server-side tool before
adding it. The example's 8 MiB `max_request_body` allows long contexts
with images while keeping `max_concurrent × max_request_body` at 32 MiB.

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

1. **Socket checks.** Model routes need `LauncherConfig.model_socket_dir`,
   an operator-chosen directory owned by the launcher's uid with mode
   0700 that is not `$XDG_RUNTIME_DIR` or `$HOME` (or an ancestor of
   either); the launcher refuses to start otherwise. The launcher
   canonicalises `host_socket` and requires that it lies inside that
   directory, is a socket owned by the launcher's uid with
   `mode & 0o077 == 0`, is not `$SSH_AUTH_SOCK`, and has no path component
   naming a credential agent (`gnupg`, `gpg`, `keyring(s)`, `ssh`,
   `openssh`, split at non-alphanumerics). This keeps the GnuPG and SSH
   agent sockets in `$XDG_RUNTIME_DIR` out of every sandbox (re-review
   2026-11-26 N2). If any check fails, the launch fails with
   `InvalidProfile`.
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

`tessera-launch-run` exposes these as `--model-socket-dir DIR`,
`--model-socket PATH`, `--model-port PORT` and `--netshim PATH`. In
`tesserad`, `ProfileSpec` has `model_route: { socket, loopback_port?,
netshim_path? }` and `launcher.model_socket_dir` is required when any
profile has one; every route is validated at start. The socket and
netshim may not overlap a protected path or a profile workspace root.

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
| Review 2026-11-26: body read only after the in-flight slot is taken (16 stalled 30 MiB uploads: 31 MiB RSS, was 483 MiB); header and body deadlines; rate-limited and summarised audit of refusals; stalled reader released at the deadline and audited (`forwarded` + completion); `;` and double encoding refused; header allowlist, `anthropic-beta` value allowlist, request `content-encoding` refused; body policy (server-side tools, `mcp_servers`, duplicate keys, `max_tokens`, model); no resolved address in errors; examples enable the policy | `tests/review_2026_11_26.rs`; `docs/security-review-2026-11-26-model-proxy.md` |
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
  example configs do not enable them. `previous_response_id` and
  conversation state on OpenAI's Responses API are not filtered.
- **Provider-side tools are an egress path** (threat model R-15). The body
  policy refuses the known shapes (`mcp_servers`, server-side
  `tools[].type`). It depends on provider API shapes and does not see
  features added later. Turn off server-side tools and connectors on the
  provider account as well.
- Token caps are per request. `n` or several choices, retries and
  reasoning tokens are bounded only by the request rate and the byte
  budgets.
- Connections refused at the 64-connection cap cost the host one
  `accept` each. The audit log is protected; the CPU is not.
- The proxy was reviewed on 2026-11-26; see
  `docs/security-review-2026-11-26-model-proxy.md`.
