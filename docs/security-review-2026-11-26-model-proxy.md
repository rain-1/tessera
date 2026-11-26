# Security review of the model proxy, 2026-11-26

Scope: `crates/model-proxy` (`tessera-model-proxy`), the trusted host-side
proxy for compatibility mode ([ADR-0030](adr/0030-compatibility-mode-model-proxy.md),
[compat.md](compat.md)), at main `0a72a52`. The reviewer's reproducers
(F-1 to F-5 and probes for request smuggling) were ported into
`crates/model-proxy/tests/review_2026_11_26.rs`. Each test asserts the
fixed behaviour. Run against the pre-fix code (with the two new audit
fields removed so that it compiles), 15 of its 16 tests failed. The 16th,
`f1_body_deadline_releases_permit`, is a guard that already passed.
Fixed on branch `wp/proxyfix`; ADR-0030 was amended.

The smuggling probes (CL+TE, duplicate `content-length`, obs-fold, a space
before the colon, bare LF, `transfer-encoding: identity, chunked`,
pipelining, absolute-form) found nothing. hyper rejects or normalises
each of them, and the proxy re-frames every request upstream.

## Findings and status

| # | Sev | Finding (as reported) | Fix | Regression test | Status |
|---|---|---|---|---|---|
| F-1 | Medium | `server.rs` read the whole body (up to 32 MiB) before `budget.admit()` checked `max_concurrent`. 16 stalled 30 MiB uploads grew RSS by 483 MiB, and there was no body-specific slow-loris bound. | `Budget::acquire` takes the in-flight slot **before** the body is read; the token bucket and lifetime totals are charged afterwards (`Budget::charge`). Further requests get 429 unread. Default `max_request_body` lowered to 4 MiB (configurable). The example sets 8 MiB. New `request_header_timeout_ms` (default 30 s, also bounds keep-alive idle and the first byte); `request_read_timeout_ms` bounds the body. | `f1_body_not_buffered_before_admission` (same scenario: RSS +31 MiB, 15 × `denied:too_many_in_flight`), `f1_header_deadline`, `f1_body_deadline_releases_permit`; `config::tests::minimal_config_defaults` | **FIXED** |
| F-2 | Medium | `local_event` wrote one audit line for every refused connection (peer uid, connection cap, TLS on the plain socket): about 53k lines/s, enough to fill the host disk. Locally denied requests on a keep-alive connection had the same problem. | Per-sandbox `EventLimiter` (token bucket; `audit_denials_per_second` 5, `audit_denials_burst` 20) for refused connections **and** every request denied before reaching the upstream. Suppressed lines are counted per outcome. The accept loop writes `suppressed:<outcome>` records with a `suppressed` count every `audit_summary_interval_ms` (10 s). | `f2_refused_connections_rate_limited_and_summarised` (51,720 connects → 14 lines plus summaries accounting for the rest), `f2_denied_requests_rate_limited` (301 pipelined denials → ≤ 20 lines; lines + summaries = 301); `audit::tests::event_limiter_counts_suppressed_lines` | **FIXED** |
| F-3 | Medium | `Pump::run` called `tx.send(..).await` with no deadline. A sandbox that stopped reading pinned the in-flight permit and the upstream connection forever, and the request was never audited. | A `forwarded` record (with a new `id`, sizes and the request digest) is written before the upstream is contacted. The completion record has the same `id`. Sends use `timeout_at(min(max_duration deadline, now + idle))`. A `select!` on `tx.closed()` stops the pump as soon as the sandbox goes away, even while it waits for the upstream. On `client_stalled`/`max_duration` the sandbox connection is closed. The permit, the upstream driver and the channel are dropped on every exit. A stream that stops early ends the body with an error instead of a clean `0\r\n\r\n`. The channel shrank from 32 to 8 chunks. | `f3_stalled_reader_released_and_audited` (permit free, 0 upstream connections, `forwarded` + `aborted:client_stalled`), `f3_client_close_stops_pump`, `f3_forwarded_record_precedes_upstream_failure`; `proxy.rs` `allowed_route_forwarded_…` (pairs the records), `size_limits` (truncated stream not clean) | **FIXED** |
| F-4 | Low | `policy.rs` `clean_path` accepted `;`, `%25` followed by hex, and segments that decode to dot segments (`/v1/models/..;/messages`, `/v1/models/%252e%252e/files`). | `policy::clean_path` now calls `tessera_adapter_https::clean_path`. That function was made `pub` (a one-line change in `adapters/https`), so the proxy and the adapter share one rule set (6050055). Route paths in the configuration are checked with the same function. | `f4_semicolon_and_double_encoding_refused`; `policy::tests::targets` | **FIXED** |
| F-5 | Medium/Low | The default forwarded every request header that was not on the denylist. `openai-organization` and `openai-project` (select the billed account), `anthropic-beta` (enables server-side tools) and `content-encoding` (the budget counted compressed bytes) all passed through. | Request headers are an **allowlist**. The default is `content-type`, `accept`, `user-agent`, `anthropic-version`, `anthropic-beta`. Each example sets a per-provider list. `anthropic-beta` values are filtered by `anthropic_beta_allow` (empty by default; the example lists three Claude Code betas), merged and de-duplicated. A request with any `content-encoding` other than `identity` is refused with 415; `content-encoding` is always stripped. Headers named in `Connection` still cannot remove the injected key. | `f5_selection_headers_not_forwarded`, `f5_anthropic_beta_value_allowlist`, `f5_request_content_encoding_refused`; `policy::tests::header_filtering` | **FIXED** |
| S-1 | High impact (design gap) | Provider-side tools let the agent make the **provider** reach arbitrary hosts: Anthropic `mcp_servers`, `web_fetch` and `web_search`; OpenAI Responses `mcp` (`server_url`) and `web_search`. | Optional JSON body policy (`body_policy`, `src/body.rs`), on in both shipped examples. On routes with `json_body` (default true), a non-empty body must be a single JSON object without duplicate keys (400 otherwise). Bodies are bounded by `max_request_body`, and nesting by serde_json's recursion limit. It refuses (403) any top-level key in `deny_keys` (default `mcp_servers`; the Anthropic example adds `container`, the OpenAI example `prompt` and `web_search_options`) and any `tools[].type` outside `allowed_tool_types` (default `custom`, `function`; a tool without `type` is client-side). Documented as defence in depth that depends on provider API shapes, and added as threat-model residual risk R-15. | `s1_body_policy_refuses_server_side_tools` (MCP connector, web_fetch, web_search, OpenAI `mcp` and `web_search`, `tools` not an array, non-string type, escaped key `mcp_servers`, duplicate `tools`, non-JSON, array, trailing data; client tools and tool names inside message text allowed; GET unaffected); `body::tests::*`; `example_configs_enable_body_policy` | **MITIGATED** (shape-dependent; see residual risks) |
| S-2 | Budget | No per-request output cap and no model restriction. | `body_policy.max_tokens`: on routes with `token_cap` (default true; the example sets false for `count_tokens`), a request must carry one of `max_tokens_fields` (`max_tokens`, `max_output_tokens`, `max_completion_tokens`), and each present field must be an integer at most the cap. `body_policy.models`: `model` must be a listed string. The Anthropic example caps at 64000. The OpenAI example sets no cap, because Codex does not send `max_output_tokens`. | `s2_max_tokens_cap_and_model_allowlist`; `body::tests::caps`; `config::tests::body_policy_defaults` | **FIXED** (optional) |
| S-3 | Low | The error reason `destination_forbidden:<ip>` told the sandbox the resolved address. | `UpstreamError::client_reason()` returns the generic `destination_forbidden` to the sandbox. The audit log keeps `upstream:destination_forbidden:<ip>`. | `s3_destination_forbidden_detail_not_returned` | **FIXED** |

## Other changes

- Audit records gained `id` (pairs `forwarded` with its completion record)
  and `suppressed` (only on summaries). Consumers that counted one line
  per request must now count completion records, or `forwarded` records.
- `ProxyBody` is now opaque. Its variants were never meant as API.
- `Budget::acquire`, `Budget::charge` and `Budget::in_flight` were added.
  `Budget::admit` is now `acquire` + `charge`.

## Residual risks

- **Body policy depends on provider API shapes.** It checks documented
  field names (`mcp_servers`, `tools[].type`, the token fields, `model`).
  A new provider feature that makes the provider reach the network
  through another field is not caught until `deny_keys` or
  `allowed_tool_types` is updated. Disable server-side tools and
  connectors on the provider account as well (threat model R-15).
- **`anthropic-beta` and header lists are per harness version.** The
  example lists were chosen from what Claude Code and Codex send. They
  were not re-checked against a live harness in this change. A missing
  beta silently disables a feature. An added beta can enable a
  server-side tool, so review it before adding it.
- **Token cap is per request.** Retries, several choices and reasoning
  tokens are bounded only by the rate and byte budgets. Codex has no cap
  in the example.
- **Disclosure (R-2) is unchanged.** The body policy does not inspect
  prompt content.
- **Connection-cap refusals still cost CPU.** The audit log is protected,
  but each refused connect is still one `accept` on the host. It is
  bounded by the sandbox's CPU and cgroup limits.
- **Memory bound is per sandbox:** `max_concurrent × max_request_body`,
  plus up to 64 connections × (header buffer + 8 response chunks). There
  is no process-wide cap across sandboxes.

## Verification

- `cargo test --workspace`, `cargo clippy --workspace --all-targets -D warnings`
  and `cargo fmt --check` all pass.
- `make adversarial`: all probes contained.
- `scripts/demo.sh`: demo OK.
