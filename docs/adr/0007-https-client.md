# ADR-0007: HTTPS adapter client: no redirects or retries, own DNS and address-class filtering

- Status: Accepted (design). Not implemented (P5).
- Spec: §9.4, §5.2, WP6

## Context
One capability unit = one outbound HTTP request attempt (§9.4). A general
HTTP client may follow redirects, retry on its own, reuse proxies from
environment variables, or resolve a hostname to an internal address (DNS
rebinding). Any of these could make one unit produce more than one request,
or send it to a destination nobody approved.

## Decision
- Use a minimal client: `hyper` (HTTP/1.1 only in the MVP) over `rustls`
  with `webpki-roots` or a pinned CA set. Do not use a client stack that
  has implicit redirect or retry behaviour, or turn those features off and
  cover them with tests.
- **Redirects:** never followed. A 3xx is returned to the agent as the
  result of the one attempt.
- **Retries:** none. Connection reuse is off: each authorized attempt opens
  a new connection, so a hidden replay on a pooled connection cannot happen.
- **No proxies:** the client ignores the environment, `HTTP(S)_PROXY` and
  the system configuration. CONNECT tunnelling is not offered.
- **DNS:** the adapter resolves the registered endpoint's hostname itself
  (with a pinned resolver configuration). It filters *every* resolved
  address by class: it denies loopback, link-local, RFC1918, CGNAT, ULA,
  multicast, unspecified, IPv4-mapped IPv6 of denied classes, and
  NAT64-embedded addresses of denied classes. The exception is an endpoint
  the operator registered with an explicit internal address class. The
  adapter connects to the exact address it validated, never to a name it
  resolves again later. SNI and certificate validation use the registered
  hostname.
- Request and response sizes are capped, and the cap is enforced while
  streaming. Timeouts apply. Secrets come from the broker-owned credential
  store and are injected into headers. They are never returned to the
  agent.
- The reservation is committed before the socket is opened (ADR-0001/0002).
  After a crash the attempt is `unknown`. It is never re-sent.

## Consequences
- Some legitimate APIs need redirects. Each such case needs its own grant.
- Exactly-once remote effects are not claimed. Remote idempotency keys are
  future work.
