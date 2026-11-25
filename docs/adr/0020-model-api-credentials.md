# ADR-0020: Model API connectivity and credentials (P5 harness profile)

- Status: Proposed. Not needed for the P4 shell demo.
- Spec: §3.1, §10.1. Open question "model API credential handling".

## Decision
A harness profile that needs a model API gets **one** baseline route: a
Unix socket bind-mounted into the sandbox, leading to a trusted local
forwarding proxy. The proxy accepts requests only to the configured
provider endpoint. It injects the API credential, which the workload never
sees. It applies the size and rate limits. It logs request digests. The
workload has no other network route. This route is an *unmediated baseline
effect*: it costs no capability units, and it is listed in
`protected-effects.md`.

## Consequences
- **The model API is a disclosure channel.** Anything the workload can read
  can be sent to the provider in a prompt (threat model residual risk R-2).
  Restricting the endpoint does not prevent this. Profiles that combine
  protected reads with model access must accept this risk explicitly.
- The proxy is a new trusted component and needs its own review.
