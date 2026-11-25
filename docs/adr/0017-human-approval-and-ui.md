# ADR-0017: Human approval: FIDO2 UP (optional UV) through a trusted UI isolated from workloads

- Status: Proposed. The design is accepted. The deployment choice still
  needs evaluation on the target host.
- Spec: §8, §16 "Human approval", R2, T7. Resolves the open question
  "trusted approval UI deployment" provisionally.

## Decision
- Every mint requires user presence (UP). User verification (UV, the PIN)
  is required when the grant policy says so.
- The approval service is a separate process, running as its own uid. It
  holds the hidraw device. It talks to the broker over a private
  socketpair. It renders only broker-normalized fields: subject, target,
  actions, quantity, delegation, lifetime and consequences. Agent-supplied
  text is shown only in a box labelled "untrusted". Markup is never
  executed. One touch is outstanding per authenticator. Requests are
  rate-limited. Deny and timeout paths exist.
- Deployment (provisional): a TTY approval UI on a dedicated virtual
  console, or a terminal under the operator's session, that no sandbox can
  reach. Sandboxes have no access to the display server, the input devices
  or `/dev/hidraw*`. A GUI (Wayland) variant needs a separate review.
- The broker may narrow a request before approval. It never expands one
  afterwards.

## Consequences
- A touch shows presence. It does not show informed consent (§8.2). The
  residual risks are UI deception and approval fatigue.
