# Installing Tessera

This guide covers host prerequisites, building, enrolling an approval key
and configuring `tesserad`. It describes the code as it is in this
repository (spec v0.1, early implementation). Read the status table in the
[README](../README.md) before relying on anything here.

To check that it works end to end, run `scripts/demo.sh`. It starts a real
`tesserad`, launches a real sandbox, approves a grant with a software key
and reads a file through the broker (see [operations](operations.md)).

## 1. Host prerequisites

Tessera runs on Linux x86_64 only. The launcher refuses to start if a
mandatory control is missing. It never falls back to a weaker profile
(R10, ADR-0005). Check the host with the probe:

```sh
cargo run -p tessera-launcher --bin tessera-launch-probe
# exit 0: launch allowed; exit 2: refused, see "missing_mandatory"
```

[`kernel-feature-report.md`](kernel-feature-report.md) has the probe output
from the reference host (Debian 13, Linux 6.12).

| Requirement | Why | How to check / enable |
|---|---|---|
| Linux ≥ 6.12 (Landlock ABI 6) | Landlock fs + TCP + abstract-socket/signal scoping; the init shim pins ABI 6 and `landlock: "required"` is the default | `cat /sys/kernel/security/lsm` must list `landlock`; probe field `landlock.abi` |
| bubblewrap ≥ 0.8.0 at `/usr/bin/bwrap` | namespace sandbox (`--disable-userns`) | `apt install bubblewrap`; it is never looked up in `$PATH`. A different path goes in `launcher.bwrap_path` |
| Unprivileged user namespaces | bwrap runs without setuid | see below |
| seccomp-BPF | syscall filter (io_uring, bpf, userfaultfd, perf, ... denied) | `grep Seccomp /proc/self/status` |
| cgroup v2 delegated to the broker user, controllers `cpu memory pids`, `cgroup.kill` | per-sandbox memory/pids limits and whole-tree kill | see below |
| Python 3 (tests only) | adversarial corpus, model checker | |

### User namespaces

Debian and Fedora allow unprivileged user namespaces by default. Ubuntu
23.10 and later restrict them through AppArmor. bwrap then fails with
`setting up uid map: Permission denied`. Either add an AppArmor profile
that allows `userns` for `/usr/bin/bwrap`, or turn the restriction off for
the whole host:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/60-tessera-userns.conf
```

On older Debian kernels, `kernel.unprivileged_userns_clone` must be `1`.
CI does the same thing (`.github/workflows/ci.yml`, "Sandbox
prerequisites").

### cgroup v2 delegation

The launcher looks for the highest ancestor of its own cgroup that is owned
by the broker's uid and enables `cpu memory pids`. Under it, the launcher
creates `tessera.launcher/<agent>-<unique>` leaves. In practice:

* **Desktop / login session:** systemd already delegates
  `user@UID.service`, so nothing needs to be done.
* **System service:** run `tesserad` as a dedicated user from a unit with
  `Delegate=yes` (see the unit below).
* **CI or a shell without a session:** use a transient unit:
  `sudo systemd-run --wait --pipe --uid=$(id -u) --gid=$(id -g) -p Delegate=yes <cmd>`.

If delegation is not possible, set `launcher.cgroup_opt_out_reason` in the
configuration. This is an explicit operator opt-out: there are no resource
limits, and stopping a sandbox relies on PID-namespace teardown only. The
reason is logged on every launch.

## 2. Building

```sh
rustup show                                  # installs the toolchain from rust-toolchain.toml
cargo build --release --locked -p tessera-broker -p tessera-cli -p tessera-launcher --bins
```

Binaries (`target/release/`):

| Binary | Runs as | Purpose |
|---|---|---|
| `tesserad` | broker user | the broker daemon |
| `tessera-admin` | broker user (operator) | operator CLI on the admin socket |
| `tessera-sandbox-init` | inside each sandbox | closes inherited fds, applies Landlock, then execs the workload |
| `tessera` | inside sandboxes | agent CLI (untrusted client) |
| `tessera-launch-probe` | anyone | host capability report |
| `tessera-launch-run` | developer | launch one sandbox by hand (adversarial tests) |

For hardware tokens, build `tessera-admin` with libfido2's command-line
tools on `$PATH`:
`cargo build --release --locked -p tessera-broker --features fido2-cli`.
This path is **untested against real hardware**.

For release builds (pinned toolchain, `SOURCE_DATE_EPOCH`, path remapping,
checksums) see [release.md](release.md).

Suggested layout:

```sh
sudo install -d -m 0755 /usr/libexec/tessera
sudo install -m 0755 target/release/tessera-sandbox-init target/release/tessera /usr/libexec/tessera/
sudo install -m 0755 target/release/tesserad target/release/tessera-admin /usr/local/bin/
```

## 3. Broker user and directories

The broker stores its journal and audit log in `state_dir`. At startup it
checks that the broker's effective uid owns the directory and sets its mode
to 0700. The admin socket must be in a directory owned by the broker uid
that is not group- or world-writable. The socket is created with mode 0600,
and every connection's `SO_PEERCRED` uid must equal the broker's uid. **The
operator runs `tessera-admin` as the broker user.**

```sh
sudo useradd --system --create-home --home-dir /var/lib/tessera tessera
sudo install -d -o tessera -g tessera -m 0700 /var/lib/tessera /run/tessera /srv/tessera/files
```

Files the broker serves must be owned by the broker user and sit directly
in `file_root`. Slot names are single names, not paths.

## 4. Configuration (`tesserad --config FILE`)

The configuration is a JSON file (`crates/broker/src/config.rs`). Unknown
keys are **silently ignored**, so check spelling.

```json
{
  "state_dir": "/var/lib/tessera/state",
  "admin_socket": "/run/tessera/admin.sock",
  "file_root": "/srv/tessera/files",
  "require_user_verification": false,
  "endpoints": [
    {
      "id": 1,
      "spec": {
        "host": "api.example.com",
        "port": 443,
        "path_prefix": "/v1/",
        "methods": ["GET", "POST"],
        "request_headers": ["content-type"],
        "response_headers": ["content-type"],
        "max_request_body": 4096,
        "max_response_body": 65536,
        "timeout_ms": 10000
      },
      "secret_header": { "name": "x-api-key", "value_file": "/etc/tessera/api-key" },
      "ca_pem_file": null
    }
  ],
  "profiles": {
    "agent": {
      "program": "/bin/sh",
      "args": ["/opt/agent/run.sh"],
      "workspace": "/srv/tessera/workspaces/agent",
      "ro_binds": [["/usr/libexec/tessera-agent", "/opt/agent"]],
      "env": [["LANG", "C.UTF-8"]],
      "memory_max_bytes": 536870912,
      "pids_max": 128
    }
  },
  "launcher": {
    "bwrap_path": "/usr/bin/bwrap",
    "init_path": "/usr/libexec/tessera/tessera-sandbox-init",
    "cgroup_opt_out_reason": null,
    "landlock": "required"
  }
}
```

| Key | Meaning |
|---|---|
| `state_dir` | broker-owned; holds `journal` (hash-chained WAL, the source of truth) and `audit.jsonl`. Never mount it into a sandbox |
| `admin_socket` | operator socket path (see §3). `tessera-admin` defaults to `$TESSERA_ADMIN_SOCKET` or `/run/tessera/admin.sock` |
| `file_root` | trusted directory for file slots. Omit it to disable the file adapter |
| `require_user_verification` | require FIDO2 UV (PIN/biometric) on every mint, not only UP |
| `endpoints[]` | HTTPS endpoints with broker-held secrets. `secret_header.value_file` is read at startup (trailing CR/LF stripped). Secrets are never journaled or audited. `ca_pem_file` adds private CAs; otherwise webpki roots are used. Optional `spec` keys: `allow_private` (permit loopback/private addresses), `pinned_addrs` (skip DNS) |
| `profiles` | trusted launch profiles. Agents cannot choose programs; the operator picks a profile with `create-principal`. `workspace` is bound read-write at `/workspace` and `ro_binds` are `[host, sandbox]` pairs |
| `launcher.landlock` | `required` (default), `best_effort` or `disabled` |
| `launcher.cgroup_opt_out_reason` | non-null = run without cgroup confinement (see §1) |

Bind **directories** in `ro_binds`, not single files. A rule on a regular
file cannot carry Landlock's directory rights, so the ruleset is reported
as "partial". Under `landlock: "required"` the init shim then refuses the
launch with `Landlock required but ruleset is partial`. Put the agent's
files in a directory and bind that.

If `profiles` is empty, no launcher is started, and only in-process
principals (tests and embeddings) can exist. If `profiles` is not empty,
the launcher probes the host at startup, and `tesserad` exits with
`launcher refused to start: ...` if a mandatory control is missing.

Settings that are compiled in and not configurable yet (`BrokerConfig`
defaults): default grant lifetime 5 min, maximum 24 h, approval timeout
2 min, 30 approvals per minute, approval queue 16, agent frame limit
128 KiB, 4 dispatch workers.

### systemd unit (example)

```ini
[Unit]
Description=Tessera capability broker
After=local-fs.target

[Service]
User=tessera
Group=tessera
ExecStart=/usr/local/bin/tesserad --config /etc/tessera/tesserad.json
Delegate=yes
RuntimeDirectory=tessera
RuntimeDirectoryMode=0700
Restart=on-failure
# The broker fails closed on restart (new epoch; every grant and sandbox is
# invalidated). Frequent automatic restarts are a denial-of-service lever.
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/tessera /srv/tessera
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

This unit has not been tested on a production host. `Delegate=yes` is what
gives the launcher its cgroup subtree.

## 5. Enrolling the operator's approval key

Every new root grant needs a FIDO2 assertion over the exact normalized
request (ADR-0006, ADR-0017). Enroll a credential once. Enrolling again
rotates it and cancels any approval in progress.

Hardware token (feature `fido2-cli`, **untested against hardware**):

```sh
fido2-token -L                                  # find the device
tessera-admin enroll --fido2 /dev/hidraw0 [--rp-id tessera.local]
```

Software key (**development only**: the key is a file and proves no
physical presence; `tessera-admin` prints a warning every time):

```sh
tessera-admin enroll --key ~/.config/tessera/operator.key
```

The key file is created with mode 0600 if it does not exist. The enrollment
(operator id, RP id, credential id, public key) is journaled, so it
survives restarts. `tessera-admin status` shows `"enrolled": true`.

## 6. Registering resources

```sh
tessera-admin register-file notes.txt --max-read 65536 --max-write 0   # prints: id N
tessera-admin register-endpoint 2 --spec endpoint.json                 # no secret: secrets only via config
```

The broker records file identity (device, inode, owner, filesystem type) when a file is
registered. After a restart it re-checks that identity. A file that was
replaced outside the broker becomes unavailable (audited as
`file-restore`) and has to be registered again under a new id. Inline
content is capped at 96 KiB.

Next: [operations.md](operations.md).
