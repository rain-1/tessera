#!/usr/bin/env bash
# End-to-end demo of a real `tesserad` with a real sandbox and a *software*
# authenticator (development only: no physical presence is proven).
#
#   1. start tesserad with a throwaway config and state directory
#   2. enroll an operator key, register a file slot
#   3. launch an agent sandbox (bubblewrap + seccomp + Landlock + cgroup)
#      whose script asks for a one-use read capability
#   4. approve the pending request with tessera-admin
#   5. the agent reads the file once; its second read is denied (budget)
#   6. show the capability tree and audit log, revoke, emergency stop
#   7. restart tesserad on the same state: new epoch, old grants dead
#
# Usage: scripts/demo.sh            (builds debug binaries first)
#   TESSERA_BIN=/path/to/bin-dir    use prebuilt binaries
#   KEEP=1                          keep the temporary directory
# Exit status: 0 success, 3 sandbox controls missing on this host, 1 failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${TESSERA_BIN:-}"
if [ -z "$bin" ]; then
    (cd "$root" && cargo build -q -p tessera-broker -p tessera-cli -p tessera-launcher --bins)
    bin="$root/target/debug"
fi
for b in tesserad tessera-admin tessera tessera-sandbox-init; do
    [ -x "$bin/$b" ] || { echo "missing $bin/$b" >&2; exit 1; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/tessera-demo.XXXXXX")"
chmod 700 "$work"
daemon=""
cleanup() {
    rc=$?
    if [ -n "$daemon" ]; then kill "$daemon" 2>/dev/null; wait "$daemon" 2>/dev/null || true; fi
    if [ "${KEEP:-0}" = 1 ]; then echo "kept $work"; else rm -rf "$work"; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
admin() { echo "\$ tessera-admin $*" >&2; "$bin/tessera-admin" --socket "$work/run/admin.sock" "$@"; }

mkdir -m 700 -p "$work/state" "$work/run" "$work/files" "$work/ws" "$work/agent"
echo "top secret notes" > "$work/files/notes.txt"
chmod 600 "$work/files/notes.txt"

# The agent's program (bound read-only into the sandbox). It waits for the
# object id the operator registered, asks for a grant, then reads twice.
cat > "$work/agent/agent.sh" <<'EOF'
#!/bin/sh
T=/opt/demo/tessera
while [ ! -s /workspace/obj ]; do sleep 0.1; done
OBJ=$(cat /workspace/obj)
$T --json --approval-timeout 120 request --file "$OBJ" --rights read --budget 1 --depth 0 \
    > /workspace/request.json 2>&1
CAP=$(sed -n 's/.*"cap_id":"\([0-9a-f]*\)".*/\1/p' /workspace/request.json)
$T --json read --cap "$CAP" > /workspace/read1.json 2>&1; echo $? > /workspace/read1.rc
$T --json read --cap "$CAP" > /workspace/read2.json 2>&1; echo $? > /workspace/read2.rc
touch /workspace/done
sleep 600
EOF

# Bind a *directory*: binding single files makes the Landlock ruleset
# "partial" (file rules cannot carry directory rights), which the launcher
# refuses under landlock=required.
cp "$bin/tessera" "$work/agent/tessera"

cat > "$work/tesserad.json" <<EOF
{
  "state_dir": "$work/state",
  "admin_socket": "$work/run/admin.sock",
  "file_root": "$work/files",
  "require_user_verification": false,
  "profiles": {
    "demo": {
      "program": "/bin/sh",
      "args": ["/opt/demo/agent.sh"],
      "workspace": "$work/ws",
      "ro_binds": [["$work/agent", "/opt/demo"]],
      "memory_max_bytes": 268435456,
      "pids_max": 64
    }
  },
  "launcher": { "init_path": "$bin/tessera-sandbox-init", "landlock": "required" }
}
EOF

start_daemon() {
    "$bin/tesserad" --config "$work/tesserad.json" 2>>"$work/tesserad.log" &
    daemon=$!
    for _ in $(seq 100); do
        [ -S "$work/run/admin.sock" ] && return 0
        if ! kill -0 "$daemon" 2>/dev/null; then
            cat "$work/tesserad.log" >&2
            if grep -q "launcher refused to start" "$work/tesserad.log"; then
                echo "SKIPPED: a mandatory sandbox control is missing on this host" >&2
                exit 3
            fi
            exit 1
        fi
        sleep 0.1
    done
    echo "tesserad did not create its socket" >&2; exit 1
}

step "start tesserad"
start_daemon
admin status

step "enroll an operator credential (software key: DEVELOPMENT ONLY)"
admin enroll --key "$work/operator.key"

step "register the file slot notes.txt"
obj=$(admin register-file notes.txt --max-read 4096 --max-write 0 | sed -n 's/^id //p')
echo "object id: $obj"

step "launch an agent sandbox from the trusted profile 'demo'"
admin create-principal demo
admin principals

step "agent asks for a capability; operator reviews and approves"
echo "$obj" > "$work/ws/obj"
ticket=""
for _ in $(seq 200); do
    ticket=$(admin pending 2>/dev/null | sed -n 's/^ticket \([0-9]*\) (awaiting touch).*/\1/p' | head -1)
    [ -n "$ticket" ] && break
    sleep 0.1
done
[ -n "$ticket" ] || { echo "no approval request arrived" >&2; cat "$work/tesserad.log" >&2; exit 1; }
admin pending
admin approve "$ticket" --key "$work/operator.key" --yes

for _ in $(seq 200); do [ -e "$work/ws/done" ] && break; sleep 0.1; done
[ -e "$work/ws/done" ] || { echo "agent did not finish" >&2; exit 1; }
step "agent results"
echo "request:      $(cat "$work/ws/request.json")"
echo "first read:   $(cat "$work/ws/read1.json") (exit $(cat "$work/ws/read1.rc"))"
echo "second read:  $(cat "$work/ws/read2.json") (exit $(cat "$work/ws/read2.rc"))"
grep -q '"body_utf8":"top secret notes' "$work/ws/read1.json"
[ "$(cat "$work/ws/read2.rc")" = 1 ]
grep -q InsufficientBudget "$work/ws/read2.json"
cap=$(sed -n 's/.*"cap_id":"\([0-9a-f]*\)".*/\1/p' "$work/ws/request.json")

step "inspect authority and audit"
admin tree
admin accounts
admin audit --limit 50

step "operator revokes the capability"
admin revoke "$cap"
admin inspect "$cap"

step "emergency stop: new epoch, every grant invalid, every sandbox stopped"
admin emergency-stop
admin status

step "restart tesserad on the same journal"
kill "$daemon"; wait "$daemon" 2>/dev/null || true; daemon=""
rm -f "$work/run/admin.sock"
start_daemon
admin status
admin checkpoint
echo
echo "demo OK"
