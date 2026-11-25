#!/bin/sh
# Hostile shell test corpus runner (spec WP5 gate: "hostile shell test corpus passes").
#
# Each probe in probes/*.sh runs inside a fresh Tessera sandbox launched by
# `tessera-launch-run`, with hostile conditions prepared on the host side:
#   * canary secrets in $HOME and in an unbound temp dir,
#   * a listening host unix socket and abstract socket,
#   * an extra inherited fd (7) open on the canary,
#   * credential-looking variables (SSH_AUTH_SOCK, *_API_KEY, ...) in the
#     launcher's own environment.
# A probe exits 0 only if every attack was contained. The runner exits 1 if
# any probe reported a breach, and 3 (loudly) if the launcher refused to start
# because a mandatory control is missing on this host.
#
# Usage: tests/adversarial/run.sh [probe-name ...]
#   TESSERA_LAUNCH_RUN=/path/to/tessera-launch-run   use a prebuilt binary
#   TESSERA_LAUNCH_ARGS="--allow-no-cgroup reason"   extra launcher flags
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RUN=${TESSERA_LAUNCH_RUN:-}
if [ -z "$RUN" ]; then
    if ! out=$(cd "$ROOT" && cargo build -q -p tessera-launcher --bins 2>&1); then
        echo "$out"; echo "build failed"; exit 2
    fi
    RUN=$ROOT/target/debug/tessera-launch-run
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tessera-adv-ws.XXXXXX")
SECRETS=$(mktemp -d "${TMPDIR:-/tmp}/tessera-adv-secret.XXXXXX")
HOMECANARY_DIR=$(mktemp -d "$HOME/.tessera-adv-canary.XXXXXX")
SECRET="tessera-canary-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
echo "$SECRET" > "$HOMECANARY_DIR/secret"
echo "$SECRET" > "$SECRETS/secret"
SOCK=$SECRETS/host.sock
ABSTRACT="tessera-adv-$$"
python3 -I -c '
import socket, sys, time
a = socket.socket(socket.AF_UNIX); a.bind(sys.argv[1]); a.listen()
b = socket.socket(socket.AF_UNIX); b.bind("\0" + sys.argv[2]); b.listen()
time.sleep(3600)' "$SOCK" "$ABSTRACT" &
LISTENER=$!
cleanup() { kill "$LISTENER" 2>/dev/null; rm -rf "$WORK" "$SECRETS" "$HOMECANARY_DIR"; }
trap cleanup EXIT INT TERM
sleep 0.3

if [ $# -gt 0 ]; then PROBES=$*; else
    PROBES=$(cd "$HERE/probes" && ls *.sh | grep -v '^lib.sh$' | sed 's/\.sh$//')
fi
fail=0; refused=0
for p in $PROBES; do
    echo "=== probe: $p"
    # fd 7: deliberately leaked (non-CLOEXEC) descriptor on the canary.
    exec 7<"$SECRETS/secret"
    SSH_AUTH_SOCK=$SOCK ANTHROPIC_API_KEY=sk-should-not-leak OPENAI_API_KEY=x GITHUB_TOKEN=x \
    DBUS_SESSION_BUS_ADDRESS=unix:path=$SOCK \
    "$RUN" ${TESSERA_LAUNCH_ARGS:-} --agent "adv-$p" --workspace "$WORK" --broker-echo \
        --ro-bind "$HERE/probes:/probes" \
        --env CANARY_HOME="$HOMECANARY_DIR/secret" --env CANARY_TMP="$SECRETS/secret" \
        --env CANARY_SECRET="$SECRET" --env HOST_SOCKET="$SOCK" --env HOST_ABSTRACT="$ABSTRACT" \
        --env HOST_PID="$$" --env EXPECT_BROKER_ECHO=1 --env EXPECT_LANDLOCK=required \
        -- /bin/sh "/probes/$p.sh"
    rc=$?
    exec 7<&-
    case $rc in
        0) echo "--- $p: PASS" ;;
        3) echo "--- $p: SKIPPED LOUDLY: launcher refused (mandatory control missing, see above)"; refused=1 ;;
        *) echo "--- $p: FAIL (exit $rc)"; fail=1 ;;
    esac
done
if [ $fail -ne 0 ]; then echo "ADVERSARIAL CORPUS: FAILED"; exit 1; fi
if [ $refused -ne 0 ]; then echo "ADVERSARIAL CORPUS: NOT RUN (launch refused on this host)"; exit 3; fi
echo "ADVERSARIAL CORPUS: ALL PROBES CONTAINED"
