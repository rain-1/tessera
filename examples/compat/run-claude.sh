#!/bin/sh
# Run an unmodified Claude Code (`claude`) in a Tessera compatibility-mode
# sandbox: empty network namespace, no host credentials, model API traffic
# only through the host-side tessera-model-proxy (docs/compat.md).
#
# Usage: examples/compat/run-claude.sh WORKSPACE [claude args...]
#   e.g. examples/compat/run-claude.sh ~/scratch/ws -p "summarise README.md"
#
# Environment:
#   PROXY_CONFIG  proxy config (default: examples/compat/anthropic-proxy.json).
#                 Its single sandbox entry's "socket" must equal MODEL_SOCKET,
#                 and its credential file is read by the proxy, never by
#                 this script and never inside the sandbox.
#   MODEL_SOCKET  host socket path (default: the "socket" in PROXY_CONFIG).
#   CLAUDE_BIN    host path of the claude executable
#                 (default: resolved ~/.local/bin/claude).
#   TESSERA_BIN   directory with tessera-model-proxy, tessera-launch-run and
#                 tessera-sandbox-init (default: target/debug of this repo).
#   LAUNCH_ARGS   extra tessera-launch-run flags (e.g. --allow-no-cgroup why).
#
# Claude Code speaks HTTP over a Unix socket when ANTHROPIC_UNIX_SOCKET is
# set, so no loopback TCP port (and no Landlock TCP exception) is needed.
# ANTHROPIC_BASE_URL=http://localhost makes it send plain HTTP on that
# socket (with an https base URL it would attempt TLS over the socket; the
# proxy refuses and logs "tls_on_plain_http_socket"). ANTHROPIC_API_KEY is a
# placeholder that the proxy strips.
#
# Remember: the model API is an unlimited-use baseline channel and a
# disclosure channel (threat model R-2). Anything in WORKSPACE can be sent
# to the model provider.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
[ $# -ge 1 ] || { sed -n '6,8p' "$0"; exit 2; }
WORKSPACE=$(cd "$1" && pwd); shift

PROXY_CONFIG=${PROXY_CONFIG:-$HERE/anthropic-proxy.json}
TESSERA_BIN=${TESSERA_BIN:-$ROOT/target/debug}
CLAUDE_BIN=${CLAUDE_BIN:-$(readlink -f "$HOME/.local/bin/claude")}
if [ -z "${MODEL_SOCKET:-}" ]; then
    MODEL_SOCKET=$(python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c["sandboxes"][0]["socket"])' "$PROXY_CONFIG")
fi

for b in tessera-model-proxy tessera-launch-run tessera-sandbox-init; do
    [ -x "$TESSERA_BIN/$b" ] || { echo "missing $TESSERA_BIN/$b (cargo build --workspace --bins)" >&2; exit 2; }
done
[ -x "$CLAUDE_BIN" ] || { echo "claude not found at $CLAUDE_BIN" >&2; exit 2; }

# Private directory for the socket (the proxy creates the socket 0600).
mkdir -p "$(dirname "$MODEL_SOCKET")"
chmod 700 "$(dirname "$MODEL_SOCKET")"

"$TESSERA_BIN/tessera-model-proxy" --config "$PROXY_CONFIG" --check >/dev/null
"$TESSERA_BIN/tessera-model-proxy" --config "$PROXY_CONFIG" &
PROXY=$!
cleanup() { kill "$PROXY" 2>/dev/null || true; wait "$PROXY" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
i=0
while [ ! -S "$MODEL_SOCKET" ]; do
    i=$((i + 1)); [ $i -lt 50 ] || { echo "proxy did not create $MODEL_SOCKET" >&2; exit 1; }
    sleep 0.1
done

status=0
# Only the variables below enter the sandbox (the launcher clears the rest),
# and none of them is a credential.
"$TESSERA_BIN/tessera-launch-run" ${LAUNCH_ARGS:-} \
    --init "$TESSERA_BIN/tessera-sandbox-init" \
    --agent claude-1 \
    --workspace "$WORKSPACE" \
    --ro-bind "$CLAUDE_BIN:/opt/claude/claude" \
    --model-socket "$MODEL_SOCKET" \
    --env ANTHROPIC_UNIX_SOCKET=/.tessera/model.sock \
    --env ANTHROPIC_BASE_URL=http://localhost \
    --env ANTHROPIC_API_KEY=tessera-placeholder \
    --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    --env DISABLE_AUTOUPDATER=1 \
    --env DISABLE_ERROR_REPORTING=1 \
    --env DISABLE_TELEMETRY=1 \
    -- /opt/claude/claude "$@" || status=$?
exit $status
