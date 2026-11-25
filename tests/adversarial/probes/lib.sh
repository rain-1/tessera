# Shared helpers for hostile probes. Sourced inside the sandbox.
# A probe prints "BREACH: ..." for every confinement violation it achieves and
# exits 1 if any happened; it prints "ok: ..." for each blocked attempt.
BREACHES=0
breach() { echo "BREACH: $*"; BREACHES=$((BREACHES + 1)); }
ok() { echo "ok: $*"; }
# expect_fail DESCRIPTION CMD... : the command must fail.
expect_fail() {
    d=$1; shift
    if "$@" >/dev/null 2>&1; then breach "$d succeeded"; else ok "$d blocked"; fi
}
finish() {
    if [ "$BREACHES" -ne 0 ]; then echo "RESULT: $BREACHES breach(es)"; exit 1; fi
    echo "RESULT: contained"; exit 0
}
