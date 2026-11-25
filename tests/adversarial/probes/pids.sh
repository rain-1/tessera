# Attempt to observe or signal host processes.
. /probes/lib.sh
n=0; for p in /proc/[0-9]*; do n=$((n + 1)); done
if [ "$n" -gt 10 ]; then breach "$n processes visible"; else ok "$n processes visible (sandbox only)"; fi
for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in
        *systemd*|*cargo*|*gnome*|*sshd*|*claude*|*tessera-launch-run*|*launcher-*) breach "host process visible: $c" ;;
    esac
done
if [ -n "${HOST_PID:-}" ]; then
    expect_fail "signal host pid $HOST_PID" kill -0 "$HOST_PID"
    [ -e "/proc/$HOST_PID/cmdline" ] && breach "/proc/$HOST_PID exists"
fi
# PID 1 is bubblewrap's init; it must not leak descriptors or environment.
expect_fail "read /proc/1/environ" cat /proc/1/environ
expect_fail "read /proc/1/fd/0 link" readlink /proc/1/fd/0
[ "$(cat /proc/self/cgroup)" = "0::/" ] && ok "cgroup namespace root" || breach "host cgroup path visible: $(cat /proc/self/cgroup)"
finish
