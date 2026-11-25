# The workload environment must be explicit: no host credentials or session handles.
. /probes/lib.sh
for v in SSH_AUTH_SOCK SSH_AGENT_PID GPG_AGENT_INFO DBUS_SESSION_BUS_ADDRESS DISPLAY WAYLAND_DISPLAY \
         XDG_RUNTIME_DIR XAUTHORITY ANTHROPIC_API_KEY OPENAI_API_KEY AWS_SECRET_ACCESS_KEY \
         AWS_ACCESS_KEY_ID GITHUB_TOKEN GH_TOKEN KRB5CCNAME LD_PRELOAD USER LOGNAME; do
    eval "val=\${$v-__unset__}"
    if [ "$val" != "__unset__" ]; then breach "$v present in environment"; else ok "$v absent"; fi
done
# Only explicitly configured keys may exist (probe inputs are CANARY_*/HOST_*/EXPECT_*).
for k in $(env | cut -d= -f1); do
    case "$k" in
        PATH|HOME|TMPDIR|LANG|PWD|SHLVL|_|OLDPWD|TESSERA_AGENT_ID|TESSERA_BROKER_FD|CANARY_*|HOST_*|EXPECT_*) ;;
        *) breach "unexpected environment variable $k" ;;
    esac
done
[ "${TESSERA_BROKER_FD:-}" = 3 ] && ok "TESSERA_BROKER_FD=3" || breach "TESSERA_BROKER_FD missing"
[ -n "${TESSERA_AGENT_ID:-}" ] && ok "TESSERA_AGENT_ID=$TESSERA_AGENT_ID" || breach "TESSERA_AGENT_ID missing"
grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status && ok "no_new_privs" || breach "no_new_privs not set"
grep -q '^Seccomp:[[:space:]]*2' /proc/self/status && ok "seccomp filter mode" || breach "seccomp not active"
grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/self/status && ok "no effective caps" || breach "effective capabilities present"
grep -q '^CapBnd:[[:space:]]*0000000000000000' /proc/self/status && ok "empty bounding set" || breach "bounding set not empty"
finish
