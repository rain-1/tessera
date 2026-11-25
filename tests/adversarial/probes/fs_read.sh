# Attempt to read host files outside the workspace.
. /probes/lib.sh
for f in "${CANARY_HOME:-/nonexistent}" "${CANARY_TMP:-/nonexistent}" /etc/shadow /etc/ssh/ssh_host_ed25519_key \
         /etc/machine-id /etc/hostname /root/.bashrc /var/log/syslog /boot/config-* ; do
    expect_fail "read $f" cat "$f"
done
for d in /home /root /run /run/user /var /sys /mnt /media /srv /opt /snap; do
    if [ -e "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then breach "host dir $d visible: $(ls -A "$d" | head -5 | tr '\n' ' ')"
    else ok "$d absent or empty"; fi
done
# The canary must not be findable anywhere in the sandbox view.
if [ -n "${CANARY_SECRET:-}" ] && grep -rqs -D skip --exclude-dir=proc --exclude-dir=usr --exclude-dir=sys "$CANARY_SECRET" / 2>/dev/null; then
    breach "canary content found by recursive grep"
else ok "canary content not found by recursive grep"; fi
# /etc must be minimal and synthetic (no host accounts).
if grep -qv '^agent:' /etc/passwd; then breach "host accounts in /etc/passwd"; else ok "synthetic /etc/passwd"; fi
finish
