# Attempt to write outside the workspace / modify the runtime or the init shim.
. /probes/lib.sh
for f in /x /usr/x /usr/bin/x /etc/x /etc/passwd /bin/x /lib/x /proc/x /proc/sys/kernel/hostname \
         /proc/sys/vm/drop_caches /.tessera/init /.tessera/x /dev/x /sys/x /home/x; do
    expect_fail "write $f" sh -c "echo pwn > '$f'"
done
expect_fail "chmod init shim" chmod 777 /.tessera/init
expect_fail "mknod device" mknod /tmp/sda b 8 0
expect_fail "mount tmpfs" mount -t tmpfs none /tmp
expect_fail "remount / rw" mount -o remount,rw /
# Sanity: allowed writable locations work.
if echo ok > /workspace/.probe-write && echo ok > /tmp/probe && rm /workspace/.probe-write; then
    ok "workspace and /tmp writable (expected)"
else breach "workspace or /tmp not writable (profile broken)"; fi
finish
