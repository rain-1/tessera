# Namespace / sandbox-in-sandbox / device escape attempts.
. /probes/lib.sh
expect_fail "unshare -U" unshare -U true
expect_fail "unshare -m" unshare -m true
expect_fail "unshare -n" unshare -rn true
expect_fail "nested bwrap" bwrap --ro-bind / / true
expect_fail "nsenter host" nsenter -t 1 -m true
expect_fail "chroot" chroot / true
for d in /dev/kvm /dev/sda /dev/nvme0n1 /dev/mem /dev/kmsg /dev/fuse /dev/net/tun /dev/vhost-vsock /dev/tpm0 /dev/hidraw0 /dev/uinput /dev/dri; do
    [ -e "$d" ] && breach "device $d present" || ok "no $d"
done
expect_fail "write /dev/tty" sh -c 'echo x > /dev/tty'
[ -e /sys/fs/cgroup ] && breach "/sys/fs/cgroup visible" || ok "no /sys/fs/cgroup"
python3 /probes/syscalls.py || BREACHES=$((BREACHES + 1))
finish
