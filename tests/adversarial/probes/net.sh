# Attempt to reach the network, host sockets and the session bus.
. /probes/lib.sh
python3 /probes/net.py || BREACHES=$((BREACHES + 1))
for s in /run/user/*/bus /var/run/docker.sock /run/docker.sock /run/dbus/system_bus_socket \
         /tmp/.X11-unix/X0 /run/user/*/wayland-0 /run/user/*/gnupg/S.gpg-agent /run/user/*/keyring/ssh; do
    if [ -S "$s" ]; then breach "host socket $s visible"; else ok "no $s"; fi
done
ifs=$(ls /sys/class/net 2>/dev/null || awk -F: 'NR>2{gsub(/ /,"",$1);print $1}' /proc/net/dev)
for i in $ifs; do [ "$i" = lo ] || breach "non-loopback interface $i"; done
ok "interfaces: $(echo $ifs)"
finish
