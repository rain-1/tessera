# Cross-principal probe, sender side (security review finding 1).
# Runs in sandbox A. Offers A's broker channel (fd 3) over every local IPC
# rendezvous a second sandbox launched from the same profile might share,
# and plants files where B might find them. Prints READY once set up, and
# BREACH-SENT if anyone ever connects and receives the fd.
import array, os, socket, sys, time

TAG = sys.argv[1] if len(sys.argv) > 1 else "tessera-cross"
listeners = []
for path in ["/workspace/x.sock", "/tmp/x.sock", "/dev/shm/x.sock"]:
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_UNIX)
        s.bind(path)
        s.listen(4)
        listeners.append(s)
    except OSError:
        pass
try:
    a = socket.socket(socket.AF_UNIX)
    a.bind("\0" + TAG)
    a.listen(4)
    listeners.append(a)
except OSError:
    pass
for path in ["/workspace/planted.sh", "/tmp/planted.sh", "/dev/shm/planted.sh"]:
    try:
        with open(path, "w") as f:
            f.write("#!/bin/sh\necho " + TAG + "\n")
        os.chmod(path, 0o755)
    except OSError:
        pass
print("READY", len(listeners), flush=True)
deadline = time.time() + float(os.environ.get("CROSS_WAIT", "30"))
for s in listeners:
    s.settimeout(0.05)
while time.time() < deadline:
    for s in listeners:
        try:
            c, _ = s.accept()
        except (socket.timeout, OSError):
            continue
        c.sendmsg([b"take-my-channel"],
                  [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [3]))])
        print("BREACH-SENT", flush=True)
