# Cross-principal probe, receiver side (security review finding 1).
# Runs in sandbox B, launched from the same profile as A while A's sender
# is READY. Exits 0 (CONTAINED) only if B can neither connect to any of A's
# rendezvous points (so no SCM_RIGHTS transfer of A's broker channel) nor
# see any file A planted.
import os, socket, sys

TAG = sys.argv[1] if len(sys.argv) > 1 else "tessera-cross"
breaches = []
for path in ["/workspace/x.sock", "/tmp/x.sock", "/dev/shm/x.sock", "\0" + TAG]:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect(path)
    except OSError:
        continue
    try:
        msg, anc, _, _ = s.recvmsg(64, socket.CMSG_SPACE(4))
        breaches.append("connected to %r, got %r with %d fds" % (path, msg, len(anc)))
    except OSError as e:
        breaches.append("connected to %r (%s)" % (path, e))
for path in ["/workspace/planted.sh", "/tmp/planted.sh", "/dev/shm/planted.sh"]:
    if os.path.exists(path):
        breaches.append("sees %s" % path)
for root in ["/workspace", "/tmp", "/dev/shm", "/run"]:
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f in ("x.sock", "planted.sh"):
                breaches.append("found %s/%s" % (dirpath, f))
if breaches:
    print("BREACH:", "; ".join(breaches), flush=True)
    sys.exit(1)
print("CONTAINED", flush=True)
