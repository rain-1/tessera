"""Inherited descriptor and broker channel checks. Exit 1 on any breach."""
import os, socket, stat, sys

breaches = 0
def breach(m):
    global breaches
    breaches += 1
    print("BREACH:", m)

listed = [int(x) for x in os.listdir("/proc/self/fd")]
fds = []
for fd in listed:
    try:
        fds.append((fd, os.readlink(f"/proc/self/fd/{fd}")))
    except OSError:
        pass  # the listing's own (closed) directory descriptor
extra = [(fd, t) for fd, t in fds if fd > 2]
expected_broker = int(os.environ.get("TESSERA_BROKER_FD", "-1"))
for fd, target in extra:
    if fd != expected_broker:
        breach(f"unexpected inherited fd {fd} -> {target}")
if expected_broker != 3:
    breach(f"TESSERA_BROKER_FD={expected_broker}, expected 3")
else:
    st = os.fstat(3)
    if not stat.S_ISSOCK(st.st_mode):
        breach("fd 3 is not a socket")
    s = socket.socket(fileno=os.dup(3))
    typ = s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    if typ != socket.SOCK_SEQPACKET:
        breach(f"broker channel type {typ} != SOCK_SEQPACKET")
    if os.environ.get("EXPECT_BROKER_ECHO") == "1":
        os.write(3, b"ping-from-sandbox")
        reply = os.read(3, 4096)
        if reply != b"echo:ping-from-sandbox":
            breach(f"unexpected broker reply {reply!r}")
        else:
            print("ok: broker channel round trip")
    s.close()
print("ok: open fds:", [fd for fd, _ in fds])
sys.exit(1 if breaches else 0)
