"""Network escape attempts. Exit 1 on any breach."""
import errno, os, socket, sys

breaches = 0

def breach(msg):
    global breaches
    breaches += 1
    print("BREACH:", msg)

def try_connect(desc, fam, addr, typ=socket.SOCK_STREAM):
    s = socket.socket(fam, typ)
    s.settimeout(3)
    try:
        s.connect(addr)
        if typ == socket.SOCK_DGRAM:
            s.send(b"x")
        breach(f"{desc} connected")
    except OSError as e:
        print(f"ok: {desc} blocked ({errno.errorcode.get(e.errno, e.errno)})")
    finally:
        s.close()

try_connect("tcp 1.1.1.1:53", socket.AF_INET, ("1.1.1.1", 53))
try_connect("tcp 8.8.8.8:443", socket.AF_INET, ("8.8.8.8", 443))
try_connect("udp 1.1.1.1:53", socket.AF_INET, ("1.1.1.1", 53), socket.SOCK_DGRAM)
try_connect("tcp [2606:4700:4700::1111]:53", socket.AF_INET6, ("2606:4700:4700::1111", 53))
try_connect("tcp 169.254.169.254:80 (metadata)", socket.AF_INET, ("169.254.169.254", 80))
try:
    socket.getaddrinfo("example.com", 443)
    breach("DNS resolution worked")
except OSError as e:
    print("ok: DNS resolution failed", e)

host_sock = os.environ.get("HOST_SOCKET")
if host_sock:
    try_connect(f"host unix socket {host_sock}", socket.AF_UNIX, host_sock)
abstract = os.environ.get("HOST_ABSTRACT")
if abstract:
    try_connect(f"host abstract socket @{abstract}", socket.AF_UNIX, "\0" + abstract)

# Loopback inside the sandbox: Landlock (when required) denies TCP bind/connect.
if os.environ.get("EXPECT_LANDLOCK") == "required":
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        breach("tcp bind on loopback allowed despite Landlock")
    except OSError as e:
        if e.errno == errno.EACCES:
            print("ok: tcp bind denied by Landlock (EACCES)")
        else:
            breach(f"tcp bind failed with unexpected {e}")
    s.close()

sys.exit(1 if breaches else 0)
