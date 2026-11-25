#!/usr/bin/env python3
"""kleine DNS-Abfrage fuer die Tests: dnsq.py <server> <name> [A|AAAA] -> Adressen (eine je Zeile) oder RCODE=n"""
import random, socket, struct, sys

srv, name = sys.argv[1], sys.argv[2]
qt = {"A": 1, "AAAA": 28}[sys.argv[3] if len(sys.argv) > 3 else "A"]
qid = random.randrange(65536)
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", qt, 1)
s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(q, (srv, 53))
r, _ = s.recvfrom(4096)
rcode, an = r[3] & 15, struct.unpack(">H", r[6:8])[0]
def skip(i):
    while True:
        if r[i] == 0:
            return i + 1
        if r[i] & 0xC0 == 0xC0:
            return i + 2
        i += 1 + r[i]

i = skip(12) + 4
out = []
for _ in range(an):
    i = skip(i)
    t, _, _, ln = struct.unpack(">HHIH", r[i:i + 10])
    d = r[i + 10:i + 10 + ln]
    if t == 1:
        out.append(socket.inet_ntop(socket.AF_INET, d))
    elif t == 28:
        out.append(socket.inet_ntop(socket.AF_INET6, d))
    i += 10 + ln
print("\n".join(out) if out else f"RCODE={rcode}")
