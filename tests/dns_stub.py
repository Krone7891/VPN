#!/usr/bin/env python3
"""kleiner DNS-Server fuer Tests (nur A-Eintraege): dns_stub.py <ip> <port> <datei.json>
Die JSON-Datei ({"name": "1.2.3.4", ...}) wird bei jeder Anfrage neu gelesen – Antworten lassen sich so umstellen."""
import json, socket, struct, sys

ip, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ip, port))
while True:
    q, a = s.recvfrom(1500)
    if len(q) < 12:
        continue
    i, labels = 12, []
    while i < len(q) and q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace")); i += 1 + q[i]
    name, qend = ".".join(labels).lower(), i + 5
    try:
        m = {k.lower(): v for k, v in json.load(open(path)).items()}
    except Exception:
        m = {}
    ans = b""
    if name in m and q[i + 1:i + 3] == b"\x00\x01":
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(m[name])
    flags = 0x8180 if name in m else 0x8183
    s.sendto(q[:2] + struct.pack(">HHHHH", flags, 1, 1 if ans else 0, 0, 0) + q[12:qend] + ans, a)
