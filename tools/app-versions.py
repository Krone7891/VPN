#!/usr/bin/env python3
"""Eigene Version je App (Android, Windows, Linux) und fuer den Server – sie steigt nur, wenn sich genau dieser Teil
wirklich geaendert hat.

Aufruf (aus build-all.sh):
  app-versions.py <app-version> android=<apk> windows=<exe> linux=<bin> server=<kvpn-server>

Fuer jeden Teil wird ein Fingerabdruck gebildet aus
  * den eigenen Quellen, die er wirklich benutzt (z. B. Windows: kronevpn + kvpn, Server: kvpn-server + kvpn),
  * den Abhaengigkeiten aus Cargo.lock, die er wirklich benutzt (nur seine, nicht die der anderen),
  * den Bau-Einstellungen in Cargo.toml (ohne die Versionsnummer).
Hat er sich seit dem letzten Bauen geaendert, kommt die neu gebaute Datei nach dist/ und bekommt die neue Version;
sonst bleibt die bisherige Datei mit ihrer bisherigen Version liegen – die Geraete bekommen dann KEIN Update.

Versionen: Apps = "version" in Cargo.toml (Arbeitsbereich), Server = "version" in kvpn-server/Cargo.toml.
Aendert sich nur der Server, bleibt die App-Version, wie sie ist (und umgekehrt).
Ergebnis: dist/app-versions.json (die App-Eintraege uebernimmt 'kvpn-server update-sign' in die signierte update.json).
"""
import hashlib, json, os, re, shutil, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
# Teil -> (Wurzel-Crate, zusaetzliche Ordner)
PARTS = {
    "android": ("kvpn-android", ["android"]),
    "windows": ("kronevpn", []),
    "linux": ("kronevpn", []),
    "server": ("kvpn-server", []),
}
NAMES = {"android": "KroneVPN.apk", "windows": "KroneVPN.exe", "linux": "kronevpn-linux", "server": "kvpn-server"}
OWN = {"kvpn", "kvpn-server", "kronevpn", "kvpn-android"}
MODE = {"linux": 0o755, "server": 0o755}


def hash_dir(h, d: str):
    for base, dirs, files in os.walk(os.path.join(ROOT, d)):
        dirs[:] = sorted(x for x in dirs if x not in ("target", "build", ".git"))
        for f in sorted(files):
            p = os.path.join(base, f)
            rel = os.path.relpath(p, ROOT)
            h.update(rel.encode() + b"\0")
            data = open(p, "rb").read()
            # die eigene Versionsnummer zaehlt nicht als Aenderung
            if rel.endswith("Cargo.toml") and os.path.basename(base) in OWN:
                data = re.sub(rb'(?m)^version = ".*"\n', b"", data, count=1)
            h.update(data)


def root_toml() -> bytes:
    toml = open(os.path.join(ROOT, "Cargo.toml")).read()
    return re.sub(r'(?m)^version = ".*"\n', "", toml, count=1).encode()


def lock_closure(root: str) -> list:
    """alle Pakete aus Cargo.lock, die `root` (direkt oder indirekt) benutzt"""
    lock = tomllib.load(open(os.path.join(ROOT, "Cargo.lock"), "rb"))
    pk = lock["package"]
    by_name = {}
    for p in pk:
        by_name.setdefault(p["name"], []).append(p)

    def find(dep: str):
        parts = dep.split(" ")
        cands = by_name.get(parts[0], [])
        if len(parts) > 1:
            cands = [c for c in cands if c["version"] == parts[1]]
        return cands[0] if cands else None

    seen, todo = {}, [by_name[root][0]]
    while todo:
        p = todo.pop()
        key = (p["name"], p["version"])
        if key in seen:
            continue
        seen[key] = p
        for d in p.get("dependencies", []):
            q = find(d)
            if q:
                todo.append(q)
    return [seen[k] for k in sorted(seen)]


def fingerprint(part: str) -> str:
    root, extra = PARTS[part]
    h = hashlib.sha256(b"v2\0")
    h.update(root_toml())
    closure = lock_closure(root)
    own_dirs = []
    for p in closure:
        if p["name"] in OWN:
            own_dirs.append(p["name"])
            h.update(f"{p['name']}\n".encode())
        else:
            h.update(f"{p['name']} {p['version']} {p.get('checksum', '')}\n".encode())
    for d in sorted(own_dirs) + extra:
        hash_dir(h, d)
    return h.hexdigest()


def legacy_fingerprint(part: str) -> str:
    """Fingerabdruck bis 1.1.2 (ganze Cargo.lock) – nur zum Uebernehmen der alten Eintraege ohne Versionssprung"""
    sources = {"android": ["android", "kvpn", "kvpn-android"], "windows": ["kronevpn", "kvpn"], "linux": ["kronevpn", "kvpn"]}
    if part not in sources:
        return ""
    toml = open(os.path.join(ROOT, "Cargo.toml")).read()
    toml = re.sub(r'(?m)^version = ".*"\n', "", toml, count=1)
    out, skip = [], False
    for line in open(os.path.join(ROOT, "Cargo.lock")).read().splitlines():
        m = re.match(r'name = "(.*)"', line)
        if m:
            skip = m.group(1) in OWN
        elif skip and line.startswith("version = "):
            continue
        out.append(line)
    h = hashlib.sha256((toml + "\n".join(out)).encode())
    for d in sources[part]:
        for base, dirs, files in os.walk(os.path.join(ROOT, d)):
            dirs[:] = sorted(x for x in dirs if x not in ("target", "build", ".git"))
            for f in sorted(files):
                p = os.path.join(base, f)
                h.update(os.path.relpath(p, ROOT).encode() + b"\0")
                h.update(open(p, "rb").read())
    return h.hexdigest()


def newer(a: str, b: str) -> bool:
    p = lambda s: [int(x) if x.isdigit() else 0 for x in s.split(".")]
    return p(a) > p(b)


def server_version() -> str:
    t = open(os.path.join(ROOT, "kvpn-server", "Cargo.toml")).read()
    m = re.search(r'(?m)^version = "(.*)"', t)
    return m.group(1) if m else ""


def main():
    app_ver = sys.argv[1]
    built = dict(a.split("=", 1) for a in sys.argv[2:])
    path = os.path.join(DIST, "app-versions.json")
    try:
        old = json.load(open(path))
    except Exception:
        old = {}
    new, failed = {}, False
    for part, name in NAMES.items():
        if part not in built:
            if part in old:
                new[part] = old[part]
            continue
        ver = server_version() if part == "server" else app_ver
        fp = fingerprint(part)
        prev = old.get(part, {})
        target = os.path.join(DIST, name)
        same = prev.get("fp2") == fp if "fp2" in prev else bool(prev.get("fp")) and prev.get("fp") == legacy_fingerprint(part)
        if same and os.path.exists(target) and prev.get("version"):
            new[part] = {"version": prev["version"], "fp2": fp}
            print(f"  {part:8} unveraendert – bleibt {prev['version']}" + ("" if part == "server" else " (kein Update fuer die Geraete)"))
            continue
        if prev.get("version") and not newer(ver, prev["version"]):
            where = "kvpn-server/Cargo.toml" if part == "server" else "Cargo.toml"
            print(f"  {part:8} GEAENDERT, aber Version {ver} ist nicht neuer als {prev['version']} – bitte in {where} erhoehen!")
            failed = True
            continue
        shutil.copyfile(built[part], target)
        os.chmod(target, MODE.get(part, 0o644))
        new[part] = {"version": ver, "fp2": fp}
        print(f"  {part:8} geaendert – neue Version {ver}")
    if failed:
        sys.exit(1)
    json.dump(new, open(path, "w"), indent=1)
    open(path, "a").write("\n")


if __name__ == "__main__":
    main()
