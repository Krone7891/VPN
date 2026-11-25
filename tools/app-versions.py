#!/usr/bin/env python3
"""Version je App (Android, Windows, Linux) – sie steigt nur, wenn sich die App wirklich geaendert hat.

Aufruf (aus build-all.sh): app-versions.py <workspace-version> android=<apk> windows=<exe> linux=<bin>
Fuer jede App wird ein Fingerabdruck ihrer Quellen gebildet (ohne die Versionsnummer selbst). Hat er sich seit dem
letzten Bauen geaendert, kommt die neu gebaute Datei nach dist/ und bekommt die aktuelle Version; sonst bleibt die
bisherige Datei mit ihrer bisherigen Version liegen – die Geraete bekommen dann KEIN Update.
Ergebnis: dist/app-versions.json (wird von 'kvpn-server update-sign' in die signierte update.json uebernommen).
"""
import hashlib, json, os, re, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
SOURCES = {
    "android": ["android", "kvpn", "kvpn-android"],
    "windows": ["kronevpn", "kvpn"],
    "linux": ["kronevpn", "kvpn"],
}
NAMES = {"android": "KroneVPN.apk", "windows": "KroneVPN.exe", "linux": "kronevpn-linux"}
OWN = {"kvpn", "kvpn-server", "kronevpn", "kvpn-android"}


def common() -> bytes:
    """Cargo.toml und Cargo.lock ohne die eigenen Versionsnummern (Abhaengigkeiten zaehlen mit)"""
    toml = open(os.path.join(ROOT, "Cargo.toml")).read()
    toml = re.sub(r'(?m)^version = ".*"\n', "", toml, count=1)
    lock, out, skip = open(os.path.join(ROOT, "Cargo.lock")).read().splitlines(), [], False
    for line in lock:
        m = re.match(r'name = "(.*)"', line)
        if m:
            skip = m.group(1) in OWN
        elif skip and line.startswith("version = "):
            continue
        out.append(line)
    return (toml + "\n".join(out)).encode()


def fingerprint(os_: str) -> str:
    h = hashlib.sha256(common())
    for d in SOURCES[os_]:
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


def main():
    ver = sys.argv[1]
    built = dict(a.split("=", 1) for a in sys.argv[2:])
    path = os.path.join(DIST, "app-versions.json")
    try:
        old = json.load(open(path))
    except Exception:
        old = {}
    new, failed = {}, False
    for os_, name in NAMES.items():
        fp = fingerprint(os_)
        prev = old.get(os_, {})
        target = os.path.join(DIST, name)
        if prev.get("fp") == fp and os.path.exists(target) and prev.get("version"):
            new[os_] = prev
            print(f"  {os_:8} unveraendert – bleibt {prev['version']} (kein Update fuer die Geraete)")
            continue
        if prev.get("version") and not newer(ver, prev["version"]):
            print(f"  {os_:8} GEAENDERT, aber Version {ver} ist nicht neuer als {prev['version']} – bitte in Cargo.toml erhoehen!")
            failed = True
            continue
        shutil.copyfile(built[os_], target)
        os.chmod(target, 0o755 if os_ == "linux" else 0o644)
        new[os_] = {"version": ver, "fp": fp}
        print(f"  {os_:8} geaendert – neue Version {ver}")
    if failed:
        sys.exit(1)
    json.dump(new, open(path, "w"), indent=1)
    open(path, "a").write("\n")


if __name__ == "__main__":
    main()
