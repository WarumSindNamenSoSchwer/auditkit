#!/usr/bin/env python3
"""
Deterministische Vorerhebung. Zaehlt und lokalisiert, was ohne Modell
zaehlbar ist, und schreibt es als JSON. Ergebnis ist bei gleichem Commit
immer identisch.

Zweck: dem Modell Fakten vorlegen statt es schaetzen zu lassen. Alles was
hier gemessen wird, kann im Report nicht mehr zwischen Laeufen schwanken.
"""
import json
import re
import subprocess
import sys
from pathlib import Path


def git_files(root: Path, *patterns: str) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", *patterns],
            capture_output=True, text=True, timeout=60,
        )
        return [l for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def git_meta(root: Path) -> dict:
    def run(*args):
        try:
            r = subprocess.run(["git", "-C", str(root), *args],
                               capture_output=True, text=True, timeout=30)
            return r.stdout.strip() or None
        except Exception:
            return None
    return {
        "commit": run("rev-parse", "HEAD"),
        "commit_short": run("rev-parse", "--short", "HEAD"),
        "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(run("status", "--porcelain")),
    }


# Muster, deren Treffer eine Stelle bezeichnen, nicht eine Meinung.
# Jedes Muster liefert Datei und Zeilennummer, damit der Report belegbar ist.
PATTERNS = {
    "unsafe_string_fn": (
        r"\b(strcpy|strcat|sprintf|gets|alloca)\s*\(",
        "Kopie ohne Laengenbegrenzung. Relevant nur, wenn die Quelle extern ist.",
    ),
    "memcpy": (
        r"\bmemcpy\s*\(",
        "Kopie mit Laenge. Relevant, wenn die Laenge aus externen Daten stammt.",
    ),
    "dynamic_alloc": (
        r"\b(malloc|calloc|realloc)\s*\(",
        "Dynamische Allokation. Projektregel verbietet sie nach dem Init.",
    ),
    "gatt_open_perm": (
        r"SecurePermission::NONE_OPEN|PERMISSION_NONE|GATT_PERM_NONE",
        "GATT-Charakteristik ohne Berechtigungspruefung.",
    ),
    "gatt_auth_perm": (
        r"SecurePermission::(AUTHENTICATED|AUTHENTICATED_LESC)",
        "GATT-Charakteristik mit Authentifizierung.",
    ),
    "security_disabled": (
        r"security\.enable\s*=\s*false|usePasskey\s*=\s*false",
        "BLE-Security oder Passkey im Code abgeschaltet.",
    ),
    "hardcoded_secret": (
        r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key)\s*"
        r"[=:]\s*[\"'][^\"']{6,}[\"']",
        "Zeichenkette, die wie ein eingebettetes Geheimnis aussieht.",
    ),
    "debug_iface": (
        r"\b(SEGGER_RTT|RTT_printf|ITM_SendChar|swo_|SWO_)",
        "Debug-Ausgabekanal, mit Probe lesbar.",
    ),
    "crc_as_check": (
        r"(?i)\bcrc(16|32)?\b.{0,40}(verify|check|valid)",
        "CRC als Pruefung. Ein CRC ist keine Signatur.",
    ),
    "signature_check": (
        r"(?i)\b(ecdsa|ed25519|rsa_verify|signature_verify|verify_signature|sha256_verify)\b",
        "Kryptografische Signaturpruefung.",
    ),
    "cert_validation_off": (
        r"(?i)(ALLOW_ALL_HOSTNAME|TrustAllCerts|checkServerTrusted\s*\(\s*\)\s*\{\s*\}|"
        r"allowsArbitraryLoads|setHostnameVerifier\s*\(\s*\w*ALLOW)",
        "Zertifikatspruefung abgeschaltet oder aufgeweicht.",
    ),
    "android_backup_on": (
        r"android:allowBackup\s*=\s*\"true\"",
        "App-Daten landen im Cloud-Backup.",
    ),
    "cleartext_traffic": (
        r"android:usesCleartextTraffic\s*=\s*\"true\"|NSAllowsArbitraryLoads",
        "Unverschluesselter Netzwerkverkehr erlaubt.",
    ),
    "insecure_storage": (
        r"(?i)(SharedPreferences|NSUserDefaults|UserDefaults\.standard)",
        "Speicher ohne Verschluesselung. Relevant bei Schluesseln oder Gesundheitsdaten.",
    ),
    "logging_call": (
        r"\b(Log\.[dviwe]|NSLog|print|console\.log|LOG_(INFO|DEBUG|WARNING|ERROR))\s*\(",
        "Logausgabe. Relevant, wenn Messwerte oder Kennungen darin stehen.",
    ),
}

GOVERNANCE = {
    "sbom": r"(?i)(sbom|bom\.json|cyclonedx|spdx)",
    "security_policy": r"(?i)security\.(md|txt)",
    "privacy_notice": r"(?i)(privacy|datenschutz)",
    "dpia": r"(?i)(dpia|dsfa|folgenabschaetzung)",
    "risk_management": r"(?i)(risk|risiko|14971|fmea)",
    "sw_lifecycle": r"(?i)(62304|lifecycle|sdlc)",
    "threat_model": r"(?i)(threat.?model|bedrohung)",
    "test_reports": r"(?i)(test.?report|verification|validation)",
    "changelog": r"(?i)changelog",
    "license": r"(?i)licen[cs]e",
}


def scan(root: Path, files: list[str], exclude: list[str]) -> dict:
    ex = [re.compile(p) for p in exclude]
    compiled = {k: (re.compile(p), d) for k, (p, d) in PATTERNS.items()}
    hits: dict[str, list] = {k: [] for k in PATTERNS}
    scanned = 0

    for rel in files:
        if any(e.search(rel) for e in ex):
            continue
        fp = root / rel
        try:
            if fp.stat().st_size > 2_000_000:
                continue
            text = fp.read_text(errors="ignore")
        except Exception:
            continue
        scanned += 1
        lines = text.splitlines()
        for key, (rx, _desc) in compiled.items():
            for n, line in enumerate(lines, 1):
                s = line.strip()
                # offensichtliche Kommentarzeilen zaehlen nicht als Fundstelle
                if s.startswith(("//", "*", "#", "--")):
                    continue
                if rx.search(line):
                    hits[key].append({
                        "file": rel,
                        "line": n,
                        "code": s[:180],
                    })
    return {"files_scanned": scanned, "hits": hits}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: collect.py <root> <profile.json> [out.json]", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    profile = json.loads(Path(sys.argv[2]).read_text())
    out_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    src = git_files(root, *profile.get("source_globs", ["*"]))
    all_files = git_files(root)
    exclude = profile.get("exclude_patterns", [])

    result = scan(root, src, exclude)

    gov = {}
    for key, pat in GOVERNANCE.items():
        rx = re.compile(pat)
        found = [f for f in all_files if rx.search(f)]
        gov[key] = found[:10]

    summary = {
        k: len(v) for k, v in result["hits"].items()
    }
    # Dateien mit den meisten Treffern bei unsicheren Kopien
    conc: dict[str, int] = {}
    for h in result["hits"]["unsafe_string_fn"]:
        conc[h["file"]] = conc.get(h["file"], 0) + 1

    payload = {
        "schema": 1,
        "profile": profile.get("name"),
        "root": str(root),
        "git": git_meta(root),
        "files_total": len(all_files),
        "files_scanned": result["files_scanned"],
        "counts": summary,
        "pattern_meaning": {k: d for k, (_p, d) in PATTERNS.items()},
        "hits": result["hits"],
        "hotspots_unsafe_string_fn": sorted(
            ({"file": f, "count": c} for f, c in conc.items()),
            key=lambda x: -x["count"],
        )[:15],
        "governance_artefacts": gov,
    }

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if out_path:
        out_path.write_text(text)
        print(f"geschrieben: {out_path}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
