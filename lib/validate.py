#!/usr/bin/env python3
"""
Prueft findings.json gegen die Wirklichkeit, bevor gerendert wird.

Haelt drei Fehlerklassen ab, die einen Bericht unbrauchbar machen:
  - erfundene Dateien oder Zeilennummern
  - Rechenfehler oder Residual ueber Initial
  - Fundstellen ohne Problem und Probleme ohne Fundstelle

Nicht belegbare Stellen werden entfernt, nicht stillschweigend uebernommen.
Rueckgabe 0 auch bei Korrekturen; nur strukturelle Schaeden brechen ab.
"""
import json
import sys
from pathlib import Path

SEV = ("critical", "high", "medium", "low")
CONF = ("confirmed", "probable", "unverified")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: validate.py <findings.json> <repo_root>", file=sys.stderr)
        return 2
    p = Path(sys.argv[1])
    root = Path(sys.argv[2])
    d = json.loads(p.read_text())

    issues = d.get("issues", [])
    findings = d.get("findings", [])
    problems: list[str] = []
    notes: list[str] = []

    # --- Fundstellen gegen das Dateisystem pruefen
    kept = []
    for f in findings:
        rel = f.get("file")
        if not rel:
            notes.append(f"{f.get('id','?')}: ohne Datei, entfernt")
            continue
        fp = root / rel
        if not fp.exists():
            notes.append(f"{f.get('id','?')}: Datei existiert nicht ({rel}), entfernt")
            continue
        line = f.get("line")
        if line:
            try:
                total = len(fp.read_text(errors="ignore").splitlines())
            except Exception:
                total = 0
            if line > total:
                notes.append(
                    f"{f.get('id','?')}: Zeile {line} > {total} in {rel}, "
                    f"Zeilenangabe entfernt")
                f["line"] = None
                f["snippet"] = None
                f["confidence"] = "unverified"
        kept.append(f)
    d["findings"] = kept

    # --- Arithmetik und Skalen
    for i in issues:
        iid = i.get("id", "?")
        for key in ("impact", "likelihood", "residual_impact", "residual_likelihood"):
            v = i.get(key)
            if not isinstance(v, int) or not 1 <= v <= 5:
                problems.append(f"{iid}: {key}={v!r} ausserhalb 1-5")
        if all(isinstance(i.get(k), int) for k in
               ("impact", "likelihood", "residual_impact", "residual_likelihood")):
            init = i["impact"] * i["likelihood"]
            res = i["residual_impact"] * i["residual_likelihood"]
            if res > init:
                notes.append(f"{iid}: Residual {res} > Initial {init}, auf Initial begrenzt")
                i["residual_impact"] = i["impact"]
                i["residual_likelihood"] = 1
        if i.get("severity") not in SEV:
            problems.append(f"{iid}: severity={i.get('severity')!r} unbekannt")
        if i.get("confidence") not in CONF:
            problems.append(f"{iid}: confidence={i.get('confidence')!r} unbekannt")

    # --- Verknuepfung Problem <-> Fundstelle
    ids = {i.get("id") for i in issues}
    for f in d["findings"]:
        if f.get("issue_id") not in ids:
            problems.append(f"{f.get('id','?')}: verweist auf unbekanntes Problem "
                            f"{f.get('issue_id')!r}")
    have = {f.get("issue_id") for f in d["findings"]}
    for i in issues:
        # 'unverified' darf ohne Fundstelle sein, alles andere braucht Beleg
        if i.get("id") not in have and i.get("confidence") != "unverified":
            notes.append(f"{i.get('id')}: keine belegte Fundstelle, "
                         f"Konfidenz auf unverified gesetzt")
            i["confidence"] = "unverified"
        # finding_ids konsistent neu setzen
        i["finding_ids"] = [f["id"] for f in d["findings"]
                            if f.get("issue_id") == i.get("id")]

    if problems:
        print("Strukturfehler:", file=sys.stderr)
        for x in problems:
            print(f"  {x}", file=sys.stderr)
        return 1

    if notes:
        print(f"Validierung: {len(notes)} Korrektur(en)", file=sys.stderr)
        for x in notes:
            print(f"  {x}", file=sys.stderr)

    d.setdefault("meta", {})["validated"] = True
    d["meta"]["validation_notes"] = notes
    p.write_text(json.dumps(d, indent=2, ensure_ascii=False))
    print(f"Validierung ok: {len(issues)} Probleme, {len(d['findings'])} Fundstellen",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
