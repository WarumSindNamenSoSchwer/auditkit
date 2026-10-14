#!/usr/bin/env python3
"""
Holt das JSON-Objekt aus einer Modellantwort. Modelle umrahmen JSON gern mit
Prosa oder Codefences, deshalb wird hier robust gesucht statt blind geparst.
"""
import json
import re
import sys
from pathlib import Path


def candidates(text: str):
    # 1. ganze Datei
    yield text
    # 2. Inhalt von ```json ... ``` oder ``` ... ```
    for m in re.finditer(r"```(?:json)?\s*\n(.*?)```", text, re.S):
        yield m.group(1)
    # 3. groesster ausbalancierter Block ab erster oeffnender Klammer
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield text[start:i + 1]
                    break
        start = text.find("{", start + 1)
        if start > 20000:
            break


REQUIRED = ("issues", "findings")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: extract_json.py <raw.txt> <out.json>", file=sys.stderr)
        return 2
    raw = Path(sys.argv[1]).read_text(errors="ignore")

    best = None
    for cand in candidates(raw):
        cand = cand.strip()
        if not cand.startswith("{"):
            continue
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        score = sum(1 for k in REQUIRED if k in obj)
        if score == len(REQUIRED):
            best = obj
            break
        if best is None and score:
            best = obj

    if best is None:
        print("kein verwertbares JSON gefunden", file=sys.stderr)
        return 1

    best.setdefault("issues", [])
    best.setdefault("findings", [])

    # Verwaiste Findings sichtbar machen statt stillschweigend verlieren
    ids = {i.get("id") for i in best["issues"]}
    orphans = [f for f in best["findings"] if f.get("issue_id") not in ids]
    if orphans:
        print(f"Warnung: {len(orphans)} Fundstelle(n) ohne passendes Problem",
              file=sys.stderr)

    Path(sys.argv[2]).write_text(json.dumps(best, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
