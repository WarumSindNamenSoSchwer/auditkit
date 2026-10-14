#!/usr/bin/env python3
"""
Rendert findings.json in lesbare Formate:
  report.md   - Lesefassung, nach Schwere sortiert
  register.csv - Risikoregister in den Spalten der CRA-Vorlage
  report.html - fuer die PDF-Erzeugung
"""
import csv
import html
import json
import sys
from datetime import date
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "KRITISCH", "high": "HOCH", "medium": "MITTEL", "low": "NIEDRIG"}
CONF_LABEL = {
    "confirmed": "belegt",
    "probable": "wahrscheinlich",
    "unverified": "nicht verifizierbar",
}


def band(score: int) -> str:
    if score >= 17:
        return "sehr hoch"
    if score >= 10:
        return "hoch"
    if score >= 5:
        return "mittel"
    return "niedrig"


def load(path: Path) -> dict:
    d = json.loads(path.read_text())
    for iss in d.get("issues", []):
        iss["risk"] = int(iss.get("impact", 0)) * int(iss.get("likelihood", 0))
        iss["residual_risk"] = int(iss.get("residual_impact", 0)) * int(
            iss.get("residual_likelihood", 0)
        )
    return d


def findings_for(data: dict, issue_id: str) -> list:
    return [f for f in data.get("findings", []) if f.get("issue_id") == issue_id]


def render_md(d: dict) -> str:
    meta = d.get("meta", {})
    s = d.get("summary", {})
    issues = sorted(
        d.get("issues", []),
        key=lambda i: (SEV_ORDER.get(i.get("severity"), 9), -i["risk"]),
    )
    counts = {k: 0 for k in SEV_ORDER}
    for i in issues:
        counts[i.get("severity", "low")] = counts.get(i.get("severity", "low"), 0) + 1

    o: list[str] = []
    a = o.append
    a(f"# Sicherheitsbestandsaufnahme — {meta.get('profile', '?')}")
    a("")
    a(f"Stand {date.today().isoformat()} · Commit `{meta.get('commit', '?')}` · "
      f"{meta.get('scanned_files', '?')} Dateien geprüft")
    a("")
    a("> Bestandsaufnahme, keine Maßnahmenplanung. Der Bericht beschreibt, was")
    a("> vorliegt, nicht wie es zu beheben ist.")
    a("")

    if s.get("headline"):
        a(f"## {s['headline']}")
        a("")
    if s.get("posture"):
        a(s["posture"])
        a("")

    a("| Schwere | Anzahl |")
    a("|---|---|")
    for k in ("critical", "high", "medium", "low"):
        a(f"| {SEV_LABEL[k]} | {counts.get(k, 0)} |")
    a(f"| **Summe** | **{len(issues)}** |")
    a("")

    if s.get("biggest_concerns"):
        a("**Die drei größten Baustellen**")
        a("")
        for i, c in enumerate(s["biggest_concerns"], 1):
            a(f"{i}. {c}")
        a("")

    a("---")
    a("")
    a("## Überblick")
    a("")
    a("| # | Problem | Bereich | Schwere | Risiko | Belegt | Stellen |")
    a("|---|---|---|---|---|---|---|")
    for n, i in enumerate(issues, 1):
        nf = len(findings_for(d, i["id"]))
        a(f"| {n} | {i.get('title','')} | {i.get('component','')} | "
          f"{SEV_LABEL.get(i.get('severity'),'')} | {i['risk']} ({band(i['risk'])}) | "
          f"{CONF_LABEL.get(i.get('confidence'),'')} | {nf} |")
    a("")
    a("---")
    a("")
    a("## Die Probleme im Einzelnen")
    a("")

    for n, i in enumerate(issues, 1):
        a(f"### {n}. {i.get('title','')}")
        a("")
        a(f"**{SEV_LABEL.get(i.get('severity'),'')}** · Risiko {i['risk']} von 25 "
          f"({band(i['risk'])}) · {CONF_LABEL.get(i.get('confidence'),'')} · "
          f"{i.get('component','')}")
        a("")
        if i.get("what"):
            a(i["what"])
            a("")
        if i.get("why_it_matters"):
            a("**Warum das zählt**")
            a("")
            a(i["why_it_matters"])
            a("")
        if i.get("attacker_view"):
            a("**Aus Angreifersicht**")
            a("")
            a(i["attacker_view"])
            a("")

        rows = [
            ("Umfang", i.get("scope")),
            ("Fehlende Kontrolle", i.get("missing_control")),
            ("Nachprüfbar durch", i.get("verification")),
            ("Schutzziel", i.get("security_property")),
            ("Angreifer", i.get("threat_actor")),
            ("Angriffsweg", i.get("attack_vector")),
            ("Bezug", i.get("reference")),
            ("Zuständig", i.get("owner_role")),
        ]
        a("| | |")
        a("|---|---|")
        for k, v in rows:
            if v:
                a(f"| {k} | {v} |")
        a("")

        fs = findings_for(d, i["id"])
        if fs:
            a(f"**Fundstellen ({len(fs)})**")
            a("")
            for f in fs:
                loc = f.get("file", "?")
                if f.get("line"):
                    loc += f":{f['line']}"
                a(f"- `{loc}`")
                if f.get("snippet"):
                    a(f"  ```")
                    a(f"  {f['snippet']}")
                    a(f"  ```")
                if f.get("data_flow"):
                    a(f"  Datenfluss: {f['data_flow']}")
                if f.get("note"):
                    a(f"  {f['note']}")
            a("")
        a("---")
        a("")

    na = d.get("not_assessable", [])
    if na:
        a("## Nicht beurteilbar")
        a("")
        a("Was im Repository schlicht nicht steht. Diese Punkte sind weder gut")
        a("noch schlecht bewertet, sie sind offen.")
        a("")
        a("| Thema | Warum nicht beurteilbar | Was es bräuchte |")
        a("|---|---|---|")
        for x in na:
            a(f"| {x.get('topic','')} | {x.get('why','')} | {x.get('needed','')} |")
        a("")

    qs = d.get("questions", [])
    if qs:
        a("## Fragen ans Team")
        a("")
        for q in qs:
            a(f"- **{q.get('to','')}**: {q.get('q','')}")
        a("")

    a("---")
    a("")
    a(f"_{meta.get('assumption_residual','')}_")
    a("")
    return "\n".join(o)


CSV_COLS = [
    "Risk ID", "Category", "Component / Asset", "Threat / Risk Scenario",
    "Threat Actor", "Attack Vector", "Security Property",
    "Impact (1-5)", "Likelihood (1-5)", "Initial Risk",
    "Mitigation / Security Measure", "Verification / Evidence",
    "Residual Impact (1-5)", "Residual Likelihood (1-5)", "Residual Risk",
    "Reference", "Owner", "Status", "Notes",
]


def render_csv(d: dict, path: Path) -> None:
    issues = sorted(d.get("issues", []), key=lambda i: -i["risk"])
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(CSV_COLS)
        for i in issues:
            fs = findings_for(d, i["id"])
            locs = ", ".join(
                f"{f['file']}:{f['line']}" if f.get("line") else f.get("file", "")
                for f in fs[:6]
            )
            if len(fs) > 6:
                locs += f" (+{len(fs)-6} weitere)"
            w.writerow([
                i.get("id", ""),
                i.get("category", ""),
                i.get("component", ""),
                i.get("what", "").replace("\n", " "),
                i.get("threat_actor", ""),
                i.get("attack_vector", ""),
                i.get("security_property", ""),
                i.get("impact", ""),
                i.get("likelihood", ""),
                i["risk"],
                i.get("missing_control", "").replace("\n", " "),
                i.get("verification", "").replace("\n", " "),
                i.get("residual_impact", ""),
                i.get("residual_likelihood", ""),
                i["residual_risk"],
                i.get("reference", ""),
                i.get("owner_role", ""),
                "Open",
                f"Belegt: {CONF_LABEL.get(i.get('confidence'),'')}. Fundstellen: {locs}",
            ])


CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font: 10.5pt/1.5 -apple-system, "Helvetica Neue", Arial, sans-serif;
       color: #1a1a1a; max-width: 100%; }
h1 { font-size: 20pt; margin: 0 0 4pt; border-bottom: 2px solid #1a1a1a;
     padding-bottom: 6pt; }
h2 { font-size: 14pt; margin: 20pt 0 6pt; border-bottom: 1px solid #bbb;
     padding-bottom: 3pt; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 16pt 0 4pt; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt;
        font-size: 9pt; page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 4pt 6pt; text-align: left;
         vertical-align: top; }
th { background: #f0f0f0; font-weight: 600; }
code { background: #f4f4f4; padding: 1pt 3pt; font-size: 8.5pt;
       font-family: "SF Mono", Menlo, monospace; }
pre { background: #f4f4f4; padding: 5pt 7pt; font-size: 8pt; overflow-x: auto;
      border-left: 2px solid #999; margin: 3pt 0; }
pre code { background: none; padding: 0; }
blockquote { border-left: 3px solid #999; margin: 8pt 0; padding: 2pt 0 2pt 10pt;
             color: #555; font-style: italic; }
hr { border: 0; border-top: 1px solid #ddd; margin: 14pt 0; }
li { margin: 2pt 0; }
.sev-KRITISCH { color: #a00; font-weight: 700; }
.sev-HOCH { color: #c45500; font-weight: 700; }
"""


def md_to_html(md: str) -> str:
    """Schlanker Markdown-Renderer fuer genau die Konstrukte, die oben
    erzeugt werden. Kein externes Paket noetig."""
    out: list[str] = []
    in_table = False
    in_pre = False
    in_list = False

    def esc(t: str) -> str:
        return html.escape(t, quote=False)

    def inline(t: str) -> str:
        t = esc(t)
        res, i = [], 0
        while i < len(t):
            if t.startswith("**", i):
                j = t.find("**", i + 2)
                if j > 0:
                    res.append("<strong>" + t[i + 2:j] + "</strong>")
                    i = j + 2
                    continue
            if t[i] == "`":
                j = t.find("`", i + 1)
                if j > 0:
                    res.append("<code>" + t[i + 1:j] + "</code>")
                    i = j + 1
                    continue
            if t[i] == "_" and i + 1 < len(t):
                j = t.find("_", i + 1)
                if j > 0:
                    res.append("<em>" + t[i + 1:j] + "</em>")
                    i = j + 1
                    continue
            res.append(t[i])
            i += 1
        return "".join(res)

    lines = md.split("\n")
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_pre:
                out.append("</code></pre>")
                in_pre = False
            else:
                out.append("<pre><code>")
                in_pre = True
            continue
        if in_pre:
            out.append(esc(line))
            continue

        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(set(c) <= set("-: ") and c for c in cells):
                continue  # Trennzeile
            if not in_table:
                out.append("<table>")
                in_table = True
                out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
            else:
                tds = []
                for c in cells:
                    cls = ""
                    for sev in ("KRITISCH", "HOCH"):
                        if c.strip() == sev:
                            cls = f' class="sev-{sev}"'
                    tds.append(f"<td{cls}>{inline(c)}</td>")
                out.append("<tr>" + "".join(tds) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False

        if stripped.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(stripped[2:])}</li>")
            continue
        if in_list and not stripped.startswith(("  ", "- ")):
            out.append("</ul>")
            in_list = False
        if in_list:
            out.append(f"<li>{inline(stripped)}</li>")
            continue

        if stripped.startswith("### "):
            out.append(f"<h3>{inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            out.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            out.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            out.append(f"<blockquote>{inline(stripped[2:])}</blockquote>")
        elif stripped == "---":
            out.append("<hr>")
        elif not stripped:
            out.append("")
        else:
            out.append(f"<p>{inline(stripped)}</p>")

    if in_table:
        out.append("</table>")
    if in_list:
        out.append("</ul>")
    if in_pre:
        out.append("</code></pre>")

    body = "\n".join(out)
    return (f"<!DOCTYPE html><html lang=\"de\"><head><meta charset=\"utf-8\">"
            f"<style>{CSS}</style></head><body>{body}</body></html>")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: render.py <findings.json> <outdir>", file=sys.stderr)
        return 2
    data = load(Path(sys.argv[1]))
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)

    md = render_md(data)
    (out / "report.md").write_text(md)
    (out / "report.html").write_text(md_to_html(md))
    render_csv(data, out / "register.csv")

    n_i = len(data.get("issues", []))
    n_f = len(data.get("findings", []))
    print(f"report.md, report.html, register.csv  ({n_i} Probleme, {n_f} Fundstellen)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
