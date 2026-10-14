# auditkit

Sicherheitsbestandsaufnahme für Embedded-Firmware und mobile Apps.

Erzeugt einen lesbaren Bericht (PDF und Markdown) plus ein Risikoregister als
CSV, das sich in eine CRA-Risikoanalyse einfügen lässt.

**Bestandsaufnahme, keine Maßnahmenplanung.** Der Bericht beschreibt, was
vorliegt, nicht wie es zu beheben ist.

## Installation

```bash
git clone <url> ~/Repos/auditkit
cd ~/Repos/auditkit
./install.sh
```

Legt einen Symlink `~/.local/bin/audit` an, sonst nichts.

Voraussetzungen: `python3`, [Claude Code](https://claude.com/claude-code).
Für PDF genügt ein installierter Chromium-Browser, keine extra Abhängigkeit.

## Benutzung

Interaktiv:

```bash
audit
```

Fragt nach Ziel (Firmware oder App) und Projektwurzel.

Direkt:

```bash
audit --target fw  --root ~/Repos/mein-firmware-projekt
audit --target app --root . --open
```

| Option | Bedeutung |
|---|---|
| `--target fw\|app` | Was geprüft wird |
| `--root PFAD` | Projektwurzel |
| `--out PFAD` | Ausgabeordner, Standard `~/Desktop/audits/<name>-<profil>-<datum>` |
| `--model NAME` | Modell für die Analyse |
| `--open` | Bericht danach öffnen |
| `--no-pdf` | PDF überspringen |
| `--quiet` | Weniger Ausgabe |

**Das geprüfte Projekt wird nur gelesen.** Es wird nichts hineingeschrieben
und nichts verändert.

## Ergebnis

| Datei | Zweck |
|---|---|
| `report.pdf` | Lesefassung zum Weitergeben |
| `report.md` | dasselbe als Markdown |
| `register.csv` | Risikoregister, Semikolon-getrennt, 19 CRA-Spalten |
| `findings.json` | Rohdaten, maschinenlesbar |
| `facts.json` | die deterministische Messung |

## Wie es arbeitet

```
1  Fakten erheben    deterministischer Scan, zählt und lokalisiert
2  Analyse           Modell bewertet die Fakten im Code-Kontext
3  Belege prüfen     jede Fundstelle gegen das Dateisystem
4  Bericht           Markdown, HTML, CSV
5  PDF               über Chromium headless
```

Der Trick liegt in Schritt 1 und 3.

**Schritt 1** zählt, was zählbar ist: unsichere Kopierfunktionen, GATT-
Berechtigungen, Debug-Schnittstellen, abgeschaltete Zertifikatsprüfung. Diese
Zahlen sind bei gleichem Commit immer identisch und werden dem Modell als
Tatsache vorgelegt, statt dass es sie selbst schätzt.

**Schritt 3** prüft jede behauptete Fundstelle gegen die Wirklichkeit. Zeigt
eine Angabe auf Zeile 1496 einer Datei mit 1034 Zeilen, wird die Angabe
entfernt und die Konfidenz herabgesetzt. Ohne diese Prüfung landen erfundene
Belege im Bericht, und genau das macht einen Audit wertlos.

## Zwei Ebenen im Bericht

Nicht eine flache Liste von Einzelzeilen, sondern:

- **Probleme** — die strukturellen Befunde. „BLE-Link ohne Verschlüsselung"
  ist ein Problem, auch wenn es an 23 Stellen sichtbar wird.
- **Fundstellen** — die Belege dazu, mit Datei, Zeile und Datenfluss.

Ein Problem ohne Fundstelle ist eine Behauptung. Eine Fundstelle ohne Problem
ist Rauschen.

## Konfidenz

Jedes Problem trägt eine von drei Stufen:

| Stufe | Bedeutung |
|---|---|
| belegt | im Code sichtbar |
| wahrscheinlich | starker Hinweis, ein Schluss |
| nicht verifizierbar | aus dem Repository nicht entscheidbar |

Alles, was von Hardware-Konfiguration, Build-Flags außerhalb des Baums oder
organisatorischen Prozessen abhängt, ist standardmäßig nicht verifizierbar.
Ein ehrliches „nicht verifizierbar" ist mehr wert als eine selbstbewusste
Vermutung.

## Profile

`profiles/firmware/profile.json` und `profiles/app/profile.json` legen fest,
welche Dateien geprüft werden, was ausgeschlossen bleibt (Vendor-SDKs) und
welches Bedrohungsmodell gilt.

Ein neues Profil ist eine Kopie mit angepassten Globs. Wer ein Backend oder
eine Weboberfläche prüfen will, legt `profiles/backend/profile.json` an.

## Grenzen

Statische Analyse. Findet fehlende Prüfungen, falsche Konfiguration,
unsichere Muster.

Findet **nicht**: Chip-off-Angriffe, Seitenkanäle, Glitching, Fehler in der
Hardware. Was außerhalb des Repositories konfiguriert wird, etwa ein
Flash-Lock beim Produktionsflashen, erscheint als nicht verifizierbar.

Ersetzt keinen Pentest.

## Lizenz

MIT
