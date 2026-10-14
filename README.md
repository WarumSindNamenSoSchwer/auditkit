# auditkit

Sicherheitsbestandsaufnahme für Embedded-Firmware und mobile Apps.

Erzeugt einen lesbaren Bericht (PDF und Markdown) plus ein Risikoregister als
CSV, das sich in eine CRA-Risikoanalyse einfügen lässt.

**Bestandsaufnahme, keine Maßnahmenplanung.** Der Bericht beschreibt, was
vorliegt, nicht wie es zu beheben ist.

## Installation

```bash
git clone https://github.com/WarumSindNamenSoSchwer/auditkit.git
cd auditkit
./install.sh
```

Legt einen Symlink `~/.local/bin/audit` an, sonst nichts. Das Werkzeug bleibt
in dem Ordner, in den du es geklont hast, und **dort landen auch die
Ergebnisse** (`<auditkit>/audits/`).

Liegt `~/.local/bin` nicht im `PATH`, sagt der Installer es dir. Alternativ
ohne Installation direkt `./bin/audit` aufrufen.

Voraussetzungen: `python3`, [Claude Code](https://claude.com/claude-code).
Für PDF genügt ein installierter Chromium-Browser, keine extra Abhängigkeit.

## Erster Lauf

```bash
audit
```

Zwei Fragen, dann läuft es:

```
Was soll geprueft werden?
  1) Firmware  (Uhr, C/C++)
  2) App       (Android / iOS / Flutter)
Auswahl [1/2]: 1
Projektwurzel [.]: ~/Repos/mein-firmware-projekt
```

Danach fünf Schritte, zusammen wenige Minuten:

```
[1/5] Messbare Fakten erheben ...
      360 Dateien, 1667 Fundstellen in 10 Mustern
[2/5] Analyse (dauert einige Minuten) ...
[3/5] Belege pruefen ...
      Validierung ok: 10 Probleme, 17 Fundstellen
[4/5] Bericht erzeugen ...
[5/5] PDF ...

Fertig.
  .../auditkit/audits/mein-projekt-firmware-2026-10-14/report.pdf
  ...
  10 Probleme: 3 kritisch, 4 hoch, 3 mittel
```

## Benutzung

Interaktiv:

```bash
audit
```

Direkt, ohne Rückfragen:

```bash
audit --target fw  --root ~/Repos/mein-firmware-projekt
audit --target app --root . --open
```

| Option | Bedeutung |
|---|---|
| `--target fw\|app` | Was geprüft wird |
| `--root PFAD` | Projektwurzel, muss ein Git-Repository sein |
| `--out PFAD` | Anderer Ausgabeordner |
| `--model NAME` | Modell für die Analyse |
| `--open` | Bericht danach öffnen |
| `--no-pdf` | PDF überspringen |
| `--quiet` | Weniger Ausgabe |

**Das geprüfte Projekt wird nur gelesen.** Es wird nichts hineingeschrieben
und nichts verändert.

Passt das Profil nicht zum Projekt, etwa `--target app` auf einem
C-Firmware-Baum, fragt das Werkzeug nach, bevor es loslegt.

## Wo die Ergebnisse liegen

```
<auditkit>/audits/<projekt>-<profil>-<datum>/
```

Also dort, wo du das Repository hingeklont hast. Alle Läufe sammeln sich an
einem Ort und lassen sich später vergleichen. Ein zweiter Lauf am selben Tag
überschreibt nichts, er bekommt `-2` angehängt.

`audits/` ist per `.gitignore` ausgeschlossen. Befunde aus fremden Projekten
landen damit nicht versehentlich in einem öffentlichen Repository.

| Datei | Zweck |
|---|---|
| `report.pdf` | Lesefassung zum Weitergeben |
| `report.md` | dasselbe als Markdown |
| `register.csv` | Risikoregister, Semikolon-getrennt, 19 CRA-Spalten |
| `findings.json` | Rohdaten, maschinenlesbar |
| `facts.json` | die deterministische Messung |

Das CSV ist auf die Spalten einer CRA-Risikoanalyse zugeschnitten und lässt
sich in ein vorhandenes Risk Register einfügen. UTF-8 mit BOM und Semikolon,
damit Excel auf deutschen Systemen es direkt richtig öffnet.

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
