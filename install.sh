#!/usr/bin/env bash
# auditkit installieren. Legt einen Symlink nach ~/.local/bin/audit an.
# Aendert sonst nichts am System.
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:-$HOME/.local/bin}"

command -v python3 >/dev/null || { echo "python3 fehlt" >&2; exit 1; }
command -v claude  >/dev/null || echo "Hinweis: claude nicht gefunden, wird zur Laufzeit gebraucht." >&2

mkdir -p "$BIN"
ln -sf "$KIT/bin/audit" "$BIN/audit"
chmod +x "$KIT/bin/audit" "$KIT"/lib/*.py

echo "installiert: $BIN/audit -> $KIT/bin/audit"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *)
    echo
    echo "$BIN liegt nicht im PATH. Zum Beispiel in ~/.zshrc ergaenzen:"
    echo "  export PATH=\"\$PATH:$BIN\""
    ;;
esac

# PDF-Weg pruefen, damit der erste Lauf nicht ueberrascht
pdf=""
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
         "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
         "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
  [ -x "$c" ] && { pdf="$c"; break; }
done
if [ -n "$pdf" ]; then
  echo "PDF-Ausgabe ueber: $(basename "$pdf")"
else
  echo "Kein Chromium-Browser gefunden. PDF entfaellt, report.html und report.md bleiben."
fi

echo
echo "Start:  audit"
