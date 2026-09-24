#!/usr/bin/env bash
# Install ctf-id into ~/.local/bin (or $PREFIX/bin).
#   curl -fsSL https://raw.githubusercontent.com/teterw/ctf-id/main/install.sh | bash
set -euo pipefail
DEST="${PREFIX:-$HOME/.local}/bin"
URL="https://raw.githubusercontent.com/teterw/ctf-id/main/ctf-id"
mkdir -p "$DEST"
curl -fsSL "$URL" -o "$DEST/ctf-id"
chmod +x "$DEST/ctf-id"
echo "installed: $DEST/ctf-id"
case ":$PATH:" in *":$DEST:"*) ;; *) echo "note: add $DEST to your PATH" ;; esac
