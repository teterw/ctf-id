#!/usr/bin/env bash
# Install ctf-id into ~/.local/bin (or $PREFIX/bin), plus bash/zsh completion.
#   curl -fsSL https://raw.githubusercontent.com/teterw/ctf-id/main/install.sh | bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
DEST="$PREFIX/bin"
RAW="https://raw.githubusercontent.com/teterw/ctf-id/main"
mkdir -p "$DEST"
curl -fsSL "$RAW/ctf-id" -o "$DEST/ctf-id"
chmod +x "$DEST/ctf-id"
echo "installed: $DEST/ctf-id"

# completions are optional — never fail the install over them
BASH_COMP="$PREFIX/share/bash-completion/completions"
ZSH_COMP="$PREFIX/share/zsh/site-functions"
if mkdir -p "$BASH_COMP" 2>/dev/null && curl -fsSL "$RAW/completions/ctf-id.bash" -o "$BASH_COMP/ctf-id" 2>/dev/null; then
  echo "installed: bash completion"
fi
if mkdir -p "$ZSH_COMP" 2>/dev/null && curl -fsSL "$RAW/completions/_ctf-id" -o "$ZSH_COMP/_ctf-id" 2>/dev/null; then
  echo "installed: zsh completion (add $ZSH_COMP to your fpath)"
fi

case ":$PATH:" in *":$DEST:"*) ;; *) echo "note: add $DEST to your PATH" ;; esac
