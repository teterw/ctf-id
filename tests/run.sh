#!/usr/bin/env bash
# Test suite for ctf-id. Builds its fixtures in a temp dir, so no binary files
# live in the repo. Run: tests/run.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
CTF_ID="$PWD/ctf-id"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0

# expect <description> <needle> <ctf-id args...>
expect(){
  local desc="$1" needle="$2"; shift 2
  local out; out=$("$CTF_ID" "$@" 2>&1)
  if grep -qF -- "$needle" <<<"$out"; then pass=$((pass+1)); printf '  ok   %s\n' "$desc"
  else fail=$((fail+1)); printf '  FAIL %s\n       wanted: %s\n' "$desc" "$needle"; printf '%s\n' "$out" | head -40 | sed 's/^/       | /'; fi
}
# reject <description> <needle> <ctf-id args...>  — output must NOT contain needle
reject(){
  local desc="$1" needle="$2"; shift 2
  local out; out=$("$CTF_ID" "$@" 2>&1)
  if grep -qF -- "$needle" <<<"$out"; then fail=$((fail+1)); printf '  FAIL %s\n       unwanted: %s\n' "$desc" "$needle"
  else pass=$((pass+1)); printf '  ok   %s\n' "$desc"; fi
}

# ---- fixtures --------------------------------------------------------------
printf 'flag{hello_world}\n' > "$T/flag.txt"
printf '\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\1\0\0\0\1\x08\x02\0\0\0\x90wS\xde\0\0\0\x0cIDATx\x9cc\xf8\x0f\0\0\x01\x01\0\x05\x18\xd8N\0\0\0\0IEND\xaeB`\x82' > "$T/img.png"
printf 'PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0' > "$T/empty.zip"
head -c 4096 /dev/urandom > "$T/random.bin"
if command -v mkfs.ext4 >/dev/null; then truncate -s 2M "$T/disk.img"; mkfs.ext4 -q "$T/disk.img" 2>/dev/null; fi

echo "cli"
expect "--version prints version"      "ctf-id "            --version
expect "--help prints usage"           "usage: ctf-id"      --help
expect "missing file is reported"      "not found:"         -q "$T/nope"

echo "detection"
expect "plain-text flag is found"      "flag{hello_world}"  -q "$T/flag.txt"
expect "ELF → reverse engineering"     "ELF binary"         -q /bin/ls
expect "PNG → steganography"           "STEGANOGRAPHY"      -q "$T/img.png"
expect "ZIP → extract"                 "ZIP archive"        -q "$T/empty.zip"
expect "random bytes → carve"          "CARVE"              -q "$T/random.bin"
expect "high entropy is flagged"       "high →"                "$T/random.bin"
[ -f "$T/disk.img" ] && expect "ext4 image → forensics" "FORENSICS" -q "$T/disk.img"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
