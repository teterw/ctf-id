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

echo "text analysis"
printf 'flag{b64_layer}' | base64 | base64 > "$T/b64x2.txt"
printf 'synt{ebg_guvegrra}\n' > "$T/rot13.txt"
printf 'flag{hex}' | xxd -p > "$T/hex.txt"
printf '5f4dcc3b5aa765d61d8327deb882cf99\n' > "$T/md5.txt"
printf '01101000 01101001 00100000 01110100 01101000 01100101 01110010 01100101\n' > "$T/bin.txt"
printf '.... . .-.. .-.. --- / .-- --- .-. .-.. -..\n' > "$T/morse.txt"
printf 'n = 3233\ne = 3\nc = 2790\n' > "$T/rsa.txt"
printf '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.\n' > "$T/bf.txt"
printf 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n' > "$T/jwt.txt"
# shellcheck disable=SC2016  # literal $ in a crypt hash
printf '$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/\n' > "$T/sha512.txt"
printf 'Wkh vhfuhw phhwlqj lv dw plgqljkw qhdu wkh rog eulgjh\n' > "$T/caesar.txt"
printf 'Hello world. This is a normal sentence and nothing is hidden in it at all.\n' > "$T/plain.txt"
printf 'KLM{phfgbz_sbezng}\n' > "$T/custom.txt"
expect "base64 x2 → flag decoded"      "base64 → base64): flag{b64_layer}" -q "$T/b64x2.txt"
expect "rot13 → flag decoded"          "rot13): flag{rot_thirteen}"         -q "$T/rot13.txt"
expect "hex → flag decoded"            "hex): flag{hex}"                    -q "$T/hex.txt"
expect "md5 hash identified"           "hashcat -m 0"                       -q "$T/md5.txt"
expect "binary decoded"                "decodes to: hi there"               -q "$T/bin.txt"
expect "morse decoded"                 "HELLO WORLD"                        -q "$T/morse.txt"
expect "RSA params + small e hint"     "small e"                            -q "$T/rsa.txt"
expect "brainfuck identified"          "Brainfuck"                          -q "$T/bf.txt"
expect "JWT identified"                '"alg":"HS256"'                      -q "$T/jwt.txt"
expect "sha512crypt identified"        "hashcat -m 1800"                    -q "$T/sha512.txt"
expect "caesar cracked"                "The secret meeting"                 -q "$T/caesar.txt"
reject "plain English → no false flag" "★ FLAG"                             -q "$T/plain.txt"
reject "JWT → no false flag"           "★ FLAG"                             -q "$T/jwt.txt"
expect "custom flag format via -f"     "rot13): XYZ{custom_format}"         -q -f XYZ "$T/custom.txt"

echo "structure checks"
python3 - "$T" <<'PY'
import sys, zlib, struct
d = sys.argv[1]
def chunk(t, b): return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
raw = b''.join(b'\0' + b'\xff\0\0' * 4 for _ in range(6))
png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 4, 6, 8, 2, 0, 0, 0))
       + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))
w = lambda n, b: open(f'{d}/{n}', 'wb').write(b)
w('good.png', png)
t = bytearray(png); t[20:24] = struct.pack('>I', 3); w('tall.png', t)
w('badhdr.png', b'\0' * 8 + png[8:])
w('append.png', png + b'PK\x03\x04secretzipdata')
w('rev.png', png[::-1])
w('xor.png', bytes(b ^ 0x42 for b in png))
PY
expect "tampered PNG height recovered"  "the real size is 4x6"   -q "$T/tall.png"
expect "broken PNG signature"           "Broken PNG header"      -q "$T/badhdr.png"
expect "zip appended after IEND"        "looks like a ZIP"       -q "$T/append.png"
expect "reversed file"                  "Reversed file"          -q "$T/rev.png"
expect "single-byte XOR"                "0x42"                   -q "$T/xor.png"
reject "clean PNG → no structure alarm" "Structure check"        -q "$T/good.png"
reject "ELF → no structure alarm"       "Structure check"        -q /bin/ls

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
