# ctf-id

Point it at a CTF challenge file and it tells you **what the file is** and **which tools to try next**, with commands you can copy and paste.

```
$ ctf-id challenge.png
────────────────────────────────────────────────────────
challenge.png  (48K)
  file: PNG image data, 800 x 600, 8-bit/color RGBA, non-interlaced
  mime: image/png   sha256: 3f9a1c0e7b2d44a1…
  • entropy: 7.91/8.0 (high → compressed/encrypted/packed)

▶ Image → STEGANOGRAPHY / METADATA
  exiftool           metadata, comments, GPS — check FIRST
     $ exiftool challenge.png
  zsteg              LSB stego in PNG/BMP (best first pass)
     $ zsteg -a challenge.png
  ...
```

`ctf-id` never changes or runs the target file. It only reads it and prints suggestions.

## What it does

- Identifies the file with `file(1)` and shows its size, MIME type and SHA-256
- Calculates Shannon entropy, where a high value suggests compressed, encrypted or packed data
- Looks for strings shaped like `flag{...}` or `CTF{...}` that are already in plain text
- Uses `binwalk` to find embedded files
- **Reads text files and works out what's in them** (see below). When a flag is hidden under layers of encoding, it decodes them and prints the flag
- Recommends tools and ready-to-run commands for the file type:

| Detected type | Category | Suggested tools |
|---|---|---|
| ELF | Reverse engineering / pwn | checksec, Ghidra, radare2, gdb+GEF, pwntools, ROPgadget, one_gadget |
| PE / MS-DOS | Windows reverse engineering | Ghidra, radare2, strings; ilspycmd when it detects .NET |
| Mach-O | macOS reverse engineering | Ghidra, radare2, otool |
| WebAssembly | Reverse engineering | wasm2wat, wasm-decompile, Ghidra |
| Python / .pyc | Source / bytecode | uncompyle6, decompyle3, pycdc |
| JAR / APK / DEX | Decompiling | jadx, apktool |
| ZIP / 7z / tar / gz / rar | Archives | 7z, bsdtar, zip2john, fcrackzip |
| PNG / JPEG / GIF / BMP | Steganography | exiftool, zsteg, steghide, stegseek, stegsolve, binwalk |
| WAV / MP3 / FLAC / OGG | Audio steganography | sox spectrogram, steghide |
| PDF | Documents | pdftotext, pdfdetach, pdf2john, qpdf |
| Word / Excel / PowerPoint (OOXML + OLE) | Macros / hidden content | olevba, oleid, office2john |
| SQLite | Databases | sqlite3 `.dump`, recovering deleted rows |
| KeePass | Password cracking | keepass2john, keepassxc-cli |
| Email (.eml) | Headers / attachments | munpack |
| pcap / pcapng | Network | Wireshark, tshark, tcpflow |
| Keys / certificates | Crypto | RsaCtfTool, openssl, ssh2john |
| Disk / filesystem images | Forensics | sleuthkit, testdisk, volatility3 |
| Large unidentified files | Memory dumps | volatility3 |
| Windows event logs / registry hives | Windows forensics | evtx_dump, chainsaw, regripper, secretsdump |
| Git repository (directory) | History forensics | `git log --all -p`, reflog, stash, fsck, git-dumper |
| Text | Encoding / crypto | CyberChef, name-that-hash, xortool |
| Unknown data | Carving | xxd, binwalk, foremost |

## Text analysis

`ctf-id` doesn't stop at "it's text". It reads the contents and tells you what they are:

```
$ ctf-id secret.txt
▶ Text → ENCODING / CRYPTO / CODE

  ★ FLAG (decoded via base64 → hex → rot13): flag{layers_all_the_way_down}
```

It recognises:

| Content | Example |
|---|---|
| Base64, Base32, Ascii85, hex, binary, decimal, octal, URL encoding | `ZmxhZ3t...`, `01101000 01101001` |
| Morse code | `.... . .-.. .-.. ---` |
| Caesar / ROT-n (it tries all 25 shifts and scores them for English) | `Wkh vhfuhw phhwlqj` |
| Substitution or Vigenère (from the index of coincidence) | letters only, no English words |
| Hashes: MD5/NTLM, SHA-1/224/256/384/512, bcrypt, md5crypt, sha256/512crypt, yescrypt, NetNTLMv2 | prints the right `hashcat -m` mode |
| JWT | shows the decoded header and common attacks |
| RSA values `n`, `e`, `c`, `p`, `q` | flags small e, huge e (Wiener), and small n that can be factored |
| Brainfuck, Ook!, uuencode, zero-width characters, whitespace steganography | |

To find a flag, it tries chains of up to 3 decoders (base64, base32, hex, binary, rot13, rot47, atbash, reverse, and more), plus all Caesar shifts. Out of the box it looks for `flag{…}`, `CTF{…}`, `HTB{…}` and `THM{…}`. For any other event's format, use `-f`:

```bash
ctf-id -f DUCTF challenge.txt
```

## Structure checks

CTF authors often damage a file on purpose so that `file` just reports `data`. `ctf-id` checks for this and shows how to undo it:

| Trick | What ctf-id reports |
|---|---|
| Magic bytes overwritten (PNG, JPEG, WAV, ZIP, PDF, ELF) | the original type, plus a `printf \| dd` command that writes the correct bytes back |
| PNG height or width edited | brute-forces the IHDR CRC to find the **real dimensions**, plus the command to patch them |
| Data appended after `IEND`, `FF D9`, GIF trailer or `%%EOF` | the offset, the type of the hidden data, and a `dd` command to cut it out |
| Whole file reversed | detects it and gives a one-liner to reverse it back |
| Whole file XOR-ed with a single byte | finds the key and gives a one-liner to decode it |

## `--run`: do the first checks for me

By default `ctf-id` never runs anything on the file. With `-r` / `--run`, it also runs the quick, read-only first checks for that file type and shows the results inline. Anything shaped like a flag is highlighted:

| Type | What `--run` runs |
|---|---|
| ELF | `checksec`, risky imported functions (`gets`, `strcpy`, `system`…), interesting strings |
| PNG/BMP | `exiftool` metadata, `zsteg`, `steghide` with an empty password |
| JPEG/GIF | `exiftool` metadata, `steghide` with an empty password |
| Audio | `exiftool`, and a spectrogram PNG made with `sox` |
| PDF | `exiftool`, `pdfdetach -list`, `pdftotext` |
| pcap | `tshark` protocol breakdown, HTTP requests, FTP/HTTP credentials |
| Archives | `7z` listing and a count of encrypted entries |
| Images | `zbarimg` to read QR codes and barcodes |
| SQLite | tables, plus any rows mentioning flag/pass/secret |
| Office | `oleid`, `olevba --decode` |
| Git repository | all commits, secrets in the diff history, stashes |

```
$ ctf-id -r challenge.png
▶ --run: quick read-only checks
  exiftool $ exiftool -S -Comment ... challenge.png
     Comment: flag{in_the_metadata}
  ★ possible flag: flag{in_the_metadata}
```

Each command has a 30-second timeout. Output files such as extracted data and spectrograms go into a temporary folder, so the challenge file is never modified.

## `--deep`: unpack nested challenges

Some challenges hide a flag inside several layers, for example a tgz containing a tar containing a PNG with a zip appended to it. `-d` / `--deep` extracts each archive (with `7z` or `bsdtar`) or carves out embedded files (with `binwalk`), then runs `ctf-id` on every file it finds, up to 3 levels deep:

```
$ ctf-id -d challenge.tgz
▶ --deep: 1 file(s) extracted from challenge.tgz → /tmp/ctf-id.87G1NQ/deep-EuaR
↳ nested (level 1)  challenge.tar
↳ nested (level 2)  outer.png   ▶ Structure check — appended data, looks like a ZIP
↳ nested (level 3)  secret.txt
  ★ FLAG (decoded via base64): flag{deep_inside}
```

Everything is extracted into a temporary folder, never next to your file. Each extraction has a timeout, and it stops after 60 files. You can combine it with `--run`: `ctf-id -d -r file`.

## Which tools do you have?

Each suggested tool is marked **✓** if it's installed and **✗** if it isn't. At the end, `ctf-id` lists the missing tools with the install command for your system (`dnf`, `apt`, `pacman` or `brew`, falling back to `pip`, `gem` or a download link):

```
▶ suggested tools you don't have yet
  ✗ zsteg                  gem install zsteg
  ✗ stegseek               https://github.com/RickdeJager/stegseek/releases
```

To check your whole setup before a CTF:

```bash
ctf-id --doctor
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/teterw/ctf-id/main/install.sh | bash
```

The installer puts `ctf-id` in `~/.local/bin` and installs tab completion for bash and zsh. Set `PREFIX=/usr/local` (and run it with sudo) to install it system-wide.

To install by hand:

```bash
curl -fsSLO https://raw.githubusercontent.com/teterw/ctf-id/main/ctf-id
chmod +x ctf-id && mv ctf-id ~/.local/bin/
```

To update later, run `ctf-id --update`. It only replaces itself when a newer version is available.

You can also download it from the [latest release](https://github.com/teterw/ctf-id/releases/latest).

## Usage

```bash
ctf-id <file> [file2 ...]   # full analysis
ctf-id -q <file>            # quick: skip entropy and binwalk
ctf-id -f PREFIX <file>     # also hunt for PREFIX{...} flags
ctf-id -r <file>            # also run the quick read-only checks
ctf-id -d <file>            # unpack nested archives/embedded files and analyse them too
ctf-id --doctor             # which suggested tools are installed?
ctf-id --update             # update to the latest version
ctf-id --version
```

## Requirements

- Required: `bash` (3.2 or newer) and `file`. Works on Linux and macOS, both tested in CI
- Optional: `python3` for entropy, `strings` from binutils for flag search, and `binwalk` for embedded files

Any optional tool that is missing is skipped without an error. `ctf-id` only recommends the other tools; you don't need them installed to run it.

## License

MIT
