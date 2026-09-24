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
- Recommends tools and ready-to-run commands for the file type:

| Detected type | Category | Suggested tools |
|---|---|---|
| ELF | Reverse engineering / pwn | checksec, Ghidra, radare2, gdb+GEF, pwntools, ROPgadget, one_gadget |
| PE / MS-DOS | Windows reverse engineering | Ghidra, radare2, strings (ILSpy for .NET) |
| Python / .pyc | Source / bytecode | uncompyle6, decompyle3, pycdc |
| JAR / APK / DEX | Decompiling | jadx, apktool |
| ZIP / 7z / tar / gz / rar | Archives | 7z, bsdtar, zip2john, fcrackzip |
| PNG / JPEG / GIF / BMP | Steganography | exiftool, zsteg, steghide, stegseek, stegsolve, binwalk |
| WAV / MP3 / FLAC / OGG | Audio steganography | sox spectrogram, steghide |
| PDF | Documents | pdftotext, pdfdetach, pdf2john, qpdf |
| pcap / pcapng | Network | Wireshark, tshark, tcpflow |
| Keys / certificates | Crypto | RsaCtfTool, openssl, ssh2john |
| Disk / filesystem images | Forensics | sleuthkit, testdisk, volatility3 |
| Text | Encoding / crypto | CyberChef, name-that-hash, xortool |
| Unknown data | Carving | xxd, binwalk, foremost |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/teterw/ctf-id/main/install.sh | bash
```

The installer puts `ctf-id` in `~/.local/bin`. Set `PREFIX=/usr/local` (and run it with sudo) to install it system-wide.

To install by hand:

```bash
curl -fsSLO https://raw.githubusercontent.com/teterw/ctf-id/main/ctf-id
chmod +x ctf-id && mv ctf-id ~/.local/bin/
```

You can also download it from the [latest release](https://github.com/teterw/ctf-id/releases/latest).

## Usage

```bash
ctf-id <file> [file2 ...]   # full analysis
ctf-id -q <file>            # quick: skip entropy and binwalk
ctf-id --version
```

## Requirements

- Required: `bash`, `file`, and GNU coreutils
- Optional: `python3` for entropy, `strings` from binutils for flag search, and `binwalk` for embedded files

Any optional tool that is missing is skipped without an error. `ctf-id` only recommends the other tools; you don't need them installed to run it.

## License

MIT
