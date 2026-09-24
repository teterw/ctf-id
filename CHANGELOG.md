# Changelog

## 2.0.0 — 2026-09-24

### New
- **Text analysis.** Decodes chains of up to 3 layers (base64/32/85, hex, binary, decimal, octal, URL, Morse, rot13/rot47, atbash, reverse, Caesar) to find hidden flags. Also identifies hash types (with the `hashcat -m` mode), JWTs, RSA values (small-e, Wiener and factorable-n hints), esoteric languages, and zero-width or whitespace steganography. Cracks Caesar by scoring each shift for English. `-f PREFIX` adds custom flag formats.
- **Structure checks.** Repairs overwritten magic bytes (PNG/JPEG/WAV/ZIP/PDF/ELF), recovers the real size of a tampered PNG by brute-forcing its IHDR CRC, finds data appended after the end of a file, and detects whole-file reversal and single-byte XOR.
- **Tool markers.** Every suggested tool shows ✓ (installed) or ✗ (missing), and missing tools are listed with the install command for dnf/apt/pacman/brew. `--doctor` checks the whole toolkit.
- **`--run`** runs the quick read-only first checks for the file type and highlights any flags in their output.
- **`--deep`** extracts nested archives and embedded files into a temp folder and analyses each one, up to 3 levels deep.
- **More file types:** Office (macros), SQLite, KeePass, Mach-O, .NET, WebAssembly, Windows event logs and registry hives, email, git repositories, memory dumps.
- **macOS support** (bash 3.2 + BSD userland), tested in CI alongside Linux.
- Bash/zsh completion, and `--update` to upgrade in place.

### Fixed
- Filesystem images and keys were treated as "unknown data".
- The "binwalk sees embedded data" alarm fired on every file with binwalk v3.
- Office documents were treated as plain zips by older versions of `file`.

## 1.0.0 — 2026-09-24
- First public release.
