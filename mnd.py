import argparse
import json
import pathlib
import sys
from typing import Dict, Tuple

# Built‑in magic number definitions: mapping bytes -> description
BUILTIN_MAGIC: Dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xFF\xD8\xFF": "JPEG image",
    b"GIF87a": "GIF image (GIF87a)",
    b"GIF89a": "GIF image (GIF89a)",
    b"%PDF-": "PDF document",
    b"\x1F\x8B\x08": "GZIP compressed archive",
    b"PK\x03\x04": "ZIP / JAR / DOCX / XLSX / ODT archive",
    b"PK\x05\x06": "ZIP archive (empty)",
    b"PK\x07\x08": "ZIP archive (spanned)",
    b"\x7FELF": "ELF executable",
    b"MZ": "Windows PE executable (MZ)",
    b"BM": "BMP image",
    b"OggS": "Ogg container",
    b"\x25\x21": "PostScript / EPS",
    b"7z\xBC\xAF\x27\x1C": "7‑Zip archive",
    b"Rar!\x1A\x07\x00": "RAR archive (v1.5)",
    b"Rar!\x1A\x07\x01\x00": "RAR archive (v5)",
    b"CWS": "Shockwave Flash (SWF; compressed)",
    b"FWS": "Shockwave Flash (SWF)",
    b"ZWS": "Shockwave Flash (SWF; LZMA)",
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "Microsoft Compound File (OLE; old DOC/XLS/PPT)",
}


def parse_custom_magic(values: Tuple[str, ...]) -> Dict[bytes, str]:
    """Parse --add HEX:NAME arguments into a dictionary."""
    custom = {}
    for v in values:
        try:
            hex_part, name = v.split(":", 1)
            custom[bytes.fromhex(hex_part)] = name
        except ValueError:
            sys.exit(f"Invalid --add argument '{v}'. Expected HEX:NAME.")
    return custom


def detect_magic(buffer: bytes, magic_db: Dict[bytes, str]) -> str:
    """Return the description for the first matching magic number."""
    for sig, desc in sorted(magic_db.items(), key=lambda x: len(x[0]), reverse=True):
        if buffer.startswith(sig):
            return desc
    return "Unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Identify files by magic number.")
    parser.add_argument("files", nargs="*", help="Files to analyze")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-l", "--list", action="store_true", help="List all known magic numbers")
    parser.add_argument("--add", dest="add", action="append", default=[],
                        metavar="HEX:NAME",
                        help="Add custom magic in the form HEX:NAME (can repeat)")

    args = parser.parse_args()

    # Combine built‑in and user‑supplied magic definitions
    magic_db = BUILTIN_MAGIC.copy()
    magic_db.update(parse_custom_magic(tuple(args.add)))

    # --list option
    if args.list:
        for sig, desc in magic_db.items():
            print(f"{sig.hex().upper()} → {desc}")
        return

    if not args.files:
        parser.error("At least one file path must be provided.")

    # Evaluate each file
    results = {}
    for path_str in args.files:
        path = pathlib.Path(path_str)
        try:
            with path.open("rb") as fh:
                head = fh.read(16)  # longest signature in table is <16 bytes
            results[str(path)] = detect_magic(head, magic_db)
        except FileNotFoundError:
            results[str(path)] = "File not found"
        except PermissionError:
            results[str(path)] = "Permission denied"

    # Output
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for file, res in results.items():
            print(f"{file}: {res}")


if __name__ == "__main__":
    main()
