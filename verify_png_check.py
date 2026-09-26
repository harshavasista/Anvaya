"""
Standalone PNG integrity checker — run this yourself, no agent needed.

Usage:
    python verify_png_check.py path/to/file.png [more/files.png ...]

With no arguments, it checks every .png file under data/demo/.

This exists to get a clean signal on whether the detection LOGIC is
correct, independent of whatever the coding agent is doing. Run it
in a normal terminal in your repo root.
"""

import sys
import glob
import json
import struct
import zlib


def check_png_integrity(file_bytes: bytes) -> dict:
    reasons = []
    checks = []

    SIG = b"\x89PNG\r\n\x1a\n"
    if file_bytes[:8] != SIG:
        return {
            "status": "SEVERELY_CORRUPTED",
            "corruption_detected": True,
            "reasons": ["invalid PNG signature"],
            "validation_checks": ["signature: FAIL"],
        }
    checks.append("signature: PASS")

    offset = 8
    idat_chunks = []
    saw_ihdr = False
    saw_iend = False

    while offset < len(file_bytes):
        if offset + 8 > len(file_bytes):
            reasons.append(f"truncated chunk header at offset {offset}")
            break

        length = struct.unpack(">I", file_bytes[offset:offset + 4])[0]
        ctype = file_bytes[offset + 4:offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4

        if crc_end > len(file_bytes):
            reasons.append(f"{ctype.decode(errors='replace')} chunk truncated")
            break

        data = file_bytes[data_start:data_end]
        stored_crc = struct.unpack(">I", file_bytes[data_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        label = ctype.decode(errors="replace")

        if stored_crc != actual_crc:
            reasons.append(f"{label} chunk CRC mismatch")
            checks.append(f"{label} CRC: FAIL")
        else:
            checks.append(f"{label} CRC: PASS")

        if ctype == b"IHDR":
            saw_ihdr = True
        elif ctype == b"IDAT":
            idat_chunks.append(data)
        elif ctype == b"IEND":
            saw_iend = True

        offset = crc_end

    if not saw_ihdr:
        reasons.append("missing IHDR chunk")
    if not saw_iend:
        reasons.append("missing IEND chunk (file is likely truncated)")
    if not idat_chunks:
        reasons.append("no IDAT chunks found")

    if idat_chunks:
        try:
            zlib.decompress(b"".join(idat_chunks))
            checks.append("IDAT zlib decompression: PASS")
        except zlib.error as e:
            reasons.append(f"IDAT stream fails to decompress: {e}")
            checks.append("IDAT zlib decompression: FAIL")

    corruption_detected = len(reasons) > 0
    if not corruption_detected:
        status = "HEALTHY"
    elif not saw_iend or any("truncated" in r for r in reasons):
        status = "SEVERELY_CORRUPTED"
    else:
        status = "CORRUPTED"

    return {
        "status": status,
        "corruption_detected": corruption_detected,
        "severity": status,
        "reasons": reasons,
        "validation_checks": checks,
    }


def main():
    paths = sys.argv[1:]
    if not paths:
        paths = sorted(glob.glob("data/demo/*.png"))
        if not paths:
            print("No path given, and no .png files found under data/demo/.")
            print("Usage: python verify_png_check.py path/to/file.png")
            return

    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"{path}: could not read ({e})")
            continue

        result = check_png_integrity(data)
        print(f"\n=== {path} ===")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()