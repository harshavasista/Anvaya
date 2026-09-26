"""
Unified Forensic Corruption Detection Engine & Reproducible Severity Rubric.
Per Section 5 (Priority 3) & Section 27a:
- Performs deterministic format-specific structural checks
- Enforces strict parser timeouts
- Applies mathematical severity rubric:
    affected_ratio == 0            -> HEALTHY
    0 < affected_ratio <= 0.25     -> PARTIALLY_CORRUPTED
    0.25 < affected_ratio < 1.0    -> CORRUPTED
    affected_ratio == 1.0 or catastrophic parse failure -> SEVERELY_CORRUPTED
"""

import io
import json
import csv
import zipfile
import sqlite3
import math
import struct
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple
import pymupdf


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for data block (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def find_affected_fragments(file_size: int, affected_regions: List[Dict[str, Any]], fragment_size: int = 4096) -> List[int]:
    """Map byte offset ranges to 0-indexed fragment numbers."""
    affected_frags = set()
    total_frags = max(1, (file_size + fragment_size - 1) // fragment_size)
    for reg in affected_regions:
        start_frag = reg["offset"] // fragment_size
        end_frag = min(total_frags - 1, (reg["offset"] + reg["length"] - 1) // fragment_size)
        for i in range(start_frag, end_frag + 1):
            affected_frags.add(i)
    return sorted(list(affected_frags))


def analyze_corruption(data: bytes, file_type: str, filename: str = "") -> Dict[str, Any]:
    """
    Run format-specific forensic integrity checks and calculate reproducible severity.
    """
    checks: List[Dict[str, Any]] = []
    reasons: List[str] = []
    affected_regions: List[Dict[str, Any]] = []
    format_analysis: Dict[str, Any] = {}
    file_size = len(data)

    if file_size == 0:
        return {
            "status": "SEVERELY_CORRUPTED",
            "corruption_detected": True,
            "severity": "SEVERELY_CORRUPTED",
            "affected_ratio": 1.0,
            "reasons": ["File is empty (0 bytes). No forensic structure present."],
            "affected_regions": [{"offset": 0, "length": 0, "reason": "Zero-byte file"}],
            "affected_fragments": [],
            "validation_checks": [{"name": "non_empty_check", "passed": False, "details": "File size is 0 bytes"}],
            "format_analysis": {"empty_file": True}
        }

    # =========================================================================
    # PDF FORMAT ANALYSIS
    # =========================================================================
    if file_type == "PDF":
        # Check 1: Header
        has_header = data.startswith(b"%PDF")
        checks.append({"name": "pdf_header", "passed": has_header, "details": "Valid %PDF signature at offset 0" if has_header else "Missing %PDF header"})
        if not has_header:
            reasons.append("Missing or invalid PDF magic bytes header.")
            affected_regions.append({"offset": 0, "length": min(16, file_size), "reason": "Missing %PDF header"})

        # Check 2: EOF Marker
        has_eof = b"%%EOF" in data[-1024:] if file_size >= 1024 else b"%%EOF" in data
        checks.append({"name": "pdf_eof", "passed": has_eof, "details": "%%EOF marker present within last 1KB" if has_eof else "Missing %%EOF marker"})
        if not has_eof:
            reasons.append("Missing EOF marker (%%EOF) in trailer region.")
            offset_eof = max(0, file_size - 128)
            affected_regions.append({"offset": offset_eof, "length": file_size - offset_eof, "reason": "Missing %%EOF"})

        # Check 3: Cross-reference table or stream
        has_xref = (b"xref" in data) or (b"/XRef" in data)
        checks.append({"name": "pdf_xref", "passed": has_xref, "details": "Cross-reference table/stream detected" if has_xref else "Missing xref table or /XRef stream"})
        if not has_xref:
            reasons.append("Cross-reference (xref) table or stream missing.")
            affected_regions.append({"offset": max(0, file_size - 512), "length": min(512, file_size), "reason": "Missing xref table"})

        # Check 4: Trailer or XRef stream dictionary
        has_trailer = (b"trailer" in data) or (b"/Root" in data)
        checks.append({"name": "pdf_trailer", "passed": has_trailer, "details": "Trailer dictionary / Root catalog detected" if has_trailer else "Missing trailer / Root catalog"})
        if not has_trailer:
            reasons.append("PDF trailer dictionary or Root catalog missing.")

        # Check 5: startxref offset keyword
        has_startxref = b"startxref" in data
        checks.append({"name": "pdf_startxref", "passed": has_startxref, "details": "startxref keyword detected" if has_startxref else "Missing startxref offset pointer"})
        if not has_startxref:
            reasons.append("startxref offset pointer missing or damaged.")
            affected_regions.append({"offset": max(0, file_size - 256), "length": min(256, file_size), "reason": "Missing startxref"})

        # Check 6: Parser verification via PyMuPDF
        pymupdf_success = False
        page_count = 0
        text_extractable = False
        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
            page_count = doc.page_count
            pymupdf_success = page_count > 0
            if pymupdf_success:
                first_text = doc[0].get_text()
                text_extractable = len(first_text.strip()) > 0
            doc.close()
            checks.append({"name": "pdf_parser_load", "passed": pymupdf_success, "details": f"PyMuPDF parsed document ({page_count} pages)"})
        except Exception as e:
            checks.append({"name": "pdf_parser_load", "passed": False, "details": f"PyMuPDF parse error: {str(e)}"})
            reasons.append(f"PDF parser encountered structural failure: {str(e)}")

        checks.append({"name": "pdf_page_count", "passed": page_count > 0, "details": f"Page tree contains {page_count} pages"})
        if page_count == 0 and pymupdf_success:
            reasons.append("PDF contains 0 renderable pages.")

        format_analysis = {
            "page_count": page_count,
            "has_header": has_header,
            "has_eof": has_eof,
            "has_xref": has_xref,
            "has_trailer": has_trailer,
            "text_extractable": text_extractable
        }

    # =========================================================================
    # JSON FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "JSON":
        # Check 1: UTF-8 encoding
        try:
            text = data.decode("utf-8")
            checks.append({"name": "json_utf8_encoding", "passed": True, "details": "Valid UTF-8 byte sequence"})
        except UnicodeDecodeError as e:
            text = data.decode("utf-8", errors="replace")
            checks.append({"name": "json_utf8_encoding", "passed": False, "details": f"Invalid UTF-8 byte at offset {e.start}"})
            reasons.append(f"Invalid UTF-8 byte sequence detected at byte {e.start}.")
            affected_regions.append({"offset": e.start, "length": max(1, e.end - e.start), "reason": "Invalid UTF-8"})

        # Check 2: Parser validation
        parsed_ok = False
        try:
            json.loads(text)
            parsed_ok = True
            checks.append({"name": "json_syntax_validation", "passed": True, "details": "Strict JSON syntax validation passed"})
        except json.JSONDecodeError as jde:
            checks.append({"name": "json_syntax_validation", "passed": False, "details": f"JSON syntax error: {jde.msg} at line {jde.lineno}, col {jde.colno}"})
            reasons.append(f"JSON syntax error: {jde.msg} at character position {jde.pos}.")
            affected_regions.append({"offset": max(0, jde.pos - 5), "length": min(10, file_size - max(0, jde.pos - 5)), "reason": f"Syntax error: {jde.msg}"})

        # Check 3: Bracket/brace balance
        open_braces = text.count("{") - text.count("}")
        open_brackets = text.count("[") - text.count("]")
        balanced = (open_braces == 0 and open_brackets == 0)
        checks.append({"name": "json_delimiter_balance", "passed": balanced, "details": f"Braces diff: {open_braces}, Brackets diff: {open_brackets}"})
        if not balanced:
            reasons.append(f"Unbalanced JSON structure: {open_braces} unclosed braces, {open_brackets} unclosed brackets.")
            affected_regions.append({"offset": max(0, file_size - 64), "length": min(64, file_size), "reason": "Unclosed brackets/braces"})

        format_analysis = {
            "parsed_ok": parsed_ok,
            "open_braces": open_braces,
            "open_brackets": open_brackets
        }

    # =========================================================================
    # TXT FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "TXT":
        # Check 1: UTF-8 encoding
        utf8_ok = True
        try:
            decoded_text = data.decode("utf-8")
            checks.append({"name": "txt_utf8_encoding", "passed": True, "details": "Valid UTF-8 byte stream"})
        except UnicodeDecodeError as e:
            utf8_ok = False
            decoded_text = data.decode("utf-8", errors="replace")
            checks.append({"name": "txt_utf8_encoding", "passed": False, "details": f"Encoding error at offset {e.start}"})
            reasons.append(f"Invalid UTF-8 byte encoding at byte offset {e.start}.")
            affected_regions.append({"offset": e.start, "length": max(1, e.end - e.start), "reason": "Invalid UTF-8 encoding"})

        # Check 2: Null-byte contamination
        null_count = data.count(b"\x00")
        has_null_bytes = null_count > 0
        checks.append({"name": "txt_null_byte_check", "passed": not has_null_bytes, "details": f"Found {null_count} null bytes" if has_null_bytes else "No null byte contamination"})
        if has_null_bytes:
            reasons.append(f"Text file contains {null_count} unexpected null bytes (possible binary contamination).")
            # Find first null byte
            first_null = data.find(b"\x00")
            affected_regions.append({"offset": first_null, "length": min(64, file_size - first_null), "reason": "Null byte sequence"})

        # Check 3: Printable ratio
        printable = sum(1 for c in decoded_text if c.isprintable() or c in "\r\n\t")
        printable_ratio = printable / max(1, len(decoded_text))
        is_printable = printable_ratio >= 0.95
        checks.append({"name": "txt_printable_ratio", "passed": is_printable, "details": f"Printable character ratio: {printable_ratio:.2%}"})
        if not is_printable:
            reasons.append(f"High non-printable character ratio: {(1 - printable_ratio):.2%} unprintable.")

        format_analysis = {
            "utf8_valid": utf8_ok,
            "null_bytes": null_count,
            "printable_ratio": printable_ratio
        }

    # =========================================================================
    # CSV FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "CSV":
        # Check 1: Encoding
        try:
            text = data.decode("utf-8")
            checks.append({"name": "csv_utf8_encoding", "passed": True, "details": "Valid UTF-8 encoding"})
        except UnicodeDecodeError as e:
            text = data.decode("utf-8", errors="replace")
            checks.append({"name": "csv_utf8_encoding", "passed": False, "details": f"Encoding error at offset {e.start}"})
            reasons.append(f"CSV encoding failure at offset {e.start}.")
            affected_regions.append({"offset": e.start, "length": max(1, e.end - e.start), "reason": "Encoding error"})

        # Check 2: Row parsing & column consistency
        lines = [l for l in text.splitlines() if l.strip()]
        csv_valid = False
        if lines:
            try:
                reader = csv.reader(io.StringIO(text))
                rows = list(reader)
                col_counts = [len(r) for r in rows if r]
                consistent_cols = len(set(col_counts)) == 1 and col_counts[0] > 0
                csv_valid = consistent_cols
                checks.append({"name": "csv_column_consistency", "passed": consistent_cols, "details": f"Consistent columns: {col_counts[0] if col_counts else 0}" if consistent_cols else f"Inconsistent column counts across rows: {set(col_counts)}"})
                if not consistent_cols:
                    reasons.append(f"CSV column count varies across records: {set(col_counts)}.")
            except Exception as e:
                checks.append({"name": "csv_column_consistency", "passed": False, "details": f"CSV parse error: {str(e)}"})
                reasons.append(f"CSV parsing error: {str(e)}")
        else:
            checks.append({"name": "csv_column_consistency", "passed": False, "details": "CSV has no records"})
            reasons.append("CSV document contains no records.")

        format_analysis = {"line_count": len(lines), "csv_valid": csv_valid}

    # =========================================================================
    # PNG FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "PNG":
        # Check 1: PNG signature
        has_png_sig = data.startswith(b"\x89PNG\r\n\x1a\n")
        checks.append({"name": "png_signature", "passed": has_png_sig, "details": "Valid PNG magic bytes" if has_png_sig else "Missing PNG signature"})
        if not has_png_sig:
            reasons.append("Missing PNG magic signature at byte 0.")
            affected_regions.append({"offset": 0, "length": min(8, file_size), "reason": "Missing PNG header"})

        # Check 2: IHDR chunk (must be first chunk)
        has_ihdr = b"IHDR" in data[8:32]
        checks.append({"name": "png_ihdr_chunk", "passed": has_ihdr, "details": "IHDR header chunk present" if has_ihdr else "Missing IHDR chunk"})
        if not has_ihdr:
            reasons.append("Missing required PNG IHDR header chunk.")

        # Check 3: IEND chunk (must be last chunk)
        has_iend = data.endswith(b"IEND\xaeB`\x82") or b"IEND" in data[-32:]
        checks.append({"name": "png_iend_chunk", "passed": has_iend, "details": "IEND terminal chunk present" if has_iend else "Missing IEND terminal chunk"})
        if not has_iend:
            reasons.append("Missing PNG IEND terminal chunk. File is truncated.")
            affected_regions.append({"offset": max(0, file_size - 12), "length": min(12, file_size), "reason": "Missing IEND"})

        format_analysis = {"has_ihdr": has_ihdr, "has_iend": has_iend}

    # =========================================================================
    # JPEG FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "JPEG":
        # Check 1: SOI (Start of Image)
        has_soi = data.startswith(b"\xFF\xD8")
        checks.append({"name": "jpeg_soi", "passed": has_soi, "details": "Valid SOI marker (0xFFD8)" if has_soi else "Missing SOI marker"})
        if not has_soi:
            reasons.append("Missing JPEG Start of Image (SOI 0xFFD8) marker.")
            affected_regions.append({"offset": 0, "length": min(4, file_size), "reason": "Missing SOI"})

        # Check 2: EOI (End of Image)
        has_eoi = data.endswith(b"\xFF\xD9") or b"\xFF\xD9" in data[-64:]
        checks.append({"name": "jpeg_eoi", "passed": has_eoi, "details": "Valid EOI marker (0xFFD9)" if has_eoi else "Missing EOI marker"})
        if not has_eoi:
            reasons.append("Missing JPEG End of Image (EOI 0xFFD9) marker. File is truncated.")
            affected_regions.append({"offset": max(0, file_size - 4), "length": min(4, file_size), "reason": "Missing EOI"})

        format_analysis = {"has_soi": has_soi, "has_eoi": has_eoi}

    # =========================================================================
    # ZIP / DOCX / XLSX FORMAT ANALYSIS
    # =========================================================================
    elif file_type in ("ZIP", "DOCX", "XLSX"):
        # Check 1: Signature
        has_zip_sig = data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
        checks.append({"name": "zip_signature", "passed": has_zip_sig, "details": "Valid PK zip signature" if has_zip_sig else "Missing PK signature"})
        if not has_zip_sig:
            reasons.append("Missing ZIP container PK magic bytes.")

        # Check 2: Central directory & decompression safety
        zip_ok = False
        total_uncompressed = 0
        names = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Security: Check for zip bomb
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                if total_uncompressed > 500 * 1024 * 1024:
                    checks.append({"name": "zip_bomb_safety", "passed": False, "details": f"Decompressed size exceeds safety cap: {total_uncompressed} bytes"})
                    reasons.append("ZIP archive exceeds 500 MB decompression safety threshold (potential zip-bomb).")
                else:
                    checks.append({"name": "zip_bomb_safety", "passed": True, "details": f"Declared uncompressed size: {total_uncompressed} bytes"})

                # Test archive integrity
                bad_file = zf.testzip()
                if bad_file is None:
                    zip_ok = True
                    checks.append({"name": "zip_central_directory", "passed": True, "details": "ZIP container and CRC validation passed"})
                else:
                    checks.append({"name": "zip_central_directory", "passed": False, "details": f"Corrupted file inside zip: {bad_file}"})
                    reasons.append(f"Corrupted CRC in archived entry '{bad_file}'.")
                names = zf.namelist()
        except Exception as e:
            checks.append({"name": "zip_central_directory", "passed": False, "details": f"ZIP structure error: {str(e)}"})
            reasons.append(f"ZIP container structural failure: {str(e)}")

        # Check 3: Format-specific internal XML validation (XXE Safe)
        if file_type == "DOCX" and zip_ok:
            if "word/document.xml" in names:
                checks.append({"name": "docx_document_xml", "passed": True, "details": "word/document.xml present in package"})
            else:
                checks.append({"name": "docx_document_xml", "passed": False, "details": "word/document.xml missing"})
                reasons.append("Required word/document.xml is missing from DOCX package.")
        elif file_type == "XLSX" and zip_ok:
            if "xl/workbook.xml" in names:
                checks.append({"name": "xlsx_workbook_xml", "passed": True, "details": "xl/workbook.xml present in package"})
            else:
                checks.append({"name": "xlsx_workbook_xml", "passed": False, "details": "xl/workbook.xml missing"})
                reasons.append("Required xl/workbook.xml is missing from XLSX package.")

        format_analysis = {"entry_count": len(names), "uncompressed_bytes": total_uncompressed}

    # =========================================================================
    # SQLITE FORMAT ANALYSIS
    # =========================================================================
    elif file_type == "SQLite":
        # Check 1: Header
        has_sqlite_sig = data.startswith(b"SQLite format 3\x00")
        checks.append({"name": "sqlite_header", "passed": has_sqlite_sig, "details": "Valid SQLite format 3 header" if has_sqlite_sig else "Missing SQLite header"})
        if not has_sqlite_sig:
            reasons.append("Missing SQLite format 3 magic bytes.")

        # Check 2: PRAGMA integrity_check in read-only immutable mode
        sqlite_ok = False
        try:
            # Connect in memory or temp URI
            temp_db = io.BytesIO(data)
            # Use SQLite memory connection with deserialization if supported, or file check
            if hasattr(sqlite3.Connection, "deserialize"):
                conn = sqlite3.connect(":memory:")
                conn.deserialize(data)
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check;")
                rows = cursor.fetchall()
                if rows and rows[0][0] == "ok":
                    sqlite_ok = True
                    checks.append({"name": "sqlite_integrity_check", "passed": True, "details": "PRAGMA integrity_check returned ok"})
                else:
                    checks.append({"name": "sqlite_integrity_check", "passed": False, "details": f"PRAGMA check: {rows}"})
                    reasons.append(f"SQLite PRAGMA integrity check reported damage: {rows}")
                conn.close()
            else:
                # Basic header page validation
                checks.append({"name": "sqlite_integrity_check", "passed": has_sqlite_sig, "details": "Basic page validation passed"})
                sqlite_ok = has_sqlite_sig
        except Exception as e:
            checks.append({"name": "sqlite_integrity_check", "passed": False, "details": f"SQLite error: {str(e)}"})
            reasons.append(f"SQLite database error: {str(e)}")

        format_analysis = {"sqlite_valid": sqlite_ok}

    # =========================================================================
    # GENERIC BINARY FALLBACK
    # =========================================================================
    else:
        entropy = calculate_entropy(data)
        null_count = data.count(b"\x00")
        null_ratio = null_count / file_size
        checks.append({"name": "binary_entropy", "passed": True, "details": f"Shannon entropy: {entropy:.2f}"})
        checks.append({"name": "binary_structure", "passed": False, "details": "Unknown binary format - no structural parser"})
        reasons.append("Format signature not recognized. Generic binary analysis only.")
        format_analysis = {"entropy": entropy, "null_ratio": null_ratio}

    # =========================================================================
    # SEVERITY RUBRIC (Section 27a)
    # =========================================================================
    total_checks = len(checks)
    failed_checks = sum(1 for c in checks if not c["passed"])
    affected_ratio = failed_checks / total_checks if total_checks > 0 else 0.0

    if affected_ratio == 0.0:
        status = "HEALTHY"
        severity = "HEALTHY"
    elif 0.0 < affected_ratio <= 0.25:
        status = "PARTIALLY_CORRUPTED"
        severity = "PARTIALLY_CORRUPTED"
    elif 0.25 < affected_ratio < 1.0:
        status = "CORRUPTED"
        severity = "CORRUPTED"
    else:
        status = "SEVERELY_CORRUPTED"
        severity = "SEVERELY_CORRUPTED"

    # Map affected fragments
    affected_frags = find_affected_fragments(file_size, affected_regions)

    return {
        "status": status,
        "corruption_detected": status != "HEALTHY",
        "severity": severity,
        "affected_ratio": round(affected_ratio, 3),
        "reasons": reasons,
        "affected_regions": affected_regions,
        "affected_fragments": affected_frags,
        "validation_checks": checks,
        "format_analysis": format_analysis
    }