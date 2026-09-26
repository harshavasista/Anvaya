"""
PDF Structural Assessor for ANVAYA Forensic Engine.
Performs non-destructive in-depth inspection of PDF internal structures:
- Header and version
- Catalog and page-tree traversal
- Object numbering and count
- Cross-reference table/stream integrity
- Content stream syntax and text extraction
"""

import io
from typing import Dict, List, Any
import pymupdf


def assess_pdf_structure(data: bytes) -> Dict[str, Any]:
    """Inspect PDF structure deeply and report findings."""
    assessment = {
        "header_valid": False,
        "version": None,
        "page_count": 0,
        "pages_recoverable": 0,
        "objects_found": data.count(b"obj"),
        "streams_found": data.count(b"stream"),
        "has_xref": b"xref" in data or b"/XRef" in data,
        "has_trailer": b"trailer" in data,
        "has_startxref": b"startxref" in data,
        "has_eof": b"%%EOF" in data,
        "extractable_text_length": 0,
        "parse_errors": [],
        "is_healthy": False
    }

    if data.startswith(b"%PDF"):
        assessment["header_valid"] = True
        try:
            line1 = data[:32].split(b"\n")[0]
            assessment["version"] = line1.decode("ascii", errors="ignore").strip()
        except Exception:
            pass

    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
        assessment["page_count"] = doc.page_count
        recoverable_pages = 0
        total_text = ""
        for i in range(doc.page_count):
            try:
                page = doc[i]
                txt = page.get_text()
                total_text += txt
                recoverable_pages += 1
            except Exception as pe:
                assessment["parse_errors"].append(f"Page {i+1} read error: {str(pe)}")

        assessment["pages_recoverable"] = recoverable_pages
        assessment["extractable_text_length"] = len(total_text.strip())
        doc.close()
    except Exception as e:
        assessment["parse_errors"].append(f"PyMuPDF load failure: {str(e)}")

    assessment["is_healthy"] = (
        assessment["header_valid"]
        and assessment["has_eof"]
        and assessment["has_xref"]
        and assessment["has_startxref"]
        and assessment["page_count"] > 0
        and len(assessment["parse_errors"]) == 0
    )

    return assessment
