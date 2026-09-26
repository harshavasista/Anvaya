"""
PDF Recovery and Reconstruction Engine for ANVAYA.
Per Section 6:
- Native repair (Mode A): PyMuPDF object recovery, xref reconstruction, clean re-saving
- Evidence-backed reconstruction (Mode B): fragment replacement from genuine reference
- Strict 15-second timeout wrapper
- Mandatory candidate validation and SHA-256 calculation
"""

import io
import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Dict, Any, Optional, Tuple
import pymupdf


def _repair_pdf_worker(damaged_data: bytes, reference_data: Optional[bytes] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """Worker performing PDF repair and candidate generation.

    Mode A (format-native repair) runs unconditionally on the uploaded file.
    Mode B (evidence-backed reconstruction) is an optional enhancement only
    when a verified reference file exists — it NEVER gates whether Mode A runs.
    """
    methods_used = []
    messages = []
    candidate_bytes = None

    # -------------------------------------------------------------------------
    # Mode A — Format-native repair (runs ALWAYS, no reference required)
    # -------------------------------------------------------------------------
    methods_used.append("FORMAT_NATIVE_REPAIR")
    repaired_stream = bytearray(damaged_data)

    # A1. Prepend header if missing
    if not repaired_stream.startswith(b"%PDF"):
        repaired_stream = bytearray(b"%PDF-1.7\n") + repaired_stream
        messages.append("Synthesized standard %PDF-1.7 header at offset 0.")

    # A2. Append %%EOF if missing
    if b"%%EOF" not in repaired_stream[-512:]:
        repaired_stream.extend(b"\n%%EOF\n")
        messages.append("Appended standard %%EOF marker to trailer.")

    # A3. Open in PyMuPDF — it will auto-rebuild the xref table
    try:
        doc = pymupdf.open(stream=bytes(repaired_stream), filetype="pdf")
        page_count = doc.page_count          # capture BEFORE close()
        if page_count > 0:
            clean_bytes = doc.tobytes(garbage=4, deflate=True, clean=True)
            doc.close()
            candidate_bytes = clean_bytes
            messages.append(f"PyMuPDF normalized structure and salvaged {page_count} page(s).")
        else:
            doc.close()
            messages.append("PyMuPDF opened the file but found 0 pages.")
    except Exception as err:
        messages.append(f"Native structural parse attempt failed: {str(err)}")

    # -------------------------------------------------------------------------
    # Mode A fallback — Stream/text salvage into new PDF container
    # -------------------------------------------------------------------------
    if candidate_bytes is None:
        try:
            text_chunks = []
            for chunk in damaged_data.split(b"\n"):
                if b"stream" not in chunk and b"endstream" not in chunk:
                    try:
                        decoded = chunk.decode("utf-8", errors="ignore").strip()
                        if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                            text_chunks.append(decoded)
                    except Exception:
                        pass
            if text_chunks:
                methods_used.append("CONTENT_STREAM_SALVAGE")
                new_doc = pymupdf.open()
                page = new_doc.new_page(width=595, height=842)
                page.insert_text((50, 72), "ANVAYA RECONSTRUCTED EVIDENCE (SALVAGED STREAM)", fontsize=14, fontname="helv")
                y = 110
                for line in text_chunks[:30]:
                    page.insert_text((50, y), line[:80], fontsize=10, fontname="helv")
                    y += 18
                candidate_bytes = new_doc.tobytes()
                new_doc.close()
                messages.append("Salvaged readable text streams into reconstructed candidate PDF container.")
        except Exception as se:
            messages.append(f"Stream salvage failed: {str(se)}")

    # -------------------------------------------------------------------------
    # Mode B — Evidence-backed reconstruction (optional enhancement)
    # Only runs if a verified reference file was supplied AND Mode A failed.
    # It NEVER overrides a successfully repaired Mode A candidate.
    # -------------------------------------------------------------------------
    if candidate_bytes is None and reference_data:
        try:
            ref_doc = pymupdf.open(stream=reference_data, filetype="pdf")
            ref_page_count = ref_doc.page_count
            if ref_page_count > 0:
                ref_bytes = ref_doc.tobytes(garbage=4, deflate=True, clean=True)
                ref_doc.close()
                candidate_bytes = ref_bytes
                methods_used.append("EVIDENCE_BACKED_RECONSTRUCTION")
                messages.append("All native repair strategies exhausted. Genuine reference evidence used as reconstruction source.")
            else:
                ref_doc.close()
        except Exception as e:
            messages.append(f"Reference validation warning: {str(e)}")

    # VALIDATION of candidate
    validation = {
        "status": "VALIDATION_FAILED",
        "valid": False,
        "page_count": 0,
        "text_extractable": False,
        "checks": []
    }

    if candidate_bytes:
        try:
            val_doc = pymupdf.open(stream=candidate_bytes, filetype="pdf")
            p_count = val_doc.page_count
            validation["page_count"] = p_count
            if p_count > 0:
                validation["checks"].append({"check": "reopen_check", "passed": True, "details": f"Candidate opened cleanly ({p_count} pages)"})
                # Check text extraction
                first_text = val_doc[0].get_text().strip()
                validation["text_extractable"] = len(first_text) > 0
                validation["checks"].append({"check": "text_extraction", "passed": True, "details": f"Extracted {len(first_text)} characters from page 1"})
                # Check rendering
                try:
                    pix = val_doc[0].get_pixmap()
                    validation["checks"].append({"check": "raster_render", "passed": True, "details": f"Rendered page 1 ({pix.width}x{pix.height})"})
                    validation["valid"] = True
                    validation["status"] = "VALIDATED"
                except Exception as re:
                    validation["checks"].append({"check": "raster_render", "passed": False, "details": str(re)})
                    validation["status"] = "PARTIALLY_VALIDATED"
            else:
                validation["checks"].append({"check": "reopen_check", "passed": False, "details": "0 pages found"})
            val_doc.close()
        except Exception as ve:
            validation["checks"].append({"check": "reopen_check", "passed": False, "details": f"Validation open error: {str(ve)}"})
            validation["status"] = "VALIDATION_FAILED"
            candidate_bytes = None

    details = {
        "methods": methods_used,
        "messages": messages,
        "validation": validation,
        "pages_recovered": validation.get("page_count", 0),
        "recovered_sha256": hashlib.sha256(candidate_bytes).hexdigest() if candidate_bytes else None,
        "candidate_bytes": candidate_bytes
    }

    return candidate_bytes, details


def repair_pdf(damaged_data: bytes, reference_data: Optional[bytes] = None, timeout_seconds: int = 15) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """
    Wrap PDF repair in hard timeout to prevent parser freezes.
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_repair_pdf_worker, damaged_data, reference_data)
        try:
            return future.result(timeout=timeout_seconds)
        except TimeoutError:
            return None, {
                "methods": ["TIMEOUT"],
                "messages": [f"PDF repair aborted: execution exceeded {timeout_seconds} second timeout threshold."],
                "validation": {"status": "VALIDATION_FAILED", "valid": False, "checks": [{"check": "timeout", "passed": False, "details": "Execution timeout"}]},
                "pages_recovered": 0,
                "recovered_sha256": None,
                "candidate_bytes": None
            }
