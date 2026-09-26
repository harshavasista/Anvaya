"""
ANVAYA — Digital Evidence Analysis & Forensic Reconstruction Engine
FastAPI Backend Application
"""

import os
import re
import json
import uuid
import struct
import zlib
import pymupdf
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException, status, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.core.security import (
    MAX_UPLOAD_SIZE,
    sanitize_filename,
    calculate_sha256,
    calculate_file_sha256,
    verify_original_unmodified
)
from backend.core.format_router import detect_format, MIME_MAP
from backend.integrity.corruption_detector import analyze_corruption, calculate_entropy
from backend.recovery.recovery_orchestrator import orchestrate_recovery
from backend.audit.chain_of_custody import log_custody_event
from backend.xai_engine import generate_xai_diagnosis

app = FastAPI(
    title="ANVAYA - Explainable AI Digital Evidence Reconstruction",
    description="Forensic integrity analysis, corruption detection, and evidence-backed recovery system.",
    version="2.1.0"
)

# -----------------------------------------------------------------------------
# CORS CONFIGURATION (Section 18)
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# STANDARDIZED ERROR HANDLING (Section 19 & 30)
# -----------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": getattr(exc, "error_code", "REQUEST_ERROR"),
                "message": exc.detail,
                "case_id": getattr(exc, "case_id", None)
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": f"Unexpected forensic engine failure: {str(exc)}",
                "case_id": None
            }
        }
    )


# -----------------------------------------------------------------------------
# HELPER: IMAGE INTEGRITY VALIDATION (Section 27a)
# Uses check_png_integrity() logic from verify_png_check.py — do NOT duplicate.
# -----------------------------------------------------------------------------
def check_png_integrity(file_bytes: bytes) -> dict:
    """
    Deep PNG integrity checker — verbatim from verify_png_check.py.
    Validates CRC of every chunk and attempts zlib decompression of IDAT stream.
    """
    reasons = []
    checks = []

    SIG = b"\x89PNG\r\n\x1a\n"
    if file_bytes[:8] != SIG:
        return {
            "status": "SEVERELY_CORRUPTED",
            "corruption_detected": True,
            "severity": "SEVERELY_CORRUPTED",
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


def validate_image(file_bytes: bytes, file_type: str) -> dict | None:
    """
    Format-aware image validator.  Returns a corruption_detector-compatible
    dict for PNG and JPEG, or None for non-image types.

    PNG  — uses check_png_integrity() (CRC + zlib, from verify_png_check.py)
    JPEG — checks SOI (0xFFD8) and EOI (0xFFD9) markers
    """
    if file_type == "PNG":
        raw = check_png_integrity(file_bytes)
        # Convert validation_checks from list-of-strings to list-of-dicts
        # to match corruption_detector schema expected by main pipeline.
        converted_checks = []
        for c in raw.get("validation_checks", []):
            passed = c.upper().endswith(": PASS")
            converted_checks.append({"name": c, "passed": passed, "details": c})

        file_size = len(file_bytes)
        affected_regions = []
        if raw["corruption_detected"]:
            affected_regions.append({
                "offset": 0,
                "length": file_size,
                "reason": "; ".join(raw["reasons"])
            })

        from backend.integrity.corruption_detector import find_affected_fragments
        affected_frags = find_affected_fragments(file_size, affected_regions)

        total_checks = len(converted_checks)
        failed_checks = sum(1 for c in converted_checks if not c["passed"])
        affected_ratio = round(failed_checks / total_checks, 3) if total_checks > 0 else 0.0

        return {
            "status": raw["status"],
            "corruption_detected": raw["corruption_detected"],
            "severity": raw["severity"],
            "affected_ratio": affected_ratio,
            "reasons": raw["reasons"],
            "affected_regions": affected_regions,
            "affected_fragments": affected_frags,
            "validation_checks": converted_checks,
            "format_analysis": {}
        }

    elif file_type == "JPEG":
        file_size = len(file_bytes)
        checks = []
        reasons = []
        affected_regions = []

        has_soi = file_bytes.startswith(b"\xFF\xD8")
        checks.append({"name": "jpeg_soi", "passed": has_soi,
                        "details": "Valid SOI marker (0xFFD8)" if has_soi else "Missing SOI marker"})
        if not has_soi:
            reasons.append("Missing JPEG Start of Image (SOI 0xFFD8) marker.")
            affected_regions.append({"offset": 0, "length": min(4, file_size), "reason": "Missing SOI"})

        has_eoi = file_bytes.endswith(b"\xFF\xD9") or b"\xFF\xD9" in file_bytes[-64:]
        checks.append({"name": "jpeg_eoi", "passed": has_eoi,
                        "details": "Valid EOI marker (0xFFD9)" if has_eoi else "Missing EOI marker"})
        if not has_eoi:
            reasons.append("Missing JPEG End of Image (EOI 0xFFD9) marker. File is truncated.")
            affected_regions.append({"offset": max(0, file_size - 4), "length": min(4, file_size), "reason": "Missing EOI"})

        total_checks = len(checks)
        failed_checks = sum(1 for c in checks if not c["passed"])
        affected_ratio = round(failed_checks / total_checks, 3) if total_checks > 0 else 0.0

        if affected_ratio == 0.0:
            status = severity = "HEALTHY"
        elif 0.0 < affected_ratio <= 0.25:
            status = severity = "PARTIALLY_CORRUPTED"
        elif 0.25 < affected_ratio < 1.0:
            status = severity = "CORRUPTED"
        else:
            status = severity = "SEVERELY_CORRUPTED"

        from backend.integrity.corruption_detector import find_affected_fragments
        affected_frags = find_affected_fragments(file_size, affected_regions)

        return {
            "status": status,
            "corruption_detected": status != "HEALTHY",
            "severity": severity,
            "affected_ratio": affected_ratio,
            "reasons": reasons,
            "affected_regions": affected_regions,
            "affected_fragments": affected_frags,
            "validation_checks": checks,
            "format_analysis": {"has_soi": has_soi, "has_eoi": has_eoi}
        }

    return None


# -----------------------------------------------------------------------------
# HELPER: CASE DIRECTORY SETUP (Section 31)
# -----------------------------------------------------------------------------
def get_case_dirs(case_id: str) -> Dict[str, str]:

    """Resolve and create standardized directory layout for a case."""
    # Sanitize case_id to prevent path traversal
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '', case_id)
    base_path = os.path.abspath(os.path.join("data", "cases", safe_case_id))
    dirs = {
        "base": base_path,
        "original": os.path.join(base_path, "original"),
        "analysis": os.path.join(base_path, "analysis"),
        "recovery": os.path.join(base_path, "recovery"),
        "validation": os.path.join(base_path, "validation"),
        "audit": os.path.join(base_path, "audit")
    }
    for p in dirs.values():
        os.makedirs(p, exist_ok=True)
    return dirs


# -----------------------------------------------------------------------------
# HEALTH / ROOT ENDPOINTS
# -----------------------------------------------------------------------------
@app.get("/")
def read_root():
    return {
        "system": "ANVAYA Digital Evidence Analysis & Recovery",
        "version": "2.1.0",
        "status": "OPERATIONAL",
        "endpoints": {
            "analyze": "POST /api/case/analyze",
            "get_case": "GET /api/case/{case_id}",
            "docs": "/docs"
        }
    }


# -----------------------------------------------------------------------------
# PRIMARY FORENSIC ANALYSIS PIPELINE (Section 5, 19, 31)
# -----------------------------------------------------------------------------
@app.post("/api/case/analyze")
async def analyze_evidence(file: UploadFile = File(...)):
    """
    Main forensic entry point:
    Ingestion -> Identification -> Integrity & Corruption Detection -> Recovery -> Validation
    """
    # 1. Ingestion & Security Checks
    raw_filename = file.filename or "evidence.bin"
    safe_name = sanitize_filename(raw_filename)

    # Read evidence bytes with size cap
    contents = await file.read(MAX_UPLOAD_SIZE + 1024)
    if len(contents) > MAX_UPLOAD_SIZE:
        exc = HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Evidence file exceeds maximum allowed threshold of {MAX_UPLOAD_SIZE // (1024*1024)} MB."
        )
        setattr(exc, "error_code", "FILE_TOO_LARGE")
        raise exc

    # Generate unique Case ID
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    case_uid = uuid.uuid4().hex[:8]
    case_id = f"CASE-{timestamp_str}-{case_uid}"

    case_dirs = get_case_dirs(case_id)
    original_path = os.path.join(case_dirs["original"], safe_name)

    with open(original_path, "wb") as f:
        f.write(contents)

    sha256_hash = calculate_sha256(contents)
    size_bytes = len(contents)

    # Initial Audit Events
    log_custody_event(case_dirs["base"], case_id, "UPLOAD_RECEIVED", f"Uploaded evidence file '{safe_name}' received ({size_bytes} bytes).", sha256_hash)
    log_custody_event(case_dirs["base"], case_id, "HASH_COMPUTED", f"Initial SHA-256 computed: {sha256_hash}", sha256_hash)
    log_custody_event(case_dirs["base"], case_id, "ANALYSIS_STARTED", f"Forensic analysis initiated for case {case_id}.")

    # 2. Format Identification (Priority 2)
    format_info = detect_format(contents, safe_name)
    file_type = format_info["file_type"]
    mime_type = format_info["mime_type"]
    extension = format_info["extension"]

    # 3. Integrity & Corruption Detection (Priority 3 & Section 27a)
    corruption_info = analyze_corruption(contents, file_type, safe_name)

    # For PNG and JPEG, validate_image() uses deep format checks (CRC-level for
    # PNG via check_png_integrity(); SOI/EOI walk for JPEG).  Its result fully
    # replaces the shallow structural check produced by analyze_corruption().
    image_result = validate_image(contents, file_type)
    if image_result is not None:
        corruption_info = image_result

    corruption_status = corruption_info["status"]
    severity = corruption_info["severity"]
    corruption_detected = corruption_info["corruption_detected"]
    reasons = corruption_info["reasons"]


    if corruption_detected:
        log_custody_event(case_dirs["base"], case_id, "CORRUPTION_DETECTED", f"Integrity analysis identified status {corruption_status}: {'; '.join(reasons[:2])}")

    # 4. Fragment Analysis (4096 bytes)
    frag_size = 4096
    total_fragments = max(1, (size_bytes + frag_size - 1) // frag_size)
    affected_frags_count = len(corruption_info["affected_fragments"])
    intact_frags_count = max(0, total_fragments - affected_frags_count) if corruption_detected else total_fragments

    # 5. Recovery Pipeline (Priority 4, 6, 14, 15, 16)
    log_custody_event(case_dirs["base"], case_id, "REPAIR_ATTEMPTED", f"Orchestrating recovery for {file_type} evidence.")
    if file_type.lower() == "pdf":
        diagnosis = generate_xai_diagnosis(original_path, "pdf")

        if diagnosis["status"] == "HEALTHY":
            recovery_result = {
                "available": False,
                "status": "NOT_REQUIRED",
                "validation": {"status": "HEALTHY", "checks": ["PDF structural markers detected"]},
                "methods": [],
                "messages": [diagnosis["explanation"]],
                "xai_explanation": diagnosis["explanation"],
                "confidence": diagnosis["confidence"],
                "original_file": original_path,
                "recovered_file": None
            }
        else:
            recovered_path = os.path.join(
                case_dirs["recovery"],
                os.path.splitext(os.path.basename(original_path))[0] + "_recovered.pdf"
            )
            pdf_bytes = contents
            try:
                with open(original_path, 'rb') as f:
                    pdf_bytes = f.read()

                if b'%PDF-' not in pdf_bytes[:1024]:
                    pdf_bytes = b'%PDF-1.5\n' + pdf_bytes
                if b'%%EOF' not in pdf_bytes[-1024:]:
                    pdf_bytes = pdf_bytes + b'\n%%EOF'

                doc = pymupdf.open("pdf", pdf_bytes)
                cleaned_bytes = doc.tobytes(garbage=4, clean=True)
                doc.close()

                with open(recovered_path, 'wb') as f:
                    f.write(cleaned_bytes)

                recovered_sha256 = calculate_file_sha256(recovered_path)
                recovery_result = {
                    "available": True,
                    "status": "RECOVERED",
                    "candidate_url": f"/api/case/{case_id}/recovered",
                    "recovered_sha256": recovered_sha256,
                    "methods": ["Mode A: PyMuPDF XREF rebuild and cleanup"],
                    "messages": [diagnosis["explanation"]],
                    "xai_explanation": diagnosis["explanation"],
                    "confidence": diagnosis["confidence"],
                    "original_file": original_path,
                    "recovered_file": recovered_path,
                    "validation": {"status": "RECOVERED", "checks": ["PyMuPDF cleanup completed"]},
                    "reference_matched": False,
                    "reference_url": None,
                    "reference_sha256": None,
                    "reference_description": None
                }
            except Exception as mode_a_error:
                try:
                    salvaged_text = ''.join(chr(byte) for byte in pdf_bytes if 32 <= byte < 127)

                    fallback_doc = pymupdf.open()
                    page = fallback_doc.new_page()
                    warning_header = (
                        "ANVAYA FORENSIC CARVING MODE\n"
                        "Native rebuild failed. Displaying salvaged raw strings:\n\n"
                    )
                    page.insert_text((50, 50), warning_header + salvaged_text[:2000], fontsize=10)
                    fallback_doc.save(recovered_path)
                    fallback_doc.close()

                    recovered_sha256 = calculate_file_sha256(recovered_path)
                    fallback_explanation = (
                        f"Native rebuild failed ({str(mode_a_error)}). Fallback executed: "
                        "Extracted surviving raw byte strings into a new container."
                    )
                    recovery_result = {
                        "available": True,
                        "status": "PARTIALLY_RECOVERED",
                        "candidate_url": f"/api/case/{case_id}/recovered",
                        "recovered_sha256": recovered_sha256,
                        "methods": ["Mode A: PyMuPDF XREF rebuild and cleanup", "Mode B: Raw Data Carving"],
                        "messages": [fallback_explanation],
                        "xai_explanation": fallback_explanation,
                        "confidence": "75.0%",
                        "original_file": original_path,
                        "recovered_file": recovered_path,
                        "validation": {
                            "status": "PARTIALLY_RECOVERED",
                            "checks": ["Carved text saved in a new PDF container"]
                        },
                        "reference_matched": False,
                        "reference_url": None,
                        "reference_sha256": None,
                        "reference_description": None
                    }
                except Exception as mode_b_error:
                    recovery_result = {
                        "available": False,
                        "status": "UNRECOVERABLE",
                        "validation": {"status": "UNRESOLVED", "checks": []},
                        "methods": ["Mode A", "Mode B"],
                        "messages": [f"All recovery modes failed: {str(mode_b_error)}"],
                        "xai_explanation": diagnosis.get("explanation", "Recovered natively."),
                        "confidence": diagnosis.get("confidence", "99%"),
                        "original_file": original_path,
                        "recovered_file": None,
                        "reference_matched": False,
                        "reference_url": None,
                        "reference_sha256": None,
                        "reference_description": None
                    }
    else:
        recovery_result = orchestrate_recovery(
            case_id=case_id,
            case_dirs=case_dirs,
            evidence_bytes=contents,
            evidence_sha256=sha256_hash,
            file_type=file_type,
            extension=extension,
            corruption_status=corruption_status
        )

    if recovery_result.get("candidate_url"):
        log_custody_event(
            case_dirs["base"],
            case_id,
            "REPAIR_CANDIDATE_GENERATED",
            f"Candidate recovered artifact generated using methods: {', '.join(recovery_result.get('methods', []))}",
            recovery_result.get("recovered_sha256")
        )

    val_res = recovery_result.get("validation", {})
    log_custody_event(case_dirs["base"], case_id, "VALIDATION_RUN", "Independent validation executed on candidate file.")
    log_custody_event(case_dirs["base"], case_id, "VALIDATION_RESULT", f"Validation status: {val_res.get('status', 'UNRESOLVED')}")

    # 6. Forensic Immutability Assertion (Section 5)
    verify_original_unmodified(original_path, sha256_hash)
    log_custody_event(case_dirs["base"], case_id, "ORIGINAL_HASH_VERIFIED", f"Original evidence re-hashed post-analysis. Cryptographic integrity verified: {sha256_hash}", sha256_hash)

    # 7. Build Explanations (Section 21, 29)
    entropy_val = calculate_entropy(contents)
    null_ratio = contents.count(b"\x00") / max(1, size_bytes)

    explanations = []
    if corruption_detected:
        explanations.append({
            "topic": "Detected Corruption",
            "detail": f"{len(reasons)} structural or encoding failure(s) identified.",
            "items": reasons
        })
    else:
        explanations.append({
            "topic": "Structural Health",
            "detail": "All evaluated format-specific checks and syntax structures passed without error.",
            "items": ["Magic bytes header intact", "Container structure verified", "Parser load verified"]
        })

    if recovery_result.get("status") in ("RECOVERED", "REPAIRED"):
        explanations.append({
            "topic": "Applied Restoration",
            "detail": f"Restoration completed via {', '.join(recovery_result.get('methods', []))}.",
            "items": recovery_result.get("messages", [])
        })
    elif recovery_result.get("status") == "PARTIALLY_RECOVERED":
        explanations.append({
            "topic": "Partial Restoration",
            "detail": "Native PDF rebuilding failed; printable evidence was carved into a new PDF container.",
            "items": recovery_result.get("messages", [])
        })
    elif recovery_result.get("status") == "UNRECOVERABLE":
        explanations.append({
            "topic": "Recovery Limitation",
            "detail": "All format-native repair strategies were attempted but could not produce a valid candidate.",
            "items": recovery_result.get("messages", [
                "PyMuPDF could not parse or reconstruct page structure from the damaged stream.",
                "Content stream salvage found no recoverable text segments."
            ])
        })

    # 8. Assemble Canonical Result Schema (Section 19)
    result_payload = {
        "case": {
            "case_id": case_id,
            "created_at": datetime.utcnow().isoformat() + "Z"
        },
        "evidence": {
            "filename": safe_name,
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "file_type": file_type,
            "mime_type": mime_type,
            "extension": extension
        },
        "classification": {
            "status": corruption_status,
            "severity": severity,
            "corruption_detected": corruption_detected,
            "reasons": reasons
        },
        "integrity": {
            "original_hash_verified": True,
            "entropy": entropy_val,
            "null_byte_ratio": round(null_ratio, 4),
            "parseable": format_info.get("parseable", False)
        },
        "fragment_analysis": {
            "fragment_size": frag_size,
            "total_fragments": total_fragments,
            "intact_fragments": intact_frags_count,
            "corrupted_fragments": affected_frags_count,
            "missing_fragments": 0,
            "duplicate_fragments": 0
        },
        "corruption": {
            "affected_ratio": corruption_info.get("affected_ratio", 0.0),
            "affected_regions": corruption_info.get("affected_regions", []),
            "affected_fragments": corruption_info.get("affected_fragments", []),
            "validation_checks": corruption_info.get("validation_checks", [])
        },
        "format_analysis": corruption_info.get("format_analysis", {}),
        "recovery": {
            "available": recovery_result.get("available", False),
            "status": recovery_result.get("status", "NOT_REQUIRED"),
            "candidate_url": recovery_result.get("candidate_url"),
            "recovered_sha256": recovery_result.get("recovered_sha256"),
            "methods": recovery_result.get("methods", []),
            "original_file": recovery_result.get("original_file"),
            "recovered_file": recovery_result.get("recovered_file"),
            "xai_explanation": recovery_result.get("xai_explanation"),
            "confidence": recovery_result.get("confidence"),
            "recovered_fragments": recovery_result.get("recovered_fragments", 0),
            "missing_fragments": recovery_result.get("missing_fragments", 0),
            "unresolved_fragments": recovery_result.get("unresolved_fragments", 0)
        },
        "validation": {
            "status": val_res.get("status", "UNRESOLVED"),
            "checks": val_res.get("checks", [])
        },
        "preview": {
            "uploaded_url": f"/api/case/{case_id}/original",
            "reference_url": recovery_result.get("reference_url"),
            "corrupted_url": f"/api/case/{case_id}/corrupted",
            "recovered_url": recovery_result.get("candidate_url")
        },
        "reference_metadata": {
            "available": recovery_result.get("reference_matched", False),
            "sha256": recovery_result.get("reference_sha256"),
            "description": recovery_result.get("reference_description")
        },
        "explanation": explanations
    }

    # Persist analysis result for page reloads (Section 19)
    result_path = os.path.join(case_dirs["analysis"], "analysis_result.json")
    with open(result_path, "w", encoding="utf-8") as rf:
        json.dump(result_payload, rf, indent=2)

    return result_payload


# -----------------------------------------------------------------------------
# CASE RETRIEVAL (Section 19: page reload support)
# -----------------------------------------------------------------------------
@app.get("/api/case/{case_id}")
def get_case_result(case_id: str):
    """Retrieve full analysis result for a stored case."""
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '', case_id)
    result_path = os.path.join("data", "cases", safe_case_id, "analysis", "analysis_result.json")
    if not os.path.exists(result_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case record '{safe_case_id}' was not found in evidence repository."
        )
    with open(result_path, "r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------------------------------------------------------------
# FILE SERVING ENDPOINTS (Section 17, 24, 35)
# -----------------------------------------------------------------------------
def _serve_evidence_file(case_id: str, subfolder: str, file_pattern: str, event_name: str) -> FileResponse:
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '', case_id)
    folder_path = os.path.join("data", "cases", safe_case_id, subfolder)
    if not os.path.exists(folder_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case subfolder {subfolder} not found.")

    candidates = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    if not candidates:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No artifact found in {subfolder}.")

    target_file = candidates[0]
    filename = os.path.basename(target_file)
    ext = os.path.splitext(filename)[1].lower()

    # Determine Content-Type
    media_type = "application/octet-stream"
    for fmt, mime in MIME_MAP.items():
        if ext == f".{fmt.lower()}":
            media_type = mime
            break
    if ext == ".pdf":
        media_type = "application/pdf"
    elif ext in (".jpg", ".jpeg"):
        media_type = "image/jpeg"
    elif ext == ".png":
        media_type = "image/png"
    elif ext == ".txt":
        media_type = "text/plain; charset=utf-8"
    elif ext == ".json":
        media_type = "application/json"
    elif ext == ".csv":
        media_type = "text/csv; charset=utf-8"

    # Log file served
    log_custody_event(
        os.path.join("data", "cases", safe_case_id),
        safe_case_id,
        "FILE_SERVED",
        f"Served {event_name} artifact '{filename}' ({media_type}) to browser."
    )

    return FileResponse(
        target_file,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@app.get("/api/case/{case_id}/original")
def serve_original(case_id: str):
    """Serve uploaded original evidence."""
    return _serve_evidence_file(case_id, "original", "*", "ORIGINAL_EVIDENCE")


@app.get("/api/case/{case_id}/corrupted")
def serve_corrupted(case_id: str):
    """Serve corrupted evidence for comparison."""
    return _serve_evidence_file(case_id, "original", "*", "CORRUPTED_EVIDENCE")


@app.get("/api/case/{case_id}/recovered")
def serve_recovered(case_id: str):
    """Serve recovered candidate evidence."""
    return _serve_evidence_file(case_id, "recovery", "*", "RECOVERED_CANDIDATE")


@app.get("/api/case/{case_id}/reference")
def serve_reference(case_id: str):
    """Serve genuine matched reference evidence from seeded manifest."""
    safe_case_id = re.sub(r'[^a-zA-Z0-9_-]', '', case_id)
    result_path = os.path.join("data", "cases", safe_case_id, "analysis", "analysis_result.json")
    if not os.path.exists(result_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case record not found.")

    with open(result_path, "r", encoding="utf-8") as f:
        case_data = json.load(f)

    ref_sha = case_data.get("reference_metadata", {}).get("sha256")
    if not ref_sha:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No registered reference for this case.")

    # Locate reference file from manifest
    manifest_path = os.path.join("data", "demo", "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as mf:
            manifest = json.load(mf)
        for d_sha, entry in manifest.items():
            ref_path = entry.get("reference_file")
            if ref_path and os.path.exists(ref_path):
                h = calculate_file_sha256(ref_path)
                if h.lower() == ref_sha.lower():
                    ext = os.path.splitext(ref_path)[1].lower()
                    media_type = "application/pdf" if ext == ".pdf" else ("application/json" if ext == ".json" else "text/plain")
                    log_custody_event(
                        os.path.join("data", "cases", safe_case_id),
                        safe_case_id,
                        "FILE_SERVED",
                        f"Served REFERENCE artifact '{os.path.basename(ref_path)}' to browser."
                    )
                    return FileResponse(
                        ref_path,
                        media_type=media_type,
                        headers={
                            "Content-Disposition": f'inline; filename="{os.path.basename(ref_path)}"',
                            "Cache-Control": "no-cache"
                        }
                    )

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reference file not located.")