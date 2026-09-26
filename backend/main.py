"""
ANVAYA — Digital Evidence Analysis & Forensic Reconstruction Engine
FastAPI Backend Application
"""

import os
import re
import json
import uuid
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
    recovery_result = orchestrate_recovery(
        case_id=case_id,
        case_dirs=case_dirs,
        evidence_bytes=contents,
        evidence_sha256=sha256_hash,
        file_type=file_type,
        extension=extension,
        corruption_status=corruption_status
    )

    if recovery_result.get("reference_matched"):
        log_custody_event(
            case_dirs["base"],
            case_id,
            "REFERENCE_MATCHED",
            f"Seeded demo manifest matched reference exhibit: {recovery_result.get('reference_description')}",
            recovery_result.get("reference_sha256")
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
    elif recovery_result.get("status") == "UNRECOVERABLE":
        explanations.append({
            "topic": "Recovery Limitation",
            "detail": "Restoration was not safe or possible with available evidence.",
            "items": [
                "Independent original/reference evidence was not available for block substitution.",
                "Format-native parser could not safely synthesize missing binary headers without risk of fabrication."
            ]
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