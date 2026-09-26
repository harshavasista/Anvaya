from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import os
import shutil
from datetime import datetime
import uuid

from backend.reconstruction.fragment_analyzer import analyze_fragments
from backend.validators.file_validators import validate_file

from backend.reconstruction.reconstruction_engine import (
    build_reconstruction_map,
    generate_candidate_file,
    create_reconstruction_report
)

from backend.reconstruction.fragment_classifier import (
    classify_all_fragments,
    get_classification_summary
)

from backend.reconstruction.file_recovery import (
    recover_file,
    validate_recovered_file,
    calculate_recovery_metrics
)

from backend.reconstruction.evidence_classifier import (
    generate_evidence_summary
)

from backend.reconstruction.recovery_report import (
    generate_recovery_report,
    save_recovery_report,
    generate_executive_summary
)

from backend.ai.anomaly_detector import (
    analyze_fragment,
    calculate_anomaly_score
)

from backend.audit.audit_logger import (
    create_audit_event,
    save_audit_log
)


app = FastAPI(
    title="Anvaya - Digital Evidence Recovery",
    description="Explainable AI-assisted digital evidence reconstruction",
    version="2.0.0"
)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# FILE TYPE IDENTIFICATION
# --------------------------------------------------

def identify_file_type(data: bytes):
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"\xFF\xD8\xFF"):
        return "JPEG"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/DOCX/XLSX"
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLite"
    try:
        data.decode("utf-8")
        return "TXT"
    except UnicodeDecodeError:
        return "Unknown"


# --------------------------------------------------
# CASE MANAGEMENT
# --------------------------------------------------

def create_case_directory(case_id: str) -> dict:
    base_path = os.path.join("data", "cases", case_id)
    directories = {
        "base": base_path,
        "evidence": os.path.join(base_path, "evidence"),
        "fragments": os.path.join(base_path, "fragments"),
        "analysis": os.path.join(base_path, "analysis"),
        "reconstruction": os.path.join(base_path, "reconstruction"),
        "audit": os.path.join(base_path, "audit")
    }
    for dir_path in directories.values():
        os.makedirs(dir_path, exist_ok=True)
    return directories


def save_evidence_file(contents: bytes, evidence_dir: str, filename: str) -> str:
    evidence_path = os.path.join(evidence_dir, filename)
    with open(evidence_path, "wb") as f:
        f.write(contents)
    return evidence_path


def split_file_to_fragments(file_path: str, fragment_dir: str, fragment_size: int = 4096) -> list:
    fragments = []
    with open(file_path, "rb") as file:
        offset = 0
        fragment_number = 1
        while True:
            data = file.read(fragment_size)
            if not data:
                break
            fragment_hash = hashlib.sha256(data).hexdigest()
            fragment_filename = f"fragment_{fragment_number:04d}.bin"
            fragment_path = os.path.join(fragment_dir, fragment_filename)
            with open(fragment_path, "wb") as f:
                f.write(data)
            fragment = {
                "fragment_id": f"fragment_{fragment_number:04d}",
                "filename": fragment_filename,
                "offset": offset,
                "size": len(data),
                "sha256": fragment_hash
            }
            fragments.append(fragment)
            offset += len(data)
            fragment_number += 1
    return fragments


# --------------------------------------------------
# STANDALONE FRAGMENT ANALYSIS
# --------------------------------------------------

def analyze_fragment_standalone(fragment_info: dict, fragment_dir: str, file_type: str, file_data: bytes) -> dict:
    """
    Analyze a single fragment in the context of the file format.
    Returns analysis with OBSERVED/SUSPECTED/UNKNOWN classification.
    """
    path = os.path.join(fragment_dir, fragment_info["filename"])
    
    with open(path, "rb") as f:
        fragment_data = f.read()
    
    # Base anomaly analysis
    anomaly_result = calculate_anomaly_score(fragment_data)
    
    # Format-specific analysis
    format_analysis = {}
    if file_type == "PDF":
        format_analysis = analyze_pdf_fragment(fragment_data, fragment_info["offset"], file_data)
    elif file_type in ("JPEG", "PNG"):
        format_analysis = analyze_image_fragment(fragment_data, fragment_info["offset"], file_type)
    elif file_type == "TXT":
        format_analysis = analyze_text_fragment(fragment_data, fragment_info["offset"])
    elif file_type == "ZIP/DOCX/XLSX":
        format_analysis = analyze_zip_fragment(fragment_data, fragment_info["offset"])
    elif file_type == "SQLite":
        format_analysis = analyze_sqlite_fragment(fragment_data, fragment_info["offset"])
    
    # Determine status based on anomaly score and format analysis
    status = classify_fragment(anomaly_result, format_analysis)
    
    # Build reasoning
    reasoning = build_reasoning(anomaly_result, format_analysis, status)
    
    return {
        "fragment_id": fragment_info["fragment_id"],
        "filename": fragment_info["filename"],
        "offset": fragment_info["offset"],
        "size": fragment_info["size"],
        "sha256": fragment_info["sha256"],
        "entropy": anomaly_result.get("entropy"),
        "zero_ratio": anomaly_result.get("zero_ratio"),
        "unique_byte_ratio": anomaly_result.get("unique_byte_ratio"),
        "anomaly_score": anomaly_result.get("anomaly_score"),
        "status": status,
        "format_analysis": format_analysis,
        "reasoning": reasoning
    }


def classify_fragment(anomaly_result: dict, format_analysis: dict) -> str:
    """
    Classify fragment as OBSERVED/INTACT, SUSPECTED/ANOMALOUS, or UNKNOWN/UNRECOVERABLE.
    """
    anomaly_score = anomaly_result.get("anomaly_score", 0)
    anomaly_status = anomaly_result.get("status", "NORMAL")
    
    # Check format-specific anomalies
    format_anomalies = format_analysis.get("anomalies", [])
    format_warnings = format_analysis.get("warnings", [])
    
    # HIGH_ANOMALY from anomaly detector OR structural format anomalies
    if anomaly_status == "HIGH_ANOMALY" or any("Missing" in a for a in format_anomalies):
        return "SUSPECTED / ANOMALOUS"
    
    # SUSPICIOUS from anomaly detector OR format warnings
    if anomaly_status == "SUSPICIOUS" or format_warnings or format_anomalies:
        return "SUSPECTED / ANOMALOUS"
    
    # If fragment is mostly zeros or empty, it might be padding/lost data
    zero_ratio = anomaly_result.get("zero_ratio", 0)
    if zero_ratio > 0.95:
        return "UNKNOWN / UNRECOVERABLE"
    
    return "OBSERVED / INTACT"


def analyze_pdf_fragment(fragment_data: bytes, offset: int, file_data: bytes) -> dict:
    """Analyze a fragment in context of PDF structure."""
    result = {"anomalies": [], "warnings": []}
    
    # Check if fragment contains PDF structural elements
    if offset == 0:
        if not fragment_data.startswith(b"%PDF"):
            result["anomalies"].append("Missing PDF header at offset 0")
        else:
            # Check version
            for line in fragment_data[:100].split(b"\n"):
                if line.startswith(b"%PDF-"):
                    try:
                        version = float(line[5:].decode().strip())
                        if version < 1.0 or version > 2.0:
                            result["warnings"].append(f"Unusual PDF version: {version}")
                    except:
                        pass
                    break
    
    # Check for structural keywords
    structural_keywords = [b"xref", b"trailer", b"startxref", b"obj", b"endobj", b"stream", b"endstream"]
    found_keywords = [kw for kw in structural_keywords if kw in fragment_data]
    
    # If in middle of file but no structural elements, might be content stream
    if offset > 100 and not found_keywords:
        result["warnings"].append("No PDF structural elements found in fragment")
    
    # Check for encryption
    if b"/Encrypt" in fragment_data:
        result["warnings"].append("Encryption dictionary found - content analysis limited")
    
    return result


def analyze_image_fragment(fragment_data: bytes, offset: int, file_type: str) -> dict:
    """Analyze a fragment in context of JPEG/PNG structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if file_type == "JPEG":
            if not fragment_data.startswith(b"\xFF\xD8\xFF"):
                result["anomalies"].append("Missing JPEG header (FF D8 FF)")
        elif file_type == "PNG":
            if not fragment_data.startswith(b"\x89PNG\r\n\x1a\n"):
                result["anomalies"].append("Missing PNG signature")
    
    # Check for end markers
    if file_type == "JPEG" and fragment_data.endswith(b"\xFF\xD9"):
        pass  # Normal EOF
    elif file_type == "PNG" and b"IEND" in fragment_data:
        pass  # Normal EOF
    
    return result


def analyze_text_fragment(fragment_data: bytes, offset: int) -> dict:
    """Analyze a fragment in context of text file."""
    result = {"anomalies": [], "warnings": []}
    
    try:
        fragment_data.decode("utf-8")
    except UnicodeDecodeError:
        result["anomalies"].append("Invalid UTF-8 sequence in fragment")
    
    # Check for null bytes
    null_count = fragment_data.count(0)
    if null_count > 0:
        result["anomalies"].append(f"Contains {null_count} null bytes")
    
    return result


def analyze_zip_fragment(fragment_data: bytes, offset: int) -> dict:
    """Analyze a fragment in context of ZIP structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not (fragment_data.startswith(b"PK\x03\x04") or 
                fragment_data.startswith(b"PK\x05\x06") or 
                fragment_data.startswith(b"PK\x07\x08")):
            result["anomalies"].append("Missing ZIP signature")
    
    return result


def analyze_sqlite_fragment(fragment_data: bytes, offset: int) -> dict:
    """Analyze a fragment in context of SQLite structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"SQLite format 3\x00"):
            result["anomalies"].append("Missing SQLite header")
    
    return result


def build_reasoning(anomaly_result: dict, format_analysis: dict, status: str) -> list:
    """Build explainable reasoning for fragment classification."""
    reasons = []
    
    # Add anomaly detector reasons
    for reason in anomaly_result.get("reasons", []):
        reasons.append(f"WHAT: {reason}")
    
    # Add format-specific reasons
    for anomaly in format_analysis.get("anomalies", []):
        reasons.append(f"WHAT: {anomaly}")
        reasons.append("WHY: Structural inconsistency detected in file format")
        reasons.append("LIMITATION: Original content cannot be determined from this evidence alone")
    
    for warning in format_analysis.get("warnings", []):
        reasons.append(f"WHAT: {warning}")
        reasons.append("WHY: Format inconsistency detected")
        reasons.append("LIMITATION: Cannot determine if this represents corruption or valid variation")
    
    if status == "UNKNOWN / UNRECOVERABLE":
        reasons.append("WHAT: Fragment is predominantly zero-filled or empty")
        reasons.append("WHY: No discernible structure or content in this region")
        reasons.append("LIMITATION: Cannot determine if data was originally present or is padding")
    
    if status == "OBSERVED / INTACT":
        reasons.append("WHAT: Fragment is physically present with no detected anomalies")
        reasons.append("WHY: Byte distribution and structure are consistent with expectations")
    
    return reasons if reasons else ["No specific analysis findings"]


# --------------------------------------------------
# EVIDENCE INTEGRITY METRICS
# --------------------------------------------------

def calculate_evidence_integrity(fragment_analyses: list, format_validation: dict) -> dict:
    """
    Calculate evidence integrity metrics from standalone analysis.
    Does NOT claim recovery rate - only reports what is observable.
    """
    total = len(fragment_analyses)
    if total == 0:
        return {
            "evidence_integrity": "N/A",
            "observed_intact": 0,
            "suspected_anomalous": 0,
            "unknown_unrecoverable": 0,
            "total_fragments": 0,
            "format_validation": format_validation
        }
    
    observed = sum(1 for f in fragment_analyses if f["status"] == "OBSERVED / INTACT")
    suspected = sum(1 for f in fragment_analyses if f["status"] == "SUSPECTED / ANOMALOUS")
    unknown = sum(1 for f in fragment_analyses if f["status"] == "UNKNOWN / UNRECOVERABLE")
    
    integrity_pct = round((observed / total) * 100, 2) if total > 0 else 0
    suspected_pct = round((suspected / total) * 100, 2) if total > 0 else 0
    unknown_pct = round((unknown / total) * 100, 2) if total > 0 else 0
    
    return {
        "evidence_integrity": integrity_pct,
        "observed_intact": observed,
        "suspected_anomalous": suspected,
        "unknown_unrecoverable": unknown,
        "observed_percentage": integrity_pct,
        "suspected_percentage": suspected_pct,
        "unknown_percentage": unknown_pct,
        "total_fragments": total,
        "format_validation": format_validation,
        "disclaimer": "Standalone analysis: no original reference evidence was supplied. Results describe the condition of the submitted evidence and do not establish recovery of missing historical data."
    }


# --------------------------------------------------
# AI ANOMALY ANALYSIS (enhanced)
# --------------------------------------------------

def run_anomaly_analysis_standalone(fragments: list, fragment_dir: str) -> list:
    """Run anomaly analysis on case-specific fragments."""
    results = []
    for fragment in fragments:
        path = os.path.join(fragment_dir, fragment["filename"])
        try:
            result = analyze_fragment(path)
            result["fragment_id"] = fragment["fragment_id"]
            results.append(result)
        except Exception as error:
            results.append({
                "fragment_id": fragment["fragment_id"],
                "filename": fragment["filename"],
                "status": "ANALYSIS_ERROR",
                "error": str(error)
            })
    return results


def summarize_anomalies(anomaly_results: list) -> dict:
    normal = 0
    suspicious = 0
    high_anomaly = 0
    errors = 0
    for result in anomaly_results:
        status = result.get("status")
        if status == "NORMAL":
            normal += 1
        elif status == "SUSPICIOUS":
            suspicious += 1
        elif status == "HIGH_ANOMALY":
            high_anomaly += 1
        elif status == "ANALYSIS_ERROR":
            errors += 1
    return {
        "fragments_analyzed": len(anomaly_results),
        "normal": normal,
        "suspicious": suspicious,
        "high_anomaly": high_anomaly,
        "analysis_errors": errors
    }


# --------------------------------------------------
# RECONSTRUCTION - ANALYSIS CANDIDATE
# --------------------------------------------------

def build_reconstruction_map_standalone(fragments: list, fragment_analyses: list) -> list:
    """
    Build reconstruction map from standalone analysis.
    No reference original - map is based on observed fragment order.
    """
    reconstruction_map = []
    for i, fragment in enumerate(fragments):
        analysis = fragment_analyses[i] if i < len(fragment_analyses) else {}
        status = analysis.get("status", "UNKNOWN / UNRECOVERABLE")
        
        if status == "OBSERVED / INTACT":
            status = "OBSERVED"
        elif status == "SUSPECTED / ANOMALOUS":
            status = "SUSPECTED"
        else:
            status = "UNKNOWN"
        
        reconstruction_map.append({
            "fragment_index": i,
            "original_index": i,
            "filename": fragment["filename"],
            "status": status,
            "sha256": fragment["sha256"],
            "size": fragment["size"],
            "offset": fragment["offset"]
        })
    return reconstruction_map


def generate_candidate_file_standalone(reconstruction_map: list, fragments_dir: str, output_path: str) -> dict:
    """
    Generate analysis candidate containing only observed evidence.
    Missing/unknown regions are left as zeros with clear labeling.
    """
    fragment_lookup = {}
    for filename in os.listdir(fragments_dir):
        if filename.endswith(".bin"):
            path = os.path.join(fragments_dir, filename)
            with open(path, "rb") as f:
                data = f.read()
            fragment_lookup[filename] = data
    
    total_bytes = 0
    observed_bytes = 0
    unknown_bytes = 0
    
    with open(output_path, "wb") as output:
        for item in reconstruction_map:
            filename = item["filename"]
            size = item["size"]
            status = item["status"]
            
            if status == "OBSERVED" and filename in fragment_lookup:
                data = fragment_lookup[filename]
                output.write(data)
                observed_bytes += len(data)
                total_bytes += len(data)
            else:
                # Zero-filled placeholder - NOT claimed as recovered
                output.write(b"\x00" * size)
                unknown_bytes += size
                total_bytes += size
    
    observed_pct = round((observed_bytes / total_bytes) * 100, 2) if total_bytes > 0 else 0
    
    return {
        "total_bytes": total_bytes,
        "observed_bytes": observed_bytes,
        "unknown_bytes": unknown_bytes,
        "observed_percentage": observed_pct
    }


def create_reconstruction_report_standalone(reconstruction_map: list) -> dict:
    observed = sum(1 for item in reconstruction_map if item["status"] == "OBSERVED")
    suspected = sum(1 for item in reconstruction_map if item["status"] == "SUSPECTED")
    unknown = sum(1 for item in reconstruction_map if item["status"] == "UNKNOWN")
    total = len(reconstruction_map)
    
    return {
        "total_fragments": total,
        "observed_fragments": observed,
        "suspected_fragments": suspected,
        "unknown_fragments": unknown,
        "observed_percentage": round((observed / total) * 100, 2) if total > 0 else 0,
        "suspected_percentage": round((suspected / total) * 100, 2) if total > 0 else 0,
        "unknown_percentage": round((unknown / total) * 100, 2) if total > 0 else 0
    }


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "project": "Anvaya",
        "status": "Backend running",
        "message": "Digital Evidence Recovery System - Standalone Analysis Mode"
    }


# --------------------------------------------------
# UPLOAD ENDPOINT
# --------------------------------------------------

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    os.makedirs("data/input", exist_ok=True)
    file_path = os.path.join("data/input", file.filename)
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)
    sha256_hash = hashlib.sha256(contents).hexdigest()
    file_type = identify_file_type(contents)
    return {
        "filename": file.filename,
        "size_bytes": len(contents),
        "file_type": file_type,
        "sha256": sha256_hash,
        "status": "evidence_ingested"
    }


# --------------------------------------------------
# COMPLETE CASE ANALYSIS - STANDALONE
# --------------------------------------------------

@app.post("/api/case/analyze")
async def complete_case_analysis(file: UploadFile = File(...)):
    os.makedirs("data/input", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    
    file_path = os.path.join("data/input", file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    with open(file_path, "rb") as f:
        contents = f.read()
    
    sha256_hash = hashlib.sha256(contents).hexdigest()
    file_type = identify_file_type(contents)
    
    # Initial fragment count
    fragments = analyze_fragments(file_path, fragment_size=4096)
    total_fragments = len(fragments)
    
    case_id = "CASE-" + datetime.now().strftime("%Y%m%d%H%M%S")
    created_at = datetime.now().isoformat()
    
    # Create case directory structure
    case_dirs = create_case_directory(case_id)
    
    # Save evidence
    evidence_path = save_evidence_file(contents, case_dirs["evidence"], file.filename)
    
    # Split into case-specific fragments
    case_fragments = split_file_to_fragments(file_path, case_dirs["fragments"], fragment_size=4096)
    
    # Audit trail
    audit_events = []
    audit_events.append(create_audit_event("CASE_CREATED", "New digital evidence case created.", metadata={"case_id": case_id, "filename": file.filename, "file_type": file_type}))
    audit_events.append(create_audit_event("EVIDENCE_INGESTED", "Original evidence file ingested and hashed.", file_path=evidence_path, metadata={"sha256": sha256_hash, "size_bytes": len(contents)}))
    audit_events.append(create_audit_event("FRAGMENT_ANALYSIS", "Evidence divided into fixed-size fragments and analyzed.", metadata={"fragment_size": 4096, "total_fragments": total_fragments}))
    
    fragment_dir = case_dirs["fragments"]
    
    # --------------------------------------------------
    # FORMAT VALIDATION
    # --------------------------------------------------
    format_validation = validate_file(contents, file_type)
    
    audit_events.append(create_audit_event("FORMAT_VALIDATION", f"File format validation completed: {file_type}", metadata=format_validation))
    
    # --------------------------------------------------
    # FRAGMENT ANALYSIS (STANDALONE)
    # --------------------------------------------------
    fragment_analyses = []
    for fragment in case_fragments:
        analysis = analyze_fragment_standalone(fragment, fragment_dir, file_type, contents)
        fragment_analyses.append(analysis)
    
    audit_events.append(create_audit_event("FRAGMENT_INTEGRITY_ANALYSIS", "Individual fragment integrity analysis completed.", metadata={"fragments_analyzed": len(fragment_analyses)}))
    
    # --------------------------------------------------
    # AI ANOMALY ANALYSIS
    # --------------------------------------------------
    anomaly_results = run_anomaly_analysis_standalone(case_fragments, fragment_dir)
    anomaly_summary = summarize_anomalies(anomaly_results)
    
    audit_events.append(create_audit_event("AI_ANOMALY_ANALYSIS", "Explainable heuristic anomaly analysis completed.", metadata=anomaly_summary))
    
    # --------------------------------------------------
    # EVIDENCE INTEGRITY METRICS
    # --------------------------------------------------
    integrity_metrics = calculate_evidence_integrity(fragment_analyses, format_validation)
    
    audit_events.append(create_audit_event("EVIDENCE_INTEGRITY_CALCULATION", "Evidence integrity metrics calculated from observable evidence.", metadata=integrity_metrics))
    
    # --------------------------------------------------
    # RECONSTRUCTION - ANALYSIS CANDIDATE
    # --------------------------------------------------
    reconstruction_map = build_reconstruction_map_standalone(case_fragments, fragment_analyses)
    reconstruction_report = create_reconstruction_report_standalone(reconstruction_map)
    
    candidate_filename = f"{case_id}_analysis_candidate.bin"
    candidate_path = os.path.join(case_dirs["reconstruction"], candidate_filename)
    
    candidate_result = generate_candidate_file_standalone(reconstruction_map, fragment_dir, candidate_path)
    
    with open(candidate_path, "rb") as candidate_file:
        candidate_hash = hashlib.sha256(candidate_file.read()).hexdigest()
    
    reconstruction_candidate = {
        "filename": candidate_filename,
        "path": candidate_path,
        "status": "ANALYSIS_CANDIDATE",
        "description": "Analysis candidate containing surviving evidence only. Missing or indeterminate content has not been invented.",
        "total_bytes": candidate_result["total_bytes"],
        "observed_bytes": candidate_result["observed_bytes"],
        "unknown_bytes": candidate_result["unknown_bytes"],
        "observed_percentage": candidate_result["observed_percentage"],
        "sha256": candidate_hash,
        "disclaimer": "Candidate reconstruction contains surviving evidence only. Missing or indeterminate content has not been invented."
    }
    
    audit_events.append(create_audit_event("ANALYSIS_CANDIDATE_GENERATED", "Analysis candidate generated from observed evidence.", file_path=candidate_path, metadata={"reconstruction_report": reconstruction_report, "candidate_sha256": candidate_hash}))
    
    # Save audit log
    audit_result = save_audit_log(case_id, audit_events, output_dir=case_dirs["audit"])
    
    # --------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------
    return {
        "case": {
            "case_id": case_id,
            "created_at": created_at,
            "status": "analysis_complete"
        },
        "evidence": {
            "filename": file.filename,
            "file_type": file_type,
            "size_bytes": len(contents),
            "sha256": sha256_hash
        },
        "fragment_analysis": {
            "total_fragments": total_fragments,
            "fragment_size": 4096
        },
        "format_validation": format_validation,
        "fragment_analysis": fragment_analyses,
        "ai_analysis": {
            "method": "Explainable AI-assisted heuristic analysis",
            "summary": anomaly_summary,
            "fragments": anomaly_results
        },
        "evidence_integrity": integrity_metrics,
        "reconstruction": {
            "status": "candidate_generated" if reconstruction_candidate else "not_available",
            "report": reconstruction_report,
            "candidate": reconstruction_candidate,
            "map": reconstruction_map
        },
        "audit": {
            "status": "audit_log_created",
            "audit_file": audit_result["audit_file"],
            "audit_sha256": audit_result["audit_sha256"],
            "event_count": audit_result["event_count"]
        }
    }


# --------------------------------------------------
# LEGACY ENDPOINTS (for backward compatibility)
# --------------------------------------------------

@app.get("/api/integrity")
def integrity_analysis_legacy():
    """Legacy endpoint - returns notice about standalone mode."""
    return {
        "status": "deprecated",
        "message": "Global fragment dataset analysis deprecated. Use /api/case/analyze for standalone file analysis."
    }


@app.get("/api/anomaly")
def anomaly_analysis_legacy():
    """Legacy endpoint - returns notice about standalone mode."""
    return {
        "status": "deprecated",
        "message": "Global fragment dataset analysis deprecated. Use /api/case/analyze for standalone file analysis."
    }


# --------------------------------------------------
# COMPLETE CASE RECOVERY - FULL PIPELINE
# --------------------------------------------------

@app.post("/api/case/recover")
async def complete_case_recovery(file: UploadFile = File(...)):
    """
    Complete recovery pipeline:
    1. Ingestion (SHA-256, metadata, file type)
    2. Identification (Magic bytes)
    3. Fragmentation (4096-byte fragments with hashes + offsets)
    4. Fragment Classification (INTACT, CORRUPTED, MISSING, DUPLICATE)
    5. Reconstruction (Correct ordering, duplicate handling)
    6. File-Type Recovery (Generic strategies)
    7. Evidence Classification (RECOVERED, REPAIRED, AI-INFERRED, UNKNOWN)
    8. Validation
    9. Recovery Report
    """
    os.makedirs("data/input", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    
    file_path = os.path.join("data/input", file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    with open(file_path, "rb") as f:
        contents = f.read()
    
    sha256_hash = hashlib.sha256(contents).hexdigest()
    file_type = identify_file_type(contents)
    
    case_id = "CASE-" + datetime.now().strftime("%Y%m%d%H%M%S")
    created_at = datetime.now().isoformat()
    
    # Create case directory structure
    case_dirs = create_case_directory(case_id)
    
    # Save evidence
    evidence_path = save_evidence_file(contents, case_dirs["evidence"], file.filename)
    
    # Split into case-specific fragments
    case_fragments = split_file_to_fragments(file_path, case_dirs["fragments"], fragment_size=4096)
    
    # Audit trail
    audit_events = []
    audit_events.append(create_audit_event("CASE_CREATED", "New digital evidence case created.", metadata={"case_id": case_id, "filename": file.filename, "file_type": file_type}))
    audit_events.append(create_audit_event("EVIDENCE_INGESTED", "Original evidence file ingested and hashed.", file_path=evidence_path, metadata={"sha256": sha256_hash, "size_bytes": len(contents)}))
    audit_events.append(create_audit_event("FRAGMENTATION", "Evidence divided into fixed-size fragments.", metadata={"fragment_size": 4096, "total_fragments": len(case_fragments)}))
    
    fragment_dir = case_dirs["fragments"]
    
    # --------------------------------------------------
    # 1. FORMAT VALIDATION (Identification)
    # --------------------------------------------------
    format_validation = validate_file(contents, file_type)
    audit_events.append(create_audit_event("FORMAT_VALIDATION", f"File format validation completed: {file_type}", metadata=format_validation))
    
    # --------------------------------------------------
    # 2. FRAGMENT CLASSIFICATION
    # --------------------------------------------------
    fragment_classifications = classify_all_fragments(case_fragments, fragment_dir, file_type)
    classification_summary = get_classification_summary(fragment_classifications)
    
    audit_events.append(create_audit_event("FRAGMENT_CLASSIFICATION", "Fragments classified as INTACT/CORRUPTED/MISSING/DUPLICATE", metadata=classification_summary))
    
    # --------------------------------------------------
    # 3. RECOVERY (Reconstruction + File-Type Recovery)
    # --------------------------------------------------
    recovered_data, evidence_classifications = recover_file(
        fragment_classifications,
        fragment_dir,
        file_type,
        len(contents),
        reference_data=None  # No reference in standalone mode
    )
    
    # Save recovered file
    # Sanitize file_type for use in filename
    safe_file_type = file_type.lower().replace("/", "_").replace("\\", "_")
    recovered_filename = f"{case_id}_recovered.{safe_file_type}"
    recovered_path = os.path.join(case_dirs["reconstruction"], recovered_filename)
    with open(recovered_path, "wb") as f:
        f.write(recovered_data)
    
    recovered_hash = hashlib.sha256(recovered_data).hexdigest()
    
    audit_events.append(create_audit_event("RECOVERY_COMPLETE", "File recovery completed using multi-strategy pipeline.", metadata={
        "recovered_size": len(recovered_data),
        "recovered_sha256": recovered_hash,
        "strategies_used": list(set(ec.get("recovery_strategy") for ec in evidence_classifications))
    }))
    
    # --------------------------------------------------
    # 4. VALIDATION
    # --------------------------------------------------
    validation_result = validate_recovered_file(recovered_data, file_type)
    
    audit_events.append(create_audit_event("RECOVERY_VALIDATION", f"Recovered file validated: {file_type}", metadata=validation_result))
    
    # --------------------------------------------------
    # 5. EVIDENCE CLASSIFICATION & METRICS
    # --------------------------------------------------
    evidence_summary = generate_evidence_summary(evidence_classifications)
    recovery_metrics = calculate_recovery_metrics(len(contents), recovered_data, evidence_classifications)
    
    audit_events.append(create_audit_event("EVIDENCE_CLASSIFICATION", "Recovered regions classified by evidence status", metadata=evidence_summary))
    
    # --------------------------------------------------
    # 6. RECOVERY REPORT
    # --------------------------------------------------
    evidence_info = {
        "filename": file.filename,
        "file_type": file_type,
        "size_bytes": len(contents),
        "sha256": sha256_hash
    }
    
    recovery_report = generate_recovery_report(
        case_id=case_id,
        evidence_info=evidence_info,
        fragment_classifications=fragment_classifications,
        evidence_classifications=evidence_classifications,
        recovered_data=recovered_data,
        validation_result=validation_result,
        recovery_metrics=recovery_metrics,
        audit_events=audit_events
    )
    
    # Save report
    report_result = save_recovery_report(recovery_report, case_dirs["analysis"], case_id)
    
    # Generate executive summary
    executive_summary = generate_executive_summary(recovery_report)
    
    audit_events.append(create_audit_event("RECOVERY_REPORT_GENERATED", "Comprehensive recovery report generated.", file_path=report_result["report_path"], metadata={"report_sha256": report_result["report_sha256"]}))
    
    # Save final audit log
    audit_result = save_audit_log(case_id, audit_events, output_dir=case_dirs["audit"])
    
    # --------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------
    return {
        "case": {
            "case_id": case_id,
            "created_at": created_at,
            "status": "recovery_complete"
        },
        "evidence": evidence_info,
        "fragment_classification": classification_summary,
        "format_validation": format_validation,
        "recovery": {
            "recovered_file": {
                "filename": recovered_filename,
                "path": recovered_path,
                "size_bytes": len(recovered_data),
                "sha256": recovered_hash
            },
            "evidence_summary": evidence_summary,
            "recovery_metrics": recovery_metrics,
            "validation": validation_result
        },
        "report": {
            "path": report_result["report_path"],
            "sha256": report_result["report_sha256"],
            "executive_summary": executive_summary
        },
        "audit": {
            "status": "audit_log_created",
            "audit_file": audit_result["audit_file"],
            "audit_sha256": audit_result["audit_sha256"],
            "event_count": audit_result["event_count"]
        }
    }