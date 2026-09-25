from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import os
import shutil
from datetime import datetime

from backend.reconstruction.fragment_analyzer import analyze_fragments
from backend.evidence.evidence_analyzer import EvidenceAnalyzer

from backend.integrity.integrity_analyzer import (
    scan_fragments,
    generate_integrity_report
)

from backend.integrity.corruption_detector import (
    split_original_file,
    load_damaged_fragments,
    compare_fragments,
    generate_corruption_report
)

from backend.reconstruction.reconstruction_engine import (
    build_reconstruction_map,
    generate_candidate_file,
    create_reconstruction_report
)

from backend.ai.anomaly_detector import (
    analyze_fragment
)

from backend.audit.audit_logger import (
    create_audit_event,
    save_audit_log
)


app = FastAPI(
    title="Anvaya - Digital Evidence Recovery",
    description="Explainable AI-assisted digital evidence reconstruction",
    version="1.0.0"
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
# AI ANOMALY ANALYSIS
# --------------------------------------------------

def run_anomaly_analysis(fragment_dir):

    results = []

    if not os.path.exists(fragment_dir):
        return results

    fragment_files = sorted(
        file
        for file in os.listdir(fragment_dir)
        if file.endswith(".bin")
    )

    for filename in fragment_files:

        path = os.path.join(
            fragment_dir,
            filename
        )

        try:

            result = analyze_fragment(path)

            results.append(result)

        except Exception as error:

            results.append({
                "fragment": filename,
                "status": "ANALYSIS_ERROR",
                "error": str(error)
            })

    return results


def summarize_anomalies(anomaly_results):

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
# CORRUPTION ANALYSIS
# --------------------------------------------------

def run_corruption_analysis(
    source_file,
    fragment_dir
):

    original_fragments = split_original_file(
        source_file,
        fragment_size=4096
    )

    damaged_fragments = load_damaged_fragments(
        fragment_dir
    )

    results = compare_fragments(
        original_fragments,
        damaged_fragments
    )

    report = generate_corruption_report(
        results
    )

    return {
        "report": report,
        "fragments": results,
        "original_fragments": original_fragments,
        "damaged_fragments": damaged_fragments
    }


# --------------------------------------------------
# FINAL RECONSTRUCTION MAP
# --------------------------------------------------

def build_final_reconstruction_map(
    original_fragments,
    damaged_fragments,
    corruption_results
):

    reconstruction_map = build_reconstruction_map(
        original_fragments,
        damaged_fragments
    )

    corruption_by_index = {
        result["original_index"]: result
        for result in corruption_results
    }

    damaged_by_filename = {
        fragment["filename"]: fragment
        for fragment in damaged_fragments
    }

    for item in reconstruction_map:

        index = item["original_index"]

        corruption = corruption_by_index.get(
            index
        )

        if corruption is None:
            continue

        if corruption["status"] == "CORRUPTED":

            filename = corruption["filename"]

            item["status"] = "CORRUPTED"

            item["filename"] = filename

            item["changed_bytes"] = (
                corruption["changed_bytes"]
            )

            if filename in damaged_by_filename:

                item["sha256"] = damaged_by_filename[
                    filename
                ]["sha256"]

        elif corruption["status"] == "MISSING":

            item["status"] = "MISSING"

            item["filename"] = None

            item["sha256"] = None

    reconstruction_map.sort(
        key=lambda item: item["original_index"]
    )

    return reconstruction_map


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():

    return {
        "project": "Anvaya",
        "status": "Backend running",
        "message": "Digital Evidence Recovery System"
    }


# --------------------------------------------------
# UPLOAD ENDPOINT
# --------------------------------------------------

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...)
):

    os.makedirs(
        "data/input",
        exist_ok=True
    )

    file_path = os.path.join(
        "data/input",
        file.filename
    )

    contents = await file.read()

    with open(file_path, "wb") as f:
        f.write(contents)

    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    file_type = identify_file_type(
        contents
    )

    return {
        "filename": file.filename,
        "size_bytes": len(contents),
        "file_type": file_type,
        "sha256": sha256_hash,
        "status": "evidence_ingested"
    }


# --------------------------------------------------
# BASIC ANALYSIS ENDPOINT
# --------------------------------------------------

@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...)
):

    os.makedirs(
        "data/input",
        exist_ok=True
    )

    file_path = os.path.join(
        "data/input",
        file.filename
    )

    with open(
        file_path,
        "wb"
    ) as buffer:

        shutil.copyfileobj(
            file.file,
            buffer
        )

    with open(
        file_path,
        "rb"
    ) as f:

        contents = f.read()

    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    file_type = identify_file_type(
        contents
    )

    fragments = analyze_fragments(
        file_path,
        fragment_size=4096
    )

    total_fragments = len(
        fragments
    )

    return {
        "filename": file.filename,
        "file_type": file_type,
        "size_bytes": len(contents),
        "sha256": sha256_hash,
        "fragment_analysis": {
            "total_fragments": total_fragments,
            "fragment_size": 4096
        },
        "status": "analysis_complete"
    }


# --------------------------------------------------
# INTEGRITY ENDPOINT
# --------------------------------------------------

@app.get("/api/integrity")
def integrity_analysis():

    fragment_dir = "data/fragments"

    if not os.path.exists(
        fragment_dir
    ):

        return {
            "status": "error",
            "message": "No fragment dataset found"
        }

    fragments = scan_fragments(
        fragment_dir
    )

    report = generate_integrity_report(
        fragments,
        original_fragment_count=79
    )

    return {
        "status": "integrity_analysis_complete",
        "integrity": report
    }


# --------------------------------------------------
# ANOMALY ENDPOINT
# --------------------------------------------------

@app.get("/api/anomaly")
def anomaly_analysis():

    fragment_dir = "data/fragments"

    if not os.path.exists(
        fragment_dir
    ):

        return {
            "status": "error",
            "message": "No fragment dataset found"
        }

    anomaly_results = run_anomaly_analysis(
        fragment_dir
    )

    summary = summarize_anomalies(
        anomaly_results
    )

    return {
        "status": "ai_anomaly_analysis_complete",
        "summary": summary,
        "fragments": anomaly_results
    }


# --------------------------------------------------
# COMPLETE CASE ANALYSIS
# --------------------------------------------------

@app.post("/api/case/analyze")
async def complete_case_analysis(
    file: UploadFile = File(...)
):

    os.makedirs(
        "data/input",
        exist_ok=True
    )

    os.makedirs(
        "results",
        exist_ok=True
    )

    file_path = os.path.join(
        "data/input",
        file.filename
    )

    with open(
        file_path,
        "wb"
    ) as buffer:

        shutil.copyfileobj(
            file.file,
            buffer
        )

    evidence_analyzer = EvidenceAnalyzer(fragment_size=4096)
    try:
        evidence_analysis = evidence_analyzer.analyze(file_path)
    except (OSError, RuntimeError) as exc:
        # Keep the existing case analysis available if this additional
        # evidence-only pass cannot read the saved upload.
        evidence_analysis = {
            "status": "unavailable",
            "error": str(exc)
        }

    with open(
        file_path,
        "rb"
    ) as f:

        contents = f.read()

    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    file_type = identify_file_type(
        contents
    )

    fragments = analyze_fragments(
        file_path,
        fragment_size=4096
    )

    total_fragments = len(
        fragments
    )

    case_id = (
        "CASE-"
        + datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
    )

    created_at = datetime.now().isoformat()


    # --------------------------------------------------
    # AUDIT TRAIL
    # --------------------------------------------------

    audit_events = []

    audit_events.append(
        create_audit_event(
            event="CASE_CREATED",
            description="New digital evidence case created.",
            metadata={
                "case_id": case_id,
                "filename": file.filename,
                "file_type": file_type
            }
        )
    )

    audit_events.append(
        create_audit_event(
            event="EVIDENCE_INGESTED",
            description="Original evidence file ingested and hashed.",
            file_path=file_path,
            metadata={
                "sha256": sha256_hash,
                "size_bytes": len(contents)
            }
        )
    )

    audit_events.append(
        create_audit_event(
            event="EVIDENCE_ANALYSIS",
            description="Evidence metadata, fragment hashes, duplicate detection, and recovery analysis completed.",
            metadata=evidence_analysis
        )
    )

    audit_events.append(
        create_audit_event(
            event="FRAGMENT_ANALYSIS",
            description="Evidence divided into fixed-size fragments and analyzed.",
            metadata={
                "fragment_size": 4096,
                "total_fragments": total_fragments
            }
        )
    )


    # --------------------------------------------------
    # ANALYSIS VARIABLES
    # --------------------------------------------------

    fragment_dir = "data/fragments"

    integrity_report = None
    corruption_report = None
    corruption_results = []
    anomaly_results = []
    anomaly_summary = None

    reconstruction_report = None
    reconstruction_map = []
    reconstruction_candidate = None


    # --------------------------------------------------
    # PROCESS FRAGMENTS
    # --------------------------------------------------

    if os.path.exists(
        fragment_dir
    ):

        # ----------------------------------------------
        # INTEGRITY
        # ----------------------------------------------

        fragment_files = scan_fragments(
            fragment_dir
        )

        integrity_report = generate_integrity_report(
            fragment_files,
            original_fragment_count=total_fragments
        )

        audit_events.append(
            create_audit_event(
                event="INTEGRITY_ANALYSIS",
                description="Fragment integrity and duplicate analysis completed.",
                metadata=integrity_report
            )
        )


        # ----------------------------------------------
        # CORRUPTION
        # ----------------------------------------------

        corruption_data = run_corruption_analysis(
            file_path,
            fragment_dir
        )

        corruption_report = (
            corruption_data["report"]
        )

        corruption_results = (
            corruption_data["fragments"]
        )

        original_fragments = (
            corruption_data["original_fragments"]
        )

        damaged_fragments = (
            corruption_data["damaged_fragments"]
        )

        audit_events.append(
            create_audit_event(
                event="CORRUPTION_ANALYSIS",
                description="Fragments classified as intact, corrupted, or missing.",
                metadata=corruption_report
            )
        )


        # ----------------------------------------------
        # AI ANALYSIS
        # ----------------------------------------------

        anomaly_results = run_anomaly_analysis(
            fragment_dir
        )

        anomaly_summary = summarize_anomalies(
            anomaly_results
        )

        audit_events.append(
            create_audit_event(
                event="AI_ANALYSIS",
                description="Explainable heuristic anomaly analysis completed.",
                metadata=anomaly_summary
            )
        )


        # ----------------------------------------------
        # RECONSTRUCTION
        # ----------------------------------------------

        reconstruction_map = (
            build_final_reconstruction_map(
                original_fragments,
                damaged_fragments,
                corruption_results
            )
        )

        reconstruction_report = (
            create_reconstruction_report(
                reconstruction_map
            )
        )

        candidate_filename = (
            f"{case_id}_reconstruction_candidate.bin"
        )

        candidate_path = os.path.join(
            "results",
            candidate_filename
        )

        candidate_result = generate_candidate_file(
            reconstruction_map,
            damaged_fragments,
            candidate_path
        )

        with open(
            candidate_path,
            "rb"
        ) as candidate_file:

            candidate_hash = hashlib.sha256(
                candidate_file.read()
            ).hexdigest()

        reconstruction_candidate = {
            "filename": candidate_filename,
            "path": candidate_path,
            "status": "CANDIDATE_ONLY",
            "description":
                "Partial reconstruction containing "
                "surviving evidence and placeholders "
                "for missing regions.",
            "total_bytes":
                candidate_result["total_bytes"],
            "recovered_bytes":
                candidate_result["recovered_bytes"],
            "missing_bytes":
                candidate_result["missing_bytes"],
            "recovery_percentage":
                candidate_result["recovery_percentage"],
            "sha256":
                candidate_hash
        }

        audit_events.append(
            create_audit_event(
                event="RECONSTRUCTION_GENERATED",
                description="Partial reconstruction candidate generated.",
                file_path=candidate_path,
                metadata={
                    "reconstruction_report":
                        reconstruction_report,
                    "candidate_sha256":
                        candidate_hash
                }
            )
        )


    # --------------------------------------------------
    # SAVE AUDIT LOG
    # --------------------------------------------------

    audit_result = save_audit_log(
        case_id,
        audit_events
    )


    # --------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------

    return {

        "case": {

            "case_id": case_id,

            "created_at":
                created_at,

            "status":
                "analysis_complete"

        },

        "evidence": {

            "filename":
                file.filename,

            "file_type":
                file_type,

            "size_bytes":
                len(contents),

            "sha256":
                sha256_hash

        },

        "evidence_analysis":
            evidence_analysis,

        "fragment_analysis": {

            "total_fragments":
                total_fragments,

            "fragment_size":
                4096

        },

        "integrity":
            integrity_report,

        "corruption": {

            "summary":
                corruption_report,

            "fragments":
                corruption_results

        },

        "ai_analysis": {

            "method":
                "Explainable AI-assisted heuristic analysis",

            "summary":
                anomaly_summary,

            "fragments":
                anomaly_results

        },

        "reconstruction": {

            "status":
                "candidate_generated"
                if reconstruction_candidate
                else "not_available",

            "report":
                reconstruction_report,

            "candidate":
                reconstruction_candidate,

            "map":
                reconstruction_map

        },

        "audit": {

            "status":
                "audit_log_created",

            "audit_file":
                audit_result["audit_file"],

            "audit_sha256":
                audit_result["audit_sha256"],

            "event_count":
                audit_result["event_count"]

        }

    }
