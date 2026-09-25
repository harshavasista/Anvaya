from fastapi import FastAPI, UploadFile, File
import hashlib
import os
import shutil

from backend.reconstruction.fragment_analyzer import analyze_fragments
from backend.integrity.integrity_analyzer import (
    scan_fragments,
    generate_integrity_report
)


# ==================================================
# ANVAYA APPLICATION
# ==================================================

app = FastAPI(
    title="Anvaya - Digital Evidence Recovery",
    description="Explainable AI-assisted digital evidence reconstruction",
    version="1.0.0"
)


# ==================================================
# FILE TYPE IDENTIFICATION
# ==================================================

def identify_file_type(data: bytes):

    # PDF
    if data.startswith(b"%PDF"):
        return "PDF"

    # JPEG
    if data.startswith(b"\xFF\xD8\xFF"):
        return "JPEG"

    # PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"

    # ZIP / DOCX / XLSX
    if data.startswith(b"PK\x03\x04"):
        return "ZIP/DOCX/XLSX"

    # SQLite
    if data.startswith(b"SQLite format 3\x00"):
        return "SQLite"

    # TXT
    try:
        data.decode("utf-8")
        return "TXT"
    except UnicodeDecodeError:
        return "Unknown"


# ==================================================
# HOME
# ==================================================

@app.get("/")
def home():

    return {
        "project": "Anvaya",
        "status": "Backend running",
        "message": "Digital Evidence Recovery System"
    }


# ==================================================
# UPLOAD EVIDENCE
# ==================================================

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):

    os.makedirs("data/input", exist_ok=True)

    file_path = os.path.join(
        "data/input",
        file.filename
    )

    # Read uploaded evidence
    contents = await file.read()

    # Save original evidence
    with open(file_path, "wb") as f:
        f.write(contents)

    # SHA-256
    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    # File type
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


# ==================================================
# ANALYZE EVIDENCE
# ==================================================

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):

    os.makedirs("data/input", exist_ok=True)

    file_path = os.path.join(
        "data/input",
        file.filename
    )

    # Save evidence
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(
            file.file,
            buffer
        )

    # Read evidence
    with open(file_path, "rb") as f:
        contents = f.read()

    # SHA-256
    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    # File type
    file_type = identify_file_type(
        contents
    )

    # Fragment analysis
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


# ==================================================
# INTEGRITY ANALYSIS
# ==================================================

@app.get("/api/integrity")
def integrity_analysis():

    fragment_dir = "data/fragments"

    # Check fragment directory
    if not os.path.exists(
        fragment_dir
    ):

        return {
            "status": "error",
            "message": "No fragment dataset found"
        }

    # Scan fragments
    fragments = scan_fragments(
        fragment_dir
    )

    # Generate report
    report = generate_integrity_report(
        fragments,
        original_fragment_count=79
    )

    return {
        "status": "integrity_analysis_complete",
        "integrity": report
    }


# ==================================================
# COMPLETE CASE ANALYSIS
# ==================================================

@app.post("/api/case/analyze")
async def complete_case_analysis(
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

    # ----------------------------------------------
    # Save evidence
    # ----------------------------------------------

    with open(
        file_path,
        "wb"
    ) as buffer:

        shutil.copyfileobj(
            file.file,
            buffer
        )

    # ----------------------------------------------
    # Read evidence
    # ----------------------------------------------

    with open(
        file_path,
        "rb"
    ) as f:

        contents = f.read()

    # ----------------------------------------------
    # Evidence hash
    # ----------------------------------------------

    sha256_hash = hashlib.sha256(
        contents
    ).hexdigest()

    # ----------------------------------------------
    # File identification
    # ----------------------------------------------

    file_type = identify_file_type(
        contents
    )

    # ----------------------------------------------
    # Fragment analysis
    # ----------------------------------------------

    fragments = analyze_fragments(
        file_path,
        fragment_size=4096
    )

    total_fragments = len(
        fragments
    )

    # ----------------------------------------------
    # Integrity analysis
    # ----------------------------------------------

    fragment_dir = "data/fragments"

    integrity_report = None

    if os.path.exists(
        fragment_dir
    ):

        fragment_files = scan_fragments(
            fragment_dir
        )

        integrity_report = (
            generate_integrity_report(
                fragment_files,
                original_fragment_count=
                total_fragments
            )
        )

    # ----------------------------------------------
    # Complete case response
    # ----------------------------------------------

    return {

        "case_status": "analysis_complete",

        "evidence": {

            "filename": file.filename,

            "file_type": file_type,

            "size_bytes": len(contents),

            "sha256": sha256_hash

        },

        "fragment_analysis": {

            "total_fragments":
                total_fragments,

            "fragment_size":
                4096

        },

        "integrity":
            integrity_report

    }