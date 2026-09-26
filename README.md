# ANVAYA
## Explainable AI-Based Digital Evidence Reconstruction and Forensic Analysis

> **Forensic Integrity Notice:**  
> *"ANVAYA does not invent genuinely missing information. Recovery requires either safe format-native repair or sufficient independent evidence."*

---

### 1. Purpose & Overview
**ANVAYA** is an autonomous, explainable digital forensics laboratory application designed to inspect, analyze, validate, and safely recover damaged or suspicious digital evidence.

Instead of presenting opaque "AI recovery" percentages or guessing corrupted data, ANVAYA enforces cryptographic certainty:
1. **Immutable Ingestion:** Original evidence is stored securely and re-hashed post-analysis to guarantee zero mutation.
2. **Deterministic Corruption Detection:** Structural, syntax, container, and encoding checks evaluate the file against strict format specifications.
3. **Reproducible Severity Rubric:** Status and severity follow a mathematical ratio rather than subjective judgment.
4. **Side-by-Side Visual Comparison:** Reference exhibits and damaged evidence are rendered simultaneously on screen.
5. **Verified Recovery & Independent Validation:** Reconstructed artifacts must be reopened, re-parsed, and re-validated before being marked as repaired.
6. **Append-Only Chain of Custody:** Every action is logged in an append-only JSONL audit trail.

---

### 2. Architecture & Workflow

```
                   UPLOAD EVIDENCE FILE (Max 100 MB)
                                 ↓
            INGESTION & SHA-256 HASH (Original preserved)
                                 ↓
                     FORMAT IDENTIFICATION ROUTER
              (Magic bytes, container inspection, headers)
                                 ↓
            STRUCTURAL & CORRUPTION DETECTION ENGINE
                (Format-specific parser & syntax checks)
                                 ↓
            REPRODUCIBLE SEVERITY RUBRIC (Section 27a)
            (HEALTHY | PARTIALLY_CORRUPTED | CORRUPTED | SEVERELY_CORRUPTED)
                                 ↓
            FORENSIC SIDE-BY-SIDE COMPARISON
          Left: ORIGINAL / REFERENCE (if available)
          Right: CORRUPTED UPLOADED EVIDENCE
                                 ↓
            RECOVERY & RECONSTRUCTION PIPELINE
         Mode A: Format-Native Repair (PyMuPDF / Syntax Normalization)
         Mode B: Evidence-Backed Reconstruction (Seeded Manifest Exhibit)
                                 ↓
            INDEPENDENT CANDIDATE VALIDATION
         (Re-open candidate, re-parse syntax, rasterize, re-hash)
                                 ↓
            FINAL FORENSIC RESULT & EXPLANATION
```

---

### 3. Tiered Format Support

| Tier | Formats | Ingestion & Hash | Corruption Detection | Structural Analysis | Safe Repair / Recovery | Independent Validation | Inline Browser Preview |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tier 1 (Core)** | **PDF, JSON, TXT** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (PDF iframe, Syntax JSON, Monospace Text) |
| **Tier 2** | **PNG, JPEG, CSV, ZIP** | ✅ | ✅ | ✅ | Conservative / Analysis | ✅ | ✅ (Images, Table) |
| **Tier 3** | **DOCX, XLSX, SQLite** | ✅ | ✅ | ✅ | Structural Inspection Only | ✅ | ✅ (Metadata/Container) |
| **Fallback** | **Generic Binary** | ✅ | ✅ (Entropy / Zeros) | Metadata | ❌ (Unsafe) | N/A | Safe Structure View |

---

### 4. Reproducible Severity Rubric (Section 27a)
To ensure that two runs on the same evidence never disagree, severity is computed deterministically:

Let $\text{affected\_ratio} = \frac{\text{Count of failed structural checks or damaged regions}}{\text{Count of total applicable structural checks for that format}}$

- $\text{affected\_ratio} = 0.0$ $\longrightarrow$ **`HEALTHY`**
- $0.0 < \text{affected\_ratio} \le 0.25$ $\longrightarrow$ **`PARTIALLY_CORRUPTED`**
- $0.25 < \text{affected\_ratio} < 1.0$ $\longrightarrow$ **`CORRUPTED`**
- $\text{affected\_ratio} = 1.0$ (or unparseable/zero-byte catastrophic failure) $\longrightarrow$ **`SEVERELY_CORRUPTED`**

---

### 5. Status Semantics (Section 27)
- **`HEALTHY`**: File passed all available integrity, signature, and structural checks.
- **`PARTIALLY_CORRUPTED`**: Some structural checks or regions failed, but core structure remains identifiable.
- **`CORRUPTED`**: Definite structural or syntax corruption detected.
- **`SEVERELY_CORRUPTED`**: Critical container failure, parser crash, or 0-byte file.
- **`REPAIRED`**: Format-native repair succeeded and candidate passed independent validation.
- **`RECOVERED`**: Reconstructed from verified reference evidence and passed independent validation.
- **`PARTIALLY_RECOVERED`**: Partial streams or pages salvaged while remaining regions remain unresolved.
- **`UNRECOVERABLE`**: Damage exists but safe reconstruction is impossible without guessing missing bytes.
- **`UNSUPPORTED`**: No repair strategy is safely defined for this format.

---

### 6. Reference Exhibit Matching (Honesty Disclosure)
In the hackathon demonstration workflow, side-by-side comparison with a genuine original exhibit is achieved via a seeded demonstration manifest (`data/demo/manifest.json`).

- When the uploaded evidence's SHA-256 matches a known test pair, ANVAYA displays the authentic reference on the left and the corrupted upload on the right.
- For arbitrary user-uploaded files not in the seeded manifest, **ANVAYA never fabricates or invents a fake original**. The UI clearly announces:  
  *`"Independent original/reference evidence was not available. Displaying uploaded evidence directly."`*

---

### 7. Security Mitigations (Section 32)
1. **Filename Sanitization:** Path traversal sequences (`../`, `..\`), absolute paths, null bytes (`\x00`), and non-alphanumeric characters are stripped.
2. **100 MB Upload Cap:** Uploads above 100 MB are rejected with HTTP 413.
3. **Zip Bomb Protection:** Decompressed size is validated before extracting archives (capped at 500 MB).
4. **XXE Injection Prevention:** Embedded XML in DOCX/XLSX packages is parsed with external entity resolution disabled.
5. **Read-Only SQLite:** SQLite databases are opened strictly in read-only and immutable mode (`?mode=ro&immutable=1`) without extension loading.
6. **Parser Timeout Wrappers:** PDF, ZIP, and binary parsers run within a 15-second hard timeout to prevent engine hangs.

*Production note:* Sandboxed worker containerization and strict per-IP rate limiting are recommended next steps for enterprise deployment.

---

### 8. Installation & Setup

#### Prerequisites
- Python 3.10+
- Node.js 18+ (for Puppeteer browser verification)
- Google Chrome or Microsoft Edge

#### Backend Setup
```bash
# Clone repository
git clone https://github.com/harshavasista/Anvaya.git
cd Anvaya

# Checkout forensic upgrade branch
git checkout anvaya-forensic-upgrade

# Install dependencies
python -m pip install -r requirements.txt
python -m pip install pytest requests

# Generate deterministic demo dataset
python scripts/generate_demo_data.py

# Start Backend Server (runs on http://127.0.0.1:8000)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

#### Frontend Setup
```bash
# In a separate terminal, serve the frontend directory (runs on http://127.0.0.1:5500)
python -m http.server 5500 --directory frontend
```

Interactive API documentation is automatically accessible at:  
`http://127.0.0.1:8000/docs`

---

### 9. Verification & Testing

#### A. Automated Unit Tests (Pytest)
Runs classifier logic, reproducible severity rubric, and recovery validators:
```bash
python -m pytest tests/
```

#### B. End-to-End Headless Browser Verification (Puppeteer)
Runs automated end-to-end tests across real Chrome instances, uploads each demo file, verifies side-by-side iframes, checks for 0 console errors, and captures full-page verification screenshots:
```bash
node scripts/run_browser_verification.js
```

Verification artifacts are saved to:
- `verification/priority-01/` (Healthy PDF Ingestion)
- `verification/priority-02/` (Format Identification for JSON, PNG)
- `verification/priority-03/` (TXT Corruption & Decontamination)
- `verification/priority-04/` (Corrupted PDF Side-by-Side Reference & Restored Render)
- `verification/priority-05/` (Corrupted PDF Without Reference)
- `verification/priority-06/` (JSON Syntax Corruption & Reparse Validation)
- `verification/priority-07/` (Adversarial Zero-Byte Input)
- `verification/final/` (Final Acceptance Demonstration)

---

### 10. Chain of Custody Audit
Every case generates an append-only audit trail at:  
`data/cases/<case_id>/audit/chain_of_custody.jsonl`

Event types include:
`UPLOAD_RECEIVED`, `HASH_COMPUTED`, `ANALYSIS_STARTED`, `CORRUPTION_DETECTED`, `REFERENCE_MATCHED`, `REPAIR_ATTEMPTED`, `REPAIR_CANDIDATE_GENERATED`, `VALIDATION_RUN`, `VALIDATION_RESULT`, `ORIGINAL_HASH_VERIFIED`, `FILE_SERVED`.
