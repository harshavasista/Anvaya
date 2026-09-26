"""
Tamper-Evident Chain-of-Custody Audit Logger for ANVAYA.
Per Section 31, records append-only JSONL entries for every forensic event.
"""

import json
import os
from datetime import datetime
from typing import Optional, Dict, Any


VALID_EVENTS = {
    "UPLOAD_RECEIVED",
    "HASH_COMPUTED",
    "ANALYSIS_STARTED",
    "CORRUPTION_DETECTED",
    "REFERENCE_MATCHED",
    "REPAIR_ATTEMPTED",
    "REPAIR_CANDIDATE_GENERATED",
    "VALIDATION_RUN",
    "VALIDATION_RESULT",
    "FILE_SERVED",
    "ORIGINAL_HASH_VERIFIED"
}


def log_custody_event(
    case_dir: str,
    case_id: str,
    event: str,
    detail: str,
    sha256: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Append a single verified audit event to chain_of_custody.jsonl."""
    audit_dir = os.path.join(case_dir, "audit")
    os.makedirs(audit_dir, exist_ok=True)
    log_path = os.path.join(audit_dir, "chain_of_custody.jsonl")

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "case_id": case_id,
        "event": event,
        "detail": detail
    }
    if sha256:
        entry["sha256"] = sha256
    if extra:
        entry["extra"] = extra

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return entry
