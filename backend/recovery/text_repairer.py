"""
Text Recovery and Repair Engine for ANVAYA.
Per Section 7:
- Clean null byte contamination and invalid UTF-8 sequences safely
- Preserve genuine surviving textual content
- Re-validate with UTF-8 decoding
- Compute SHA-256 for recovered candidate
"""

import hashlib
from typing import Dict, Any, Optional, Tuple


def repair_text(damaged_data: bytes, reference_data: Optional[bytes] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """Attempt safe text decontamination and UTF-8 validation."""
    methods_used = []
    messages = []
    candidate_bytes = None

    # Strategy 1: Evidence-backed
    if reference_data:
        try:
            reference_data.decode("utf-8")
            candidate_bytes = reference_data
            methods_used.append("EVIDENCE_BACKED_RECONSTRUCTION")
            messages.append("Restored valid text document from genuine reference evidence.")
        except Exception:
            pass

    # Strategy 2: Format-native repair
    if candidate_bytes is None:
        methods_used.append("ENCODING_DECONTAMINATION")
        # Strip null bytes
        cleaned = damaged_data.replace(b"\x00", b"")
        if len(cleaned) < len(damaged_data):
            messages.append(f"Removed {len(damaged_data) - len(cleaned)} contaminating null bytes.")

        # Decode ignoring/replacing invalid sequences, then re-encode as clean UTF-8
        try:
            text = cleaned.decode("utf-8", errors="replace")
            # Replace replacement char with placeholder or clean text
            candidate_bytes = text.encode("utf-8")
            messages.append("Normalized byte stream into valid UTF-8 sequence.")
        except Exception as e:
            messages.append(f"Text normalization error: {str(e)}")

    # VALIDATION
    validation = {
        "status": "VALIDATION_FAILED",
        "valid": False,
        "checks": []
    }

    if candidate_bytes:
        try:
            decoded = candidate_bytes.decode("utf-8")
            validation["valid"] = True
            validation["status"] = "VALIDATED"
            validation["checks"].append({
                "check": "utf8_revalidation",
                "passed": True,
                "details": f"Successfully decoded {len(decoded)} characters as valid UTF-8"
            })
        except Exception as ve:
            validation["valid"] = False
            validation["status"] = "VALIDATION_FAILED"
            validation["checks"].append({
                "check": "utf8_revalidation",
                "passed": False,
                "details": f"Candidate failed UTF-8 validation: {str(ve)}"
            })
            candidate_bytes = None

    return candidate_bytes, {
        "methods": methods_used,
        "messages": messages,
        "validation": validation,
        "recovered_sha256": hashlib.sha256(candidate_bytes).hexdigest() if candidate_bytes else None
    }
