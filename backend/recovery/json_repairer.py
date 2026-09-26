"""
JSON Recovery and Repair Engine for ANVAYA.
Per Section 8:
- Detect syntax truncation, unclosed quotes, missing braces/brackets
- Execute safe, explainable repair rules
- Mandatory re-parsing validation: if reparsing fails, DO NOT call it repaired.
- Compute SHA-256 for recovered candidate
"""

import json
import hashlib
from typing import Dict, Any, Optional, Tuple


def repair_json(damaged_data: bytes, reference_data: Optional[bytes] = None) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """Attempt safe JSON repair and strictly validate by re-parsing."""
    methods_used = []
    messages = []
    candidate_bytes = None

    # Strategy 1: Evidence-backed
    if reference_data:
        try:
            json.loads(reference_data.decode("utf-8"))
            candidate_bytes = reference_data
            methods_used.append("EVIDENCE_BACKED_RECONSTRUCTION")
            messages.append("Restored valid JSON document from genuine reference evidence.")
        except Exception:
            pass

    # Strategy 2: Format-native syntax repair
    if candidate_bytes is None:
        try:
            text = damaged_data.decode("utf-8", errors="replace").strip()
            repaired = text
            methods_used.append("SYNTAX_STRUCTURE_REPAIR")

            # Check for unclosed quote
            quote_count = 0
            for i, c in enumerate(repaired):
                if c == '"' and (i == 0 or repaired[i - 1] != '\\'):
                    quote_count += 1
            if quote_count % 2 != 0:
                repaired += '"'
                messages.append("Closed unterminated string literal.")

            # Strip trailing comma
            repaired = repaired.rstrip()
            if repaired.endswith(","):
                repaired = repaired[:-1].rstrip()
                messages.append("Removed invalid trailing comma.")

            # Balance delimiters using stack
            stack = []
            in_str = False
            for i, c in enumerate(repaired):
                if c == '"' and (i == 0 or repaired[i - 1] != '\\'):
                    in_str = not in_str
                elif not in_str:
                    if c in "{[":
                        stack.append(c)
                    elif c == "}" and stack and stack[-1] == "{":
                        stack.pop()
                    elif c == "]" and stack and stack[-1] == "[":
                        stack.pop()

            while stack:
                top = stack.pop()
                if top == "{":
                    repaired += "\n}"
                    messages.append("Appended missing closing brace '}'.")
                elif top == "[":
                    repaired += "\n]"
                    messages.append("Appended missing closing bracket ']'.")

            candidate_bytes = repaired.encode("utf-8")
        except Exception as e:
            messages.append(f"Native repair attempt error: {str(e)}")

    # VALIDATION: Strictly re-parse
    validation = {
        "status": "VALIDATION_FAILED",
        "valid": False,
        "checks": []
    }

    if candidate_bytes:
        try:
            parsed = json.loads(candidate_bytes.decode("utf-8"))
            validation["valid"] = True
            validation["status"] = "VALIDATED"
            validation["checks"].append({
                "check": "json_reparse",
                "passed": True,
                "details": f"Strict JSON re-parse passed ({len(parsed) if isinstance(parsed, (dict, list)) else 1} top-level items)"
            })
        except Exception as ve:
            validation["valid"] = False
            validation["status"] = "VALIDATION_FAILED"
            validation["checks"].append({
                "check": "json_reparse",
                "passed": False,
                "details": f"Candidate failed re-parse: {str(ve)}"
            })
            candidate_bytes = None
            messages.append("Candidate failed re-parsing. Marked as UNRECOVERABLE.")

    return candidate_bytes, {
        "methods": methods_used,
        "messages": messages,
        "validation": validation,
        "recovered_sha256": hashlib.sha256(candidate_bytes).hexdigest() if candidate_bytes else None
    }
