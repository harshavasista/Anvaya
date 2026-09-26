import hashlib
import math
import os
from typing import List, Dict, Any
from backend.validators.file_validators import validate_file


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in frequency:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def analyze_fragments(file_path: str, fragment_size: int = 4096) -> List[Dict[str, Any]]:
    """
    Split a file into fragments and analyze each fragment.
    Returns list of fragment info dicts with basic metadata.
    """
    fragments = []
    with open(file_path, "rb") as file:
        offset = 0
        fragment_number = 1
        while True:
            data = file.read(fragment_size)
            if not data:
                break
            fragment_hash = hashlib.sha256(data).hexdigest()
            entropy = calculate_entropy(data)
            fragment = {
                "fragment_id": f"fragment_{fragment_number:04d}",
                "offset": offset,
                "size": len(data),
                "sha256": fragment_hash,
                "entropy": entropy
            }
            fragments.append(fragment)
            offset += len(data)
            fragment_number += 1
    return fragments


def analyze_fragment_standalone(fragment_data: bytes, fragment_info: dict, file_type: str, file_data: bytes = None) -> dict:
    """
    Analyze a single fragment with format-specific checks.
    Returns comprehensive analysis with new classification system.
    """
    from backend.ai.anomaly_detector import calculate_anomaly_score
    from backend.validators.file_validators import (
        validate_pdf, validate_jpeg, validate_png, 
        validate_txt, validate_zip, validate_sqlite, validate_generic_binary
    )
    
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
    else:
        format_analysis = validate_generic_binary(fragment_data)
    
    # Determine status
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
    """Classify fragment as OBSERVED/INTACT, SUSPECTED/ANOMALOUS, or UNKNOWN/UNRECOVERABLE."""
    anomaly_score = anomaly_result.get("anomaly_score", 0)
    anomaly_status = anomaly_result.get("status", "NORMAL")
    zero_ratio = anomaly_result.get("zero_ratio", 0)
    
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
    if zero_ratio > 0.95:
        return "UNKNOWN / UNRECOVERABLE"
    
    return "OBSERVED / INTACT"


def analyze_pdf_fragment(fragment_data: bytes, offset: int, file_data: bytes = None) -> dict:
    """Analyze a fragment in context of PDF structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"%PDF"):
            result["anomalies"].append("Missing PDF header at offset 0")
        else:
            for line in fragment_data[:100].split(b"\n"):
                if line.startswith(b"%PDF-"):
                    try:
                        version = float(line[5:].decode().strip())
                        if version < 1.0 or version > 2.0:
                            result["warnings"].append(f"Unusual PDF version: {version}")
                    except:
                        pass
                    break
    
    structural_keywords = [b"xref", b"trailer", b"startxref", b"obj", b"endobj", b"stream", b"endstream"]
    found_keywords = [kw for kw in structural_keywords if kw in fragment_data]
    
    if offset > 100 and not found_keywords:
        result["warnings"].append("No PDF structural elements found in fragment")
    
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
    
    return result


def analyze_text_fragment(fragment_data: bytes, offset: int) -> dict:
    """Analyze a fragment in context of text file."""
    result = {"anomalies": [], "warnings": []}
    
    try:
        fragment_data.decode("utf-8")
    except UnicodeDecodeError:
        result["anomalies"].append("Invalid UTF-8 sequence in fragment")
    
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


def validate_generic_binary(fragment_data: bytes) -> dict:
    """Generic binary fragment analysis."""
    from collections import Counter
    import math
    
    result = {"anomalies": [], "warnings": []}
    
    if len(fragment_data) == 0:
        result["anomalies"].append("Empty fragment")
        return result
    
    counts = Counter(fragment_data)
    length = len(fragment_data)
    
    # Entropy
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    
    if entropy > 7.95:
        result["anomalies"].append("Very high entropy / random-looking data")
    elif entropy < 1.0:
        result["anomalies"].append("Very low entropy / highly repetitive data")
    
    # Zero ratio
    zero_bytes = fragment_data.count(0)
    zero_ratio = zero_bytes / length
    if zero_ratio > 0.5:
        result["anomalies"].append("Large proportion of zero-filled bytes")
    
    # Unique byte ratio
    unique_ratio = len(counts) / 256
    if unique_ratio < 0.1:
        result["anomalies"].append("Very low byte diversity")
    
    return result


def build_reasoning(anomaly_result: dict, format_analysis: dict, status: str) -> list:
    """Build explainable reasoning for fragment classification."""
    reasons = []
    
    for reason in anomaly_result.get("reasons", []):
        reasons.append(f"WHAT: {reason}")
    
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


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        fragments = analyze_fragments(sys.argv[1])
        for f in fragments[:5]:
            print(f)