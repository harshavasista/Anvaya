import math
from collections import Counter
from typing import Dict, Any


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def calculate_zero_ratio(data: bytes) -> float:
    """Calculate the percentage of zero bytes."""
    if not data:
        return 0.0
    zero_bytes = data.count(0)
    return round(zero_bytes / len(data), 4)


def calculate_unique_ratio(data: bytes) -> float:
    """Calculate how diverse the bytes are."""
    if not data:
        return 0.0
    return round(len(set(data)) / 256, 4)


def calculate_anomaly_score(data: bytes, file_type: str = None) -> Dict[str, Any]:
    """
    Calculate an explainable anomaly score with format-aware analysis.
    
    This is an AI-assisted heuristic score,
    not a trained machine-learning prediction.
    """
    entropy = calculate_entropy(data)
    zero_ratio = calculate_zero_ratio(data)
    unique_ratio = calculate_unique_ratio(data)
    
    score = 0.0
    reasons = []
    
    # ------------------------------------------
    # Entropy analysis
    # ------------------------------------------
    if entropy < 1.0:
        score += 0.25
        reasons.append("Very low entropy / highly repetitive data")
    elif entropy > 7.95:
        score += 0.10
        reasons.append("Very high entropy / random-looking data")
    
    # ------------------------------------------
    # Zero-byte analysis
    # ------------------------------------------
    if zero_ratio > 0.50:
        score += 0.45
        reasons.append("Large proportion of zero-filled bytes")
    elif zero_ratio > 0.20:
        score += 0.20
        reasons.append("Elevated zero-byte concentration")
    
    # ------------------------------------------
    # Byte diversity
    # ------------------------------------------
    if unique_ratio < 0.10:
        score += 0.25
        reasons.append("Very low byte diversity")
    
    # Limit score to 1.0
    score = min(score, 1.0)
    
    # ------------------------------------------
    # Classification
    # ------------------------------------------
    if score >= 0.60:
        status = "HIGH_ANOMALY"
    elif score >= 0.30:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"
    
    return {
        "anomaly_score": round(score, 2),
        "status": status,
        "entropy": entropy,
        "zero_ratio": zero_ratio,
        "unique_byte_ratio": unique_ratio,
        "reasons": reasons
    }


def analyze_fragment(fragment_path: str, file_type: str = None) -> Dict[str, Any]:
    """Analyze a fragment file with optional file-type context."""
    with open(fragment_path, "rb") as f:
        data = f.read()
    result = calculate_anomaly_score(data, file_type)
    result["fragment"] = fragment_path
    result["size"] = len(data)
    return result


def analyze_fragment_with_context(fragment_data: bytes, fragment_info: dict, file_type: str, full_file_data: bytes = None) -> Dict[str, Any]:
    """
    Analyze fragment with format-specific context.
    This is the enhanced version used by the standalone analysis pipeline.
    """
    # Get base anomaly score
    base_result = calculate_anomaly_score(fragment_data, file_type)
    
    # Add format-specific context
    context_anomalies = []
    context_warnings = []
    
    offset = fragment_info.get("offset", 0)
    
    if file_type == "PDF":
        context = analyze_pdf_context(fragment_data, offset, full_file_data)
        context_anomalies.extend(context.get("anomalies", []))
        context_warnings.extend(context.get("warnings", []))
    elif file_type in ("JPEG", "PNG"):
        context = analyze_image_context(fragment_data, offset, file_type)
        context_anomalies.extend(context.get("anomalies", []))
        context_warnings.extend(context.get("warnings", []))
    elif file_type == "TXT":
        context = analyze_text_context(fragment_data, offset)
        context_anomalies.extend(context.get("anomalies", []))
        context_warnings.extend(context.get("warnings", []))
    elif file_type == "ZIP/DOCX/XLSX":
        context = analyze_zip_context(fragment_data, offset)
        context_anomalies.extend(context.get("anomalies", []))
        context_warnings.extend(context.get("warnings", []))
    elif file_type == "SQLite":
        context = analyze_sqlite_context(fragment_data, offset)
        context_anomalies.extend(context.get("anomalies", []))
        context_warnings.extend(context.get("warnings", []))
    
    # Adjust score based on context
    adjusted_score = base_result["anomaly_score"]
    adjusted_reasons = list(base_result["reasons"])
    
    # Structural anomalies add to score
    if context_anomalies:
        adjusted_score = min(adjusted_score + 0.3 * len(context_anomalies), 1.0)
        adjusted_reasons.extend(context_anomalies)
    
    # Warnings add slightly
    if context_warnings:
        adjusted_score = min(adjusted_score + 0.15 * len(context_warnings), 1.0)
        adjusted_reasons.extend(context_warnings)
    
    # Reclassify
    if adjusted_score >= 0.60:
        status = "HIGH_ANOMALY"
    elif adjusted_score >= 0.30:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"
    
    return {
        "anomaly_score": round(adjusted_score, 2),
        "status": status,
        "entropy": base_result["entropy"],
        "zero_ratio": base_result["zero_ratio"],
        "unique_byte_ratio": base_result["unique_byte_ratio"],
        "reasons": adjusted_reasons,
        "context_anomalies": context_anomalies,
        "context_warnings": context_warnings
    }


def analyze_pdf_context(fragment_data: bytes, offset: int, full_file_data: bytes = None) -> Dict[str, Any]:
    """Analyze fragment in PDF context."""
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


def analyze_image_context(fragment_data: bytes, offset: int, file_type: str) -> Dict[str, Any]:
    """Analyze fragment in image context."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if file_type == "JPEG":
            if not fragment_data.startswith(b"\xFF\xD8\xFF"):
                result["anomalies"].append("Missing JPEG header (FF D8 FF)")
        elif file_type == "PNG":
            if not fragment_data.startswith(b"\x89PNG\r\n\x1a\n"):
                result["anomalies"].append("Missing PNG signature")
    
    return result


def analyze_text_context(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Analyze fragment in text context."""
    result = {"anomalies": [], "warnings": []}
    
    try:
        fragment_data.decode("utf-8")
    except UnicodeDecodeError:
        result["anomalies"].append("Invalid UTF-8 sequence in fragment")
    
    null_count = fragment_data.count(0)
    if null_count > 0:
        result["anomalies"].append(f"Contains {null_count} null bytes")
    
    return result


def analyze_zip_context(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Analyze fragment in ZIP context."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not (fragment_data.startswith(b"PK\x03\x04") or 
                fragment_data.startswith(b"PK\x05\x06") or 
                fragment_data.startswith(b"PK\x07\x08")):
            result["anomalies"].append("Missing ZIP signature")
    
    return result


def analyze_sqlite_context(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Analyze fragment in SQLite context."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"SQLite format 3\x00"):
            result["anomalies"].append("Missing SQLite header")
    
    return result


if __name__ == "__main__":
    import os
    import sys
    
    if len(sys.argv) > 1:
        fragment_dir = sys.argv[1]
    else:
        fragment_dir = "data/fragments"
    
    print()
    print("ANVAYA AI-ASSISTED ANOMALY ANALYSIS")
    print("===================================")
    
    if not os.path.exists(fragment_dir):
        print("Fragment directory not found.")
        raise SystemExit
    
    files = [
        file
        for file in os.listdir(fragment_dir)
        if file.endswith(".bin")
    ]
    
    print(f"Fragments analyzed: {len(files)}")
    print()
    
    for filename in files[:10]:
        path = os.path.join(fragment_dir, filename)
        result = analyze_fragment(path)
        print(
            f"{filename} | "
            f"Score: {result['anomaly_score']} | "
            f"Status: {result['status']} | "
            f"Entropy: {result['entropy']}"
        )
        if result["reasons"]:
            print(
                "  Reason:",
                "; ".join(result["reasons"])
            )