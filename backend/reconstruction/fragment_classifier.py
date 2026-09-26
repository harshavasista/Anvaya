"""
Fragment Classification Module

Classifies fragments into: INTACT, CORRUPTED, MISSING, DUPLICATE
Based on byte analysis, structural validation, and hash comparison.
"""

import hashlib
from collections import Counter
from typing import Dict, List, Any, Optional
from backend.ai.anomaly_detector import calculate_anomaly_score
from backend.validators.file_validators import validate_file


def classify_fragment(
    fragment_data: bytes,
    fragment_info: Dict[str, Any],
    file_type: str,
    all_fragments: List[Dict[str, Any]] = None,
    hash_to_indices: Dict[str, List[int]] = None
) -> Dict[str, Any]:
    """
    Classify a single fragment based on multiple criteria.
    
    Returns classification with detailed reasoning.
    """
    classification = {
        "fragment_id": fragment_info["fragment_id"],
        "filename": fragment_info.get("filename", ""),
        "offset": fragment_info["offset"],
        "size": fragment_info["size"],
        "sha256": fragment_info["sha256"],
        "classification": "UNKNOWN",
        "confidence": 0.0,
        "reasons": [],
        "metrics": {}
    }
    
    # 1. Check for DUPLICATE (based on hash)
    if hash_to_indices and fragment_info["sha256"] in hash_to_indices:
        indices = hash_to_indices[fragment_info["sha256"]]
        if len(indices) > 1:
            classification["classification"] = "DUPLICATE"
            classification["confidence"] = 1.0
            classification["reasons"].append(f"Hash collision with {len(indices)} fragments")
            classification["metrics"]["duplicate_count"] = len(indices)
            classification["metrics"]["duplicate_indices"] = indices
            return classification
    
    # 2. Check for MISSING (empty or all zeros)
    if fragment_info["size"] == 0:
        classification["classification"] = "MISSING"
        classification["confidence"] = 1.0
        classification["reasons"].append("Fragment has zero size")
        return classification
    
    # Calculate metrics
    zero_ratio = fragment_data.count(0) / len(fragment_data) if fragment_data else 1.0
    entropy = calculate_anomaly_score(fragment_data)["entropy"]
    unique_ratio = len(set(fragment_data)) / 256 if fragment_data else 0.0
    
    classification["metrics"] = {
        "zero_ratio": round(zero_ratio, 4),
        "entropy": entropy,
        "unique_ratio": round(unique_ratio, 4)
    }
    
    # 3. Check for MISSING (all zeros/padding)
    if zero_ratio > 0.95:
        classification["classification"] = "MISSING"
        classification["confidence"] = 0.95
        classification["reasons"].append(f"Fragment is {zero_ratio*100:.1f}% zero bytes (likely padding/missing)")
        return classification
    
    # 4. Format-specific structural validation
    format_validation = validate_fragment_structure(fragment_data, fragment_info["offset"], file_type)
    
    # 5. Anomaly detection
    anomaly_result = calculate_anomaly_score(fragment_data)
    anomaly_score = anomaly_result.get("anomaly_score", 0)
    anomaly_status = anomaly_result.get("status", "NORMAL")
    
    # Combine classification logic
    structural_anomalies = format_validation.get("anomalies", [])
    structural_warnings = format_validation.get("warnings", [])
    
    # CORRUPTED if:
    # - High anomaly score
    # - Structural anomalies in format
    # - Suspicious byte patterns (SUSPICIOUS anomaly status)
    is_corrupted = False
    corruption_reasons = []
    
    if anomaly_status == "HIGH_ANOMALY":
        is_corrupted = True
        corruption_reasons.append(f"High anomaly score: {anomaly_score}")
    
    if structural_anomalies:
        is_corrupted = True
        corruption_reasons.extend([f"Structural: {a}" for a in structural_anomalies])
    
    if anomaly_status == "SUSPICIOUS":
        is_corrupted = True
        corruption_reasons.append(f"Suspicious anomaly pattern (score: {anomaly_score})")
        if structural_warnings:
            corruption_reasons.append(f"With warnings: {structural_warnings}")
        if zero_ratio > 0.5:
            corruption_reasons.append(f"High zero ratio: {zero_ratio:.2f}")
    
    # Check for truncated fragment (size < expected and not last fragment)
    expected_size = 4096  # Default fragment size
    if fragment_info["size"] < expected_size and all_fragments:
        # Check if this is the last fragment
        last_fragment = max(all_fragments, key=lambda f: f["offset"])
        if fragment_info["offset"] != last_fragment["offset"]:
            is_corrupted = True
            corruption_reasons.append(f"Truncated fragment ({fragment_info['size']} bytes, expected {expected_size})")
    
    if is_corrupted:
        classification["classification"] = "CORRUPTED"
        classification["confidence"] = min(0.7 + (anomaly_score * 0.3), 0.95)
        classification["reasons"].extend(corruption_reasons)
        classification["metrics"]["anomaly_score"] = anomaly_score
        classification["metrics"]["format_anomalies"] = structural_anomalies
        classification["metrics"]["format_warnings"] = structural_warnings
        return classification
    
    # INTACT if no issues detected
    classification["classification"] = "INTACT"
    classification["confidence"] = 0.9
    classification["reasons"].append("No anomalies detected; fragment structure consistent with file type")
    classification["metrics"]["anomaly_score"] = anomaly_score
    classification["metrics"]["format_anomalies"] = structural_anomalies
    classification["metrics"]["format_warnings"] = structural_warnings
    
    return classification


def validate_fragment_structure(
    fragment_data: bytes,
    offset: int,
    file_type: str
) -> Dict[str, Any]:
    """
    Validate fragment structure based on file type.
    Returns anomalies and warnings specific to the fragment's position.
    """
    result = {"anomalies": [], "warnings": []}
    
    if file_type == "PDF":
        return validate_pdf_fragment(fragment_data, offset)
    elif file_type in ("JPEG", "JPG"):
        return validate_jpeg_fragment(fragment_data, offset)
    elif file_type == "PNG":
        return validate_png_fragment(fragment_data, offset)
    elif file_type == "TXT":
        return validate_txt_fragment(fragment_data, offset)
    elif file_type == "ZIP/DOCX/XLSX":
        return validate_zip_fragment(fragment_data, offset)
    elif file_type == "SQLite":
        return validate_sqlite_fragment(fragment_data, offset)
    else:
        return validate_generic_fragment(fragment_data, offset)


def validate_pdf_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate PDF fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
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
    
    # Check if fragment should contain structural elements based on position
    if offset > 100 and not found_keywords and b"stream" not in fragment_data:
        # Could be pure content stream data - not necessarily anomalous
        pass
    
    if b"/Encrypt" in fragment_data:
        result["warnings"].append("Encryption dictionary found - content analysis limited")
    
    return result


def validate_jpeg_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate JPEG fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"\xFF\xD8\xFF"):
            result["anomalies"].append("Missing JPEG header (FF D8 FF)")
    
    # Check for markers
    if b"\xFF\xD9" in fragment_data:
        # EOF marker found
        pass
    
    return result


def validate_png_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate PNG fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"\x89PNG\r\n\x1a\n"):
            result["anomalies"].append("Missing PNG signature")
    
    if b"IEND" in fragment_data:
        # EOF chunk found
        pass
    
    return result


def validate_txt_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate text fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
    try:
        fragment_data.decode("utf-8")
    except UnicodeDecodeError:
        result["anomalies"].append("Invalid UTF-8 sequence in fragment")
    
    null_count = fragment_data.count(0)
    if null_count > 0:
        result["anomalies"].append(f"Contains {null_count} null bytes")
    
    return result


def validate_zip_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate ZIP fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not (fragment_data.startswith(b"PK\x03\x04") or 
                fragment_data.startswith(b"PK\x05\x06") or 
                fragment_data.startswith(b"PK\x07\x08")):
            result["anomalies"].append("Missing ZIP signature")
    
    return result


def validate_sqlite_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Validate SQLite fragment structure."""
    result = {"anomalies": [], "warnings": []}
    
    if offset == 0:
        if not fragment_data.startswith(b"SQLite format 3\x00"):
            result["anomalies"].append("Missing SQLite header")
    
    return result


def validate_generic_fragment(fragment_data: bytes, offset: int) -> Dict[str, Any]:
    """Generic binary fragment validation."""
    result = {"anomalies": [], "warnings": []}
    
    if len(fragment_data) == 0:
        result["anomalies"].append("Empty fragment")
        return result
    
    counts = Counter(fragment_data)
    length = len(fragment_data)
    
    # Entropy
    import math
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


def classify_all_fragments(
    fragments: List[Dict[str, Any]],
    fragment_dir: str,
    file_type: str
) -> List[Dict[str, Any]]:
    """
    Classify all fragments in a file.
    Returns list of classifications with DUPLICATE detection across all fragments.
    """
    # Build hash index for duplicate detection
    hash_to_indices = {}
    for i, fragment in enumerate(fragments):
        hash_val = fragment["sha256"]
        if hash_val not in hash_to_indices:
            hash_to_indices[hash_val] = []
        hash_to_indices[hash_val].append(i)
    
    # Load fragment data
    fragment_data_map = {}
    for fragment in fragments:
        path = f"{fragment_dir}/{fragment['filename']}"
        try:
            with open(path, "rb") as f:
                fragment_data_map[fragment["fragment_id"]] = f.read()
        except:
            fragment_data_map[fragment["fragment_id"]] = b""
    
    # Classify each fragment
    classifications = []
    for fragment in fragments:
        data = fragment_data_map.get(fragment["fragment_id"], b"")
        classification = classify_fragment(
            data, fragment, file_type, fragments, hash_to_indices
        )
        classifications.append(classification)
    
    return classifications


def get_classification_summary(classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary statistics from fragment classifications."""
    total = len(classifications)
    if total == 0:
        return {"total": 0, "intact": 0, "corrupted": 0, "missing": 0, "duplicate": 0}
    
    counts = {"INTACT": 0, "CORRUPTED": 0, "MISSING": 0, "DUPLICATE": 0, "UNKNOWN": 0}
    for c in classifications:
        cls = c.get("classification", "UNKNOWN")
        if cls in counts:
            counts[cls] += 1
    
    return {
        "total": total,
        "intact": counts["INTACT"],
        "corrupted": counts["CORRUPTED"],
        "missing": counts["MISSING"],
        "duplicate": counts["DUPLICATE"],
        "unknown": counts["UNKNOWN"],
        "intact_percentage": round(counts["INTACT"] / total * 100, 2),
        "corrupted_percentage": round(counts["CORRUPTED"] / total * 100, 2),
        "missing_percentage": round(counts["MISSING"] / total * 100, 2),
        "duplicate_percentage": round(counts["DUPLICATE"] / total * 100, 2)
    }


if __name__ == "__main__":
    import sys
    import os
    
    if len(sys.argv) < 3:
        print("Usage: python fragment_classifier.py <fragment_dir> <file_type>")
        sys.exit(1)
    
    fragment_dir = sys.argv[1]
    file_type = sys.argv[2]
    
    # Load fragments
    fragments = []
    for filename in sorted(os.listdir(fragment_dir)):
        if filename.endswith(".bin"):
            path = os.path.join(fragment_dir, filename)
            with open(path, "rb") as f:
                data = f.read()
            fragment_hash = hashlib.sha256(data).hexdigest()
            fragment_id = filename.replace(".bin", "")
            # Extract fragment number
            try:
                frag_num = int(fragment_id.split("_")[1])
            except:
                frag_num = 0
            fragments.append({
                "fragment_id": fragment_id,
                "filename": filename,
                "offset": frag_num * 4096,
                "size": len(data),
                "sha256": fragment_hash
            })
    
    classifications = classify_all_fragments(fragments, fragment_dir, file_type)
    summary = get_classification_summary(classifications)
    
    print(f"Fragment Classification Summary:")
    print(f"  Total: {summary['total']}")
    print(f"  INTACT: {summary['intact']} ({summary['intact_percentage']}%)")
    print(f"  CORRUPTED: {summary['corrupted']} ({summary['corrupted_percentage']}%)")
    print(f"  MISSING: {summary['missing']} ({summary['missing_percentage']}%)")
    print(f"  DUPLICATE: {summary['duplicate']} ({summary['duplicate_percentage']}%)")
    print()
    
    for c in classifications:
        print(f"{c['fragment_id']}: {c['classification']} (confidence: {c['confidence']:.2f})")
        for reason in c['reasons']:
            print(f"  - {reason}")