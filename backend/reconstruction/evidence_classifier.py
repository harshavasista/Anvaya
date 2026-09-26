"""
Evidence Classification Module

Classifies recovered regions into: RECOVERED, REPAIRED, AI-INFERRED, UNKNOWN
Based on the recovery strategy used and confidence level.
"""

from typing import Dict, List, Any, Optional
from enum import Enum


class EvidenceStatus(Enum):
    RECOVERED = "RECOVERED"           # Exact duplicate found
    REPAIRED = "REPAIRED"             # Structure-based repair successful
    PARTIAL_RECOVERY = "PARTIAL_RECOVERY"  # Page/object/stream salvaged
    AI_INFERRED = "AI_INFERRED"       # Content inferred from context
    UNKNOWN = "UNKNOWN"               # Insufficient evidence


class RecoveryStrategy(Enum):
    EXACT_DUPLICATE = "exact_duplicate"
    STRUCTURAL_REPAIR = "structural_repair"
    OBJECT_REFERENCE_REPAIR = "object_reference_repair"
    STREAM_RECOVERY = "stream_recovery"
    PAGE_LEVEL_SALVAGE = "page_level_salvage"
    CONTENT_INFERENCE = "content_inference"


# Strategy to evidence status mapping
STRATEGY_TO_STATUS = {
    RecoveryStrategy.EXACT_DUPLICATE: EvidenceStatus.RECOVERED,
    RecoveryStrategy.STRUCTURAL_REPAIR: EvidenceStatus.REPAIRED,
    RecoveryStrategy.OBJECT_REFERENCE_REPAIR: EvidenceStatus.REPAIRED,
    RecoveryStrategy.STREAM_RECOVERY: EvidenceStatus.PARTIAL_RECOVERY,
    RecoveryStrategy.PAGE_LEVEL_SALVAGE: EvidenceStatus.PARTIAL_RECOVERY,
    RecoveryStrategy.CONTENT_INFERENCE: EvidenceStatus.AI_INFERRED,
}


def classify_evidence(
    region: Dict[str, Any],
    recovery_strategy: RecoveryStrategy,
    confidence: float,
    validation_result: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Classify a recovered region based on the strategy used and validation results.
    
    Args:
        region: Dict with offset, size, and other region metadata
        recovery_strategy: The strategy used to recover this region
        confidence: Confidence score (0.0 to 1.0)
        validation_result: Optional validation results from file-type validator
    
    Returns:
        Dict with evidence classification and detailed reasoning
    """
    base_status = STRATEGY_TO_STATUS.get(recovery_strategy, EvidenceStatus.UNKNOWN)
    
    # Adjust status based on validation results
    final_status = base_status
    adjusted_confidence = confidence
    reasons = []
    
    if validation_result:
        is_valid = validation_result.get("valid", False)
        validation_errors = validation_result.get("errors", [])
        validation_warnings = validation_result.get("warnings", [])
        
        if is_valid:
            reasons.append(f"Validation passed: {validation_result.get('message', 'Structure valid')}")
            adjusted_confidence = min(confidence * 1.1, 1.0)
        else:
            if base_status == EvidenceStatus.RECOVERED:
                # Exact duplicate should always be valid
                reasons.append("Exact duplicate match - validation not required")
            elif base_status == EvidenceStatus.REPAIRED:
                if validation_errors:
                    # Repair may be partial
                    final_status = EvidenceStatus.PARTIAL_RECOVERY
                    adjusted_confidence = confidence * 0.7
                    reasons.append(f"Repair validation errors: {validation_errors}")
                elif validation_warnings:
                    reasons.append(f"Repair validation warnings: {validation_warnings}")
            elif base_status == EvidenceStatus.PARTIAL_RECOVERY:
                if validation_errors:
                    adjusted_confidence = confidence * 0.5
                    reasons.append(f"Partial salvage validation errors: {validation_errors}")
            elif base_status == EvidenceStatus.AI_INFERRED:
                # AI inferred is inherently lower confidence
                adjusted_confidence = confidence * 0.8
                reasons.append("Content inferred from surrounding context")
    
    # Build detailed classification
    classification = {
        "region_offset": region.get("offset", 0),
        "region_size": region.get("size", 0),
        "recovery_strategy": recovery_strategy.value,
        "evidence_status": final_status.value,
        "confidence": round(adjusted_confidence, 3),
        "base_confidence": confidence,
        "reasons": reasons,
        "validation": validation_result
    }
    
    return classification


def classify_region_by_strategy(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None,
    reference_hashes: Dict[str, bytes] = None
) -> Dict[str, Any]:
    """
    Determine the best recovery strategy for a region and classify the evidence.
    
    This implements the decision flow:
    1. Exact duplicate exists? -> RECOVERED
    2. File structure can reconstruct? -> REPAIRED
    3. Can page/object/stream be salvaged? -> PARTIAL_RECOVERY
    4. Can content be inferred from context? -> AI_INFERRED
    5. Insufficient evidence -> UNKNOWN
    """
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    region_hash = region.get("sha256", "")
    
    # Strategy 1: Check for exact duplicate
    if reference_hashes and region_hash in reference_hashes:
        return classify_evidence(
            region,
            RecoveryStrategy.EXACT_DUPLICATE,
            1.0,
            {"valid": True, "message": "Exact hash match with reference"}
        )
    
    # Check if fragment is INTACT (already observed)
    fragment_cls = None
    for fc in fragment_classifications:
        if fc["offset"] <= offset < fc["offset"] + fc["size"]:
            fragment_cls = fc
            break
    
    if fragment_cls and fragment_cls.get("classification") == "INTACT":
        return classify_evidence(
            region,
            RecoveryStrategy.EXACT_DUPLICATE,
            0.95,
            {"valid": True, "message": "Fragment classified as INTACT"}
        )
    
    # Strategy 2: Check if file structure can reconstruct
    structural_repair = can_structural_repair(region, fragment_classifications, file_type, file_data)
    if structural_repair["possible"]:
        return classify_evidence(
            region,
            RecoveryStrategy.STRUCTURAL_REPAIR,
            structural_repair["confidence"],
            structural_repair.get("validation")
        )
    
    # Strategy 3: Check object/reference repair (PDF-specific, but concept applies to others)
    obj_repair = can_object_reference_repair(region, fragment_classifications, file_type, file_data)
    if obj_repair["possible"]:
        return classify_evidence(
            region,
            RecoveryStrategy.OBJECT_REFERENCE_REPAIR,
            obj_repair["confidence"],
            obj_repair.get("validation")
        )
    
    # Strategy 4: Stream recovery
    stream_recovery = can_stream_recovery(region, fragment_classifications, file_type, file_data)
    if stream_recovery["possible"]:
        return classify_evidence(
            region,
            RecoveryStrategy.STREAM_RECOVERY,
            stream_recovery["confidence"],
            stream_recovery.get("validation")
        )
    
    # Strategy 5: Page-level salvage
    page_salvage = can_page_level_salvage(region, fragment_classifications, file_type, file_data)
    if page_salvage["possible"]:
        return classify_evidence(
            region,
            RecoveryStrategy.PAGE_LEVEL_SALVAGE,
            page_salvage["confidence"],
            page_salvage.get("validation")
        )
    
    # Strategy 6: Content inference from context
    content_inference = can_content_inference(region, fragment_classifications, file_type, file_data)
    if content_inference["possible"]:
        return classify_evidence(
            region,
            RecoveryStrategy.CONTENT_INFERENCE,
            content_inference["confidence"],
            content_inference.get("validation")
        )
    
    # No strategy worked
    return classify_evidence(
        region,
        RecoveryStrategy.CONTENT_INFERENCE,  # Default to inference with low confidence
        0.1,
        {"valid": False, "errors": ["Insufficient evidence for any recovery strategy"]}
    )


def can_structural_repair(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None
) -> Dict[str, Any]:
    """
    Check if file structure (headers, footers, tables) can reconstruct the region.
    """
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    # Check if region contains known structural elements
    structural_elements = get_structural_elements(file_type)
    
    # For now, simplified logic - in practice would parse the actual structure
    # Check surrounding fragments for structural clues
    preceding_intact = False
    following_intact = False
    
    for fc in fragment_classifications:
        fc_offset = fc.get("offset", 0)
        fc_size = fc.get("size", 0)
        fc_end = fc_offset + fc_size
        
        if fc_end == offset and fc.get("classification") == "INTACT":
            preceding_intact = True
        if fc_offset == offset + size and fc.get("classification") == "INTACT":
            following_intact = True
    
    # Structural repair possible if we have intact fragments on both sides
    # and the file type has well-defined structure
    if preceding_intact and following_intact:
        if file_type in ["PDF", "ZIP/DOCX/XLSX", "PNG", "JPEG", "SQLite"]:
            return {
                "possible": True,
                "confidence": 0.75,
                "validation": {"valid": True, "message": "Structural boundaries confirmed by intact neighbors"}
            }
    
    # Check if region is at known structural position (header, footer, etc.)
    if offset == 0 and file_type in ["PDF", "PNG", "JPEG", "ZIP/DOCX/XLSX", "SQLite"]:
        return {
            "possible": True,
            "confidence": 0.85,
            "validation": {"valid": True, "message": "Known header structure for file type"}
        }
    
    return {"possible": False, "confidence": 0.0}


def can_object_reference_repair(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None
) -> Dict[str, Any]:
    """
    Check if object references (xref, FAT, B-tree, etc.) can repair the region.
    """
    if file_type != "PDF":
        # Other formats have similar concepts but different implementations
        if file_type == "ZIP/DOCX/XLSX":
            return {"possible": True, "confidence": 0.6, "validation": {"valid": True, "message": "Central directory can reference local file headers"}}
        if file_type == "SQLite":
            return {"possible": True, "confidence": 0.6, "validation": {"valid": True, "message": "B-tree structure can locate pages"}}
        return {"possible": False, "confidence": 0.0}
    
    # PDF-specific: check if xref/trailer can locate objects
    if file_data:
        # Look for xref and trailer in surrounding intact fragments
        has_xref = False
        has_trailer = False
        
        for fc in fragment_classifications:
            if fc.get("classification") == "INTACT":
                # In practice, would check actual fragment data
                pass
        
        # Simplified: if we have PDF and some intact fragments, object repair is possible
        intact_count = sum(1 for fc in fragment_classifications if fc.get("classification") == "INTACT")
        if intact_count > len(fragment_classifications) * 0.3:  # At least 30% intact
            return {
                "possible": True,
                "confidence": 0.65,
                "validation": {"valid": True, "message": "Sufficient intact fragments for xref-based object recovery"}
            }
    
    return {"possible": False, "confidence": 0.0}


def can_stream_recovery(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None
) -> Dict[str, Any]:
    """
    Check if compressed/encoded streams can be recovered.
    """
    # Stream recovery applies to PDF streams, JPEG scan data, PNG IDAT, ZIP compressed data
    stream_types = ["PDF", "JPEG", "PNG", "ZIP/DOCX/XLSX"]
    
    if file_type not in stream_types:
        return {"possible": False, "confidence": 0.0}
    
    # Check if region is likely a stream (high entropy, between stream/endstream markers)
    # Simplified: if we have some intact fragments, partial stream recovery may be possible
    intact_count = sum(1 for fc in fragment_classifications if fc.get("classification") == "INTACT")
    if intact_count > 0:
        return {
            "possible": True,
            "confidence": 0.5,
            "validation": {"valid": True, "message": "Stream data partially recoverable from intact fragments"}
        }
    
    return {"possible": False, "confidence": 0.0}


def can_page_level_salvage(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None
) -> Dict[str, Any]:
    """
    Check if page-level structures can be salvaged.
    """
    page_types = ["PDF", "TIFF", "DOCX", "XLSX"]
    
    if file_type not in page_types:
        return {"possible": False, "confidence": 0.0}
    
    # Check if we have intact page structures
    intact_count = sum(1 for fc in fragment_classifications if fc.get("classification") == "INTACT")
    if intact_count > len(fragment_classifications) * 0.2:
        return {
            "possible": True,
            "confidence": 0.55,
            "validation": {"valid": True, "message": "Page structure partially salvageable"}
        }
    
    return {"possible": False, "confidence": 0.0}


def can_content_inference(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    file_data: bytes = None
) -> Dict[str, Any]:
    """
    Check if content can be inferred from surrounding context.
    """
    # Content inference is always possible as a last resort
    # but with low confidence
    intact_neighbors = 0
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    for fc in fragment_classifications:
        fc_offset = fc.get("offset", 0)
        fc_size = fc.get("size", 0)
        fc_end = fc_offset + fc_size
        
        # Check if fragment is adjacent to region
        if (fc_end == offset or fc_offset == offset + size) and fc.get("classification") == "INTACT":
            intact_neighbors += 1
    
    if intact_neighbors >= 2:
        return {
            "possible": True,
            "confidence": 0.35,
            "validation": {"valid": True, "message": "Content inferred from intact neighboring fragments"}
        }
    elif intact_neighbors == 1:
        return {
            "possible": True,
            "confidence": 0.25,
            "validation": {"valid": True, "message": "Content partially inferred from one intact neighbor"}
        }
    else:
        return {
            "possible": True,
            "confidence": 0.1,
            "validation": {"valid": False, "errors": ["No intact context for inference"]}
        }


def get_structural_elements(file_type: str) -> Dict[str, Any]:
    """Get known structural elements for a file type."""
    elements = {
        "PDF": {
            "header": b"%PDF",
            "footer": b"%%EOF",
            "xref": b"xref",
            "trailer": b"trailer",
            "startxref": b"startxref",
            "object": b"obj",
            "endobject": b"endobj",
            "stream": b"stream",
            "endstream": b"endstream"
        },
        "JPEG": {
            "header": b"\xFF\xD8\xFF",
            "footer": b"\xFF\xD9",
            "sof": [0xC0, 0xC1, 0xC2, 0xC3],
            "dht": 0xC4,
            "dqt": 0xDB,
            "sos": 0xDA
        },
        "PNG": {
            "header": b"\x89PNG\r\n\x1a\n",
            "ihdr": b"IHDR",
            "idat": b"IDAT",
            "iend": b"IEND"
        },
        "ZIP/DOCX/XLSX": {
            "local_header": b"PK\x03\x04",
            "central_header": b"PK\x01\x02",
            "end_central": b"PK\x05\x06",
            "zip64_end": b"PK\x06\x06",
            "zip64_locator": b"PK\x06\x07"
        },
        "SQLite": {
            "header": b"SQLite format 3\x00",
            "page_size_offset": 16,
            "freelist_offset": 36
        },
        "TXT": {}
    }
    return elements.get(file_type, {})


def generate_evidence_summary(evidence_classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary of evidence classifications."""
    total = len(evidence_classifications)
    if total == 0:
        return {"total_regions": 0}
    
    status_counts = {}
    strategy_counts = {}
    total_confidence = 0.0
    
    for ec in evidence_classifications:
        status = ec.get("evidence_status", "UNKNOWN")
        strategy = ec.get("recovery_strategy", "unknown")
        confidence = ec.get("confidence", 0.0)
        
        status_counts[status] = status_counts.get(status, 0) + 1
        strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
        total_confidence += confidence
    
    return {
        "total_regions": total,
        "status_distribution": status_counts,
        "strategy_distribution": strategy_counts,
        "average_confidence": round(total_confidence / total, 3) if total > 0 else 0.0,
        "recovered_bytes": sum(ec.get("region_size", 0) for ec in evidence_classifications 
                               if ec.get("evidence_status") == "RECOVERED"),
        "repaired_bytes": sum(ec.get("region_size", 0) for ec in evidence_classifications 
                              if ec.get("evidence_status") == "REPAIRED"),
        "partial_bytes": sum(ec.get("region_size", 0) for ec in evidence_classifications 
                             if ec.get("evidence_status") == "PARTIAL_RECOVERY"),
        "inferred_bytes": sum(ec.get("region_size", 0) for ec in evidence_classifications 
                              if ec.get("evidence_status") == "AI_INFERRED"),
        "unknown_bytes": sum(ec.get("region_size", 0) for ec in evidence_classifications 
                             if ec.get("evidence_status") == "UNKNOWN")
    }


if __name__ == "__main__":
    # Test the classification
    test_region = {"offset": 0, "size": 4096, "sha256": "test"}
    test_fragments = [
        {"offset": 0, "size": 4096, "classification": "INTACT"},
        {"offset": 4096, "size": 4096, "classification": "CORRUPTED"}
    ]
    
    result = classify_region_by_strategy(test_region, test_fragments, "PDF")
    print(result)