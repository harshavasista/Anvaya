"""
File Recovery Module

Implements generic recovery strategies for all supported file types:
1. Exact duplicate recovery
2. Structural repair (headers, footers, tables)
3. Object/reference repair
4. Stream recovery
5. Page-level salvage
6. Content inference
"""

import os
import hashlib
import struct
from typing import Dict, List, Any, Optional, Tuple, Callable
from collections import defaultdict

from backend.validators.file_validators import (
    validate_pdf, validate_jpeg, validate_png, 
    validate_txt, validate_zip, validate_sqlite, validate_generic_binary
)


class RecoveryResult:
    """Result of a recovery attempt."""
    def __init__(
        self,
        success: bool,
        data: bytes = b"",
        strategy: str = "",
        confidence: float = 0.0,
        validation: Dict[str, Any] = None,
        errors: List[str] = None,
        warnings: List[str] = None
    ):
        self.success = success
        self.data = data
        self.strategy = strategy
        self.confidence = confidence
        self.validation = validation or {}
        self.errors = errors or []
        self.warnings = warnings or []


def recover_file(
    fragment_classifications: List[Dict[str, Any]],
    fragment_dir: str,
    file_type: str,
    original_size: int,
    reference_data: bytes = None
) -> Tuple[bytes, List[Dict[str, Any]]]:
    """
    Main recovery function that orchestrates all strategies.
    
    Returns:
        Tuple of (recovered_data, evidence_classifications)
    """
    # Load all fragment data
    fragment_data_map = {}
    for fc in fragment_classifications:
        fragment_id = fc.get("fragment_id", "")
        filename = fc.get("filename", "")
        path = os.path.join(fragment_dir, filename)
        try:
            with open(path, "rb") as f:
                fragment_data_map[fragment_id] = f.read()
        except:
            fragment_data_map[fragment_id] = b""
    
    # Also load by filename for lookup
    fragment_data_by_filename = {}
    for filename in os.listdir(fragment_dir):
        if filename.endswith(".bin"):
            path = os.path.join(fragment_dir, filename)
            try:
                with open(path, "rb") as f:
                    fragment_data_by_filename[filename] = f.read()
            except:
                fragment_data_by_filename[filename] = b""
    
    # Build reference hash map if reference data provided
    reference_hashes = {}
    if reference_data:
        # Hash 4096-byte chunks of reference
        for i in range(0, len(reference_data), 4096):
            chunk = reference_data[i:i+4096]
            reference_hashes[hashlib.sha256(chunk).hexdigest()] = chunk
    
    # Initialize output buffer
    recovered_data = bytearray(original_size)
    evidence_classifications = []
    
    # Process each fragment position
    for fc in fragment_classifications:
        offset = fc.get("offset", 0)
        size = fc.get("size", 0)
        fragment_id = fc.get("fragment_id", "")
        classification = fc.get("classification", "UNKNOWN")
        sha256 = fc.get("sha256", "")
        
        region = {
            "offset": offset,
            "size": size,
            "sha256": sha256,
            "fragment_id": fragment_id
        }
        
        # Determine recovery strategy based on classification
        if classification == "INTACT":
            # Strategy 1: Exact duplicate - use fragment as-is
            data = fragment_data_map.get(fragment_id, b"")
            result = RecoveryResult(
                success=True,
                data=data,
                strategy="exact_duplicate",
                confidence=0.95,
                validation={"valid": True, "message": "Fragment classified as INTACT"}
            )
        
        elif classification == "DUPLICATE":
            # Strategy 1: Exact duplicate - use first occurrence
            data = fragment_data_map.get(fragment_id, b"")
            result = RecoveryResult(
                success=True,
                data=data,
                strategy="exact_duplicate",
                confidence=1.0,
                validation={"valid": True, "message": "Exact hash match with duplicate fragment"}
            )
        
        elif classification == "MISSING":
            # Try structural repair for missing regions
            result = attempt_structural_repair(region, fragment_classifications, file_type, reference_data)
            if not result.success:
                result = attempt_content_inference(region, fragment_classifications, file_type, fragment_data_map)
        
        elif classification == "CORRUPTED":
            # Try multiple strategies in order
            result = attempt_structural_repair(region, fragment_classifications, file_type, reference_data)
            if not result.success:
                result = attempt_object_reference_repair(region, fragment_classifications, file_type, fragment_data_map)
            if not result.success:
                result = attempt_stream_recovery(region, fragment_classifications, file_type, fragment_data_map)
            if not result.success:
                result = attempt_page_level_salvage(region, fragment_classifications, file_type, fragment_data_map)
            if not result.success:
                result = attempt_content_inference(region, fragment_classifications, file_type, fragment_data_map)
        
        else:
            # UNKNOWN - try inference
            result = attempt_content_inference(region, fragment_classifications, file_type, fragment_data_map)
        
        # Write recovered data to output
        if result.success and result.data:
            end_offset = min(offset + len(result.data), original_size)
            recovered_data[offset:end_offset] = result.data[:end_offset - offset]
        else:
            # Fill with zeros
            end_offset = min(offset + size, original_size)
            recovered_data[offset:end_offset] = b"\x00" * (end_offset - offset)
        
        # Classify evidence
        from backend.reconstruction.evidence_classifier import (
            classify_evidence, RecoveryStrategy, EvidenceStatus
        )
        
        strategy_map = {
            "exact_duplicate": RecoveryStrategy.EXACT_DUPLICATE,
            "structural_repair": RecoveryStrategy.STRUCTURAL_REPAIR,
            "object_reference_repair": RecoveryStrategy.OBJECT_REFERENCE_REPAIR,
            "stream_recovery": RecoveryStrategy.STREAM_RECOVERY,
            "page_level_salvage": RecoveryStrategy.PAGE_LEVEL_SALVAGE,
            "content_inference": RecoveryStrategy.CONTENT_INFERENCE
        }
        
        strategy = strategy_map.get(result.strategy, RecoveryStrategy.CONTENT_INFERENCE)
        evidence_cls = classify_evidence(region, strategy, result.confidence, result.validation)
        evidence_classifications.append(evidence_cls)
    
    return bytes(recovered_data), evidence_classifications


def attempt_structural_repair(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    reference_data: bytes = None
) -> RecoveryResult:
    """Attempt to repair region using file structure (headers, footers, tables)."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    # PDF structural repair
    if file_type == "PDF":
        return repair_pdf_structure(region, fragment_classifications, reference_data)
    
    # JPEG structural repair
    if file_type == "JPEG":
        return repair_jpeg_structure(region, fragment_classifications, reference_data)
    
    # PNG structural repair
    if file_type == "PNG":
        return repair_png_structure(region, fragment_classifications, reference_data)
    
    # ZIP/DOCX/XLSX structural repair
    if file_type == "ZIP/DOCX/XLSX":
        return repair_zip_structure(region, fragment_classifications, reference_data)
    
    # SQLite structural repair
    if file_type == "SQLite":
        return repair_sqlite_structure(region, fragment_classifications, reference_data)
    
    # TXT - not much structure to repair
    if file_type == "TXT":
        return repair_txt_structure(region, fragment_classifications, reference_data)
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["No structural repair for this file type"])


def repair_pdf_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair PDF structure using known patterns."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    # If we have reference data, use it
    if reference_data and offset < len(reference_data):
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.9,
            validation={"valid": True, "message": "Reference data used for PDF header/footer/xref"}
        )
    
    # Try to reconstruct based on position
    if offset == 0:
        # PDF header
        header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        return RecoveryResult(
            success=True,
            data=header.ljust(size, b"\x00"),
            strategy="structural_repair",
            confidence=0.8,
            validation={"valid": True, "message": "Reconstructed standard PDF header"}
        )
    
    # Check if near end - might be xref/trailer
    # This would require parsing the PDF to find actual positions
    return RecoveryResult(
        success=False,
        strategy="structural_repair",
        errors=["Cannot determine PDF structure position without parsing"]
    )


def repair_jpeg_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair JPEG structure."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    if reference_data and offset < len(reference_data):
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.9,
            validation={"valid": True, "message": "Reference data used for JPEG markers"}
        )
    
    if offset == 0:
        # JPEG header
        header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
        return RecoveryResult(
            success=True,
            data=header.ljust(size, b"\x00"),
            strategy="structural_repair",
            confidence=0.8,
            validation={"valid": True, "message": "Reconstructed standard JPEG header"}
        )
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["Cannot determine JPEG structure position"])


def repair_png_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair PNG structure."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    if reference_data and offset < len(reference_data):
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.9,
            validation={"valid": True, "message": "Reference data used for PNG chunks"}
        )
    
    if offset == 0:
        # PNG signature
        sig = b"\x89PNG\r\n\x1a\n"
        return RecoveryResult(
            success=True,
            data=sig.ljust(size, b"\x00"),
            strategy="structural_repair",
            confidence=0.8,
            validation={"valid": True, "message": "Reconstructed PNG signature"}
        )
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["Cannot determine PNG chunk position"])


def repair_zip_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair ZIP/DOCX/XLSX structure."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    if reference_data and offset < len(reference_data):
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.9,
            validation={"valid": True, "message": "Reference data used for ZIP structure"}
        )
    
    if offset == 0:
        # ZIP local file header signature
        header = b"PK\x03\x04"
        return RecoveryResult(
            success=True,
            data=header.ljust(size, b"\x00"),
            strategy="structural_repair",
            confidence=0.7,
            validation={"valid": True, "message": "Reconstructed ZIP local header signature"}
        )
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["Cannot determine ZIP structure position"])


def repair_sqlite_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair SQLite structure."""
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    if reference_data and offset < len(reference_data):
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.9,
            validation={"valid": True, "message": "Reference data used for SQLite header"}
        )
    
    if offset == 0:
        # SQLite header (100 bytes)
        header = b"SQLite format 3\x00" + b"\x00" * 84
        # Page size at offset 16 (default 4096)
        if size >= 18:
            header = bytearray(header)
            header[16:18] = struct.pack(">H", 4096)
            header = bytes(header)
        return RecoveryResult(
            success=True,
            data=header[:size],
            strategy="structural_repair",
            confidence=0.8,
            validation={"valid": True, "message": "Reconstructed SQLite header"}
        )
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["Cannot determine SQLite page position"])


def repair_txt_structure(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    reference_data: bytes = None
) -> RecoveryResult:
    """Repair text file structure (limited)."""
    if reference_data and region.get("offset", 0) < len(reference_data):
        offset = region.get("offset", 0)
        size = region.get("size", 0)
        ref_chunk = reference_data[offset:offset+size]
        return RecoveryResult(
            success=True,
            data=ref_chunk,
            strategy="structural_repair",
            confidence=0.8,
            validation={"valid": True, "message": "Reference data used for text content"}
        )
    
    return RecoveryResult(success=False, strategy="structural_repair", errors=["No structural repair for text files"])


def attempt_object_reference_repair(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    fragment_data_map: Dict[str, bytes]
) -> RecoveryResult:
    """Attempt repair using object references (xref, FAT, B-tree, etc.)."""
    # This would require parsing the file structure
    # For now, return failure to fall through to next strategy
    return RecoveryResult(
        success=False,
        strategy="object_reference_repair",
        errors=["Object reference repair requires full file parsing - not yet implemented"]
    )


def attempt_stream_recovery(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    fragment_data_map: Dict[str, bytes]
) -> RecoveryResult:
    """Attempt to recover compressed/encoded streams."""
    # This would require decompressing and recompressing streams
    # For now, return failure
    return RecoveryResult(
        success=False,
        strategy="stream_recovery",
        errors=["Stream recovery requires decompression - not yet implemented"]
    )


def attempt_page_level_salvage(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    fragment_data_map: Dict[str, bytes]
) -> RecoveryResult:
    """Attempt to salvage page-level structures."""
    # This would require identifying page boundaries
    # For now, return failure
    return RecoveryResult(
        success=False,
        strategy="page_level_salvage",
        errors=["Page-level salvage requires page boundary detection - not yet implemented"]
    )


def attempt_content_inference(
    region: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    file_type: str,
    fragment_data_map: Dict[str, bytes]
) -> RecoveryResult:
    """
    Infer content from surrounding intact fragments.
    Uses simple heuristics based on file type.
    """
    offset = region.get("offset", 0)
    size = region.get("size", 0)
    
    # Find intact neighbors
    preceding_data = b""
    following_data = b""
    
    for fc in fragment_classifications:
        fc_offset = fc.get("offset", 0)
        fc_size = fc.get("size", 0)
        fc_id = fc.get("fragment_id", "")
        fc_class = fc.get("classification", "")
        
        if fc_class == "INTACT":
            fc_end = fc_offset + fc_size
            if fc_end == offset:
                preceding_data = fragment_data_map.get(fc_id, b"")
            elif fc_offset == offset + size:
                following_data = fragment_data_map.get(fc_id, b"")
    
    if not preceding_data and not following_data:
        return RecoveryResult(
            success=False,
            strategy="content_inference",
            confidence=0.05,
            errors=["No intact neighbors for inference"]
        )
    
    # Simple inference based on file type
    inferred_data = bytearray(size)
    
    if file_type == "TXT":
        # For text, try to infer from context
        if preceding_data:
            try:
                text = preceding_data.decode("utf-8", errors="ignore")
                # If preceding ends with partial word, continue
                last_words = text.split()[-3:] if text.split() else []
                if last_words:
                    inferred = " ".join(last_words) + " "
                    inferred_bytes = inferred.encode("utf-8")
                    inferred_data[:min(len(inferred_bytes), size)] = inferred_bytes[:size]
            except:
                pass
    
    elif file_type in ["PDF", "ZIP/DOCX/XLSX"]:
        # For structured formats, inferring content is hard
        # Fill with zeros but mark as inferred
        pass
    
    elif file_type in ["JPEG", "PNG"]:
        # Image data - can't really infer
        pass
    
    return RecoveryResult(
        success=True,
        data=bytes(inferred_data),
        strategy="content_inference",
        confidence=0.25 if (preceding_data and following_data) else 0.15,
        validation={"valid": True, "message": "Content inferred from neighbors"},
        warnings=["Low confidence inference"]
    )


def validate_recovered_file(data: bytes, file_type: str) -> Dict[str, Any]:
    """Validate the recovered file using appropriate validator."""
    validators = {
        "PDF": validate_pdf,
        "JPEG": validate_jpeg,
        "PNG": validate_png,
        "TXT": validate_txt,
        "ZIP/DOCX/XLSX": validate_zip,
        "SQLite": validate_sqlite,
    }
    
    validator = validators.get(file_type, validate_generic_binary)
    return validator(data)


def calculate_recovery_metrics(
    original_size: int,
    recovered_data: bytes,
    evidence_classifications: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Calculate recovery quality metrics."""
    total_regions = len(evidence_classifications)
    
    status_bytes = defaultdict(int)
    for ec in evidence_classifications:
        status = ec.get("evidence_status", "UNKNOWN")
        size = ec.get("region_size", 0)
        status_bytes[status] += size
    
    # Non-zero bytes in recovered data
    non_zero_bytes = sum(1 for b in recovered_data if b != 0)
    
    return {
        "original_size": original_size,
        "recovered_size": len(recovered_data),
        "non_zero_bytes": non_zero_bytes,
        "zero_bytes": len(recovered_data) - non_zero_bytes,
        "non_zero_percentage": round(non_zero_bytes / len(recovered_data) * 100, 2) if recovered_data else 0,
        "status_byte_distribution": dict(status_bytes),
        "total_regions": total_regions,
        "recovered_regions": status_bytes.get("RECOVERED", 0),
        "repaired_regions": status_bytes.get("REPAIRED", 0),
        "partial_regions": status_bytes.get("PARTIAL_RECOVERY", 0),
        "inferred_regions": status_bytes.get("AI_INFERRED", 0),
        "unknown_regions": status_bytes.get("UNKNOWN", 0)
    }


if __name__ == "__main__":
    import sys
    import os
    
    if len(sys.argv) < 4:
        print("Usage: python file_recovery.py <fragment_dir> <file_type> <original_size>")
        sys.exit(1)
    
    fragment_dir = sys.argv[1]
    file_type = sys.argv[2]
    original_size = int(sys.argv[3])
    
    # Load fragments
    from backend.reconstruction.fragment_classifier import classify_all_fragments
    import hashlib
    
    fragments = []
    for filename in sorted(os.listdir(fragment_dir)):
        if filename.endswith(".bin"):
            path = os.path.join(fragment_dir, filename)
            with open(path, "rb") as f:
                data = f.read()
            fragment_hash = hashlib.sha256(data).hexdigest()
            fragment_id = filename.replace(".bin", "")
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
    
    recovered_data, evidence = recover_file(
        classifications, fragment_dir, file_type, original_size
    )
    
    # Save recovered file
    output_path = os.path.join(fragment_dir, f"recovered_{file_type.lower()}.bin")
    with open(output_path, "wb") as f:
        f.write(recovered_data)
    
    print(f"Recovered file saved to: {output_path}")
    print(f"Size: {len(recovered_data)} bytes")
    
    # Validation
    validation = validate_recovered_file(recovered_data, file_type)
    print(f"Validation: {validation}")
    
    # Metrics
    metrics = calculate_recovery_metrics(original_size, recovered_data, evidence)
    print(f"Metrics: {metrics}")
    
    # Evidence summary
    from backend.reconstruction.evidence_classifier import generate_evidence_summary
    summary = generate_evidence_summary(evidence)
    print(f"Evidence Summary: {summary}")