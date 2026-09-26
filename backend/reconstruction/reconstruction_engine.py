import os
import hashlib
from typing import List, Dict, Any


def build_reconstruction_map_standalone(fragments: List[Dict[str, Any]], fragment_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build reconstruction map from standalone analysis.
    No reference original - map is based on observed fragment order.
    """
    reconstruction_map = []
    for i, fragment in enumerate(fragments):
        analysis = fragment_analyses[i] if i < len(fragment_analyses) else {}
        status = analysis.get("status", "UNKNOWN / UNRECOVERABLE")
        
        # Map status for reconstruction
        if status == "OBSERVED / INTACT":
            recon_status = "OBSERVED"
        elif status == "SUSPECTED / ANOMALOUS":
            recon_status = "SUSPECTED"
        else:
            recon_status = "UNKNOWN"
        
        reconstruction_map.append({
            "fragment_index": i,
            "original_index": i,
            "filename": fragment["filename"],
            "status": recon_status,
            "sha256": fragment["sha256"],
            "size": fragment["size"],
            "offset": fragment["offset"]
        })
    return reconstruction_map


def build_reconstruction_map(
    original_fragments: List[Dict[str, Any]],
    damaged_fragments: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Legacy function for comparison against reference original.
    Kept for backward compatibility with controlled demo.
    """
    original_by_hash = {}
    for fragment in original_fragments:
        original_by_hash[fragment["sha256"]] = fragment["original_index"]
    
    reconstruction = []
    matched_indexes = set()
    
    for damaged in damaged_fragments:
        original_index = original_by_hash.get(damaged["sha256"])
        if original_index is None:
            continue
        if original_index in matched_indexes:
            continue
        matched_indexes.add(original_index)
        reconstruction.append({
            "original_index": original_index,
            "filename": damaged["filename"],
            "status": "RECOVERED",
            "sha256": damaged["sha256"],
            "size": damaged["size"]
        })
    
    for original in original_fragments:
        index = original["original_index"]
        if index not in matched_indexes:
            reconstruction.append({
                "original_index": index,
                "filename": None,
                "status": "MISSING",
                "sha256": None,
                "size": original["size"]
            })
    
    reconstruction.sort(key=lambda item: item["original_index"])
    return reconstruction


def generate_candidate_file_standalone(
    reconstruction_map: List[Dict[str, Any]],
    fragments_dir: str,
    output_path: str
) -> Dict[str, Any]:
    """
    Generate analysis candidate containing only observed evidence.
    Missing/unknown regions are left as zeros with clear labeling.
    """
    fragment_lookup = {}
    for filename in os.listdir(fragments_dir):
        if filename.endswith(".bin"):
            path = os.path.join(fragments_dir, filename)
            with open(path, "rb") as f:
                data = f.read()
            fragment_lookup[filename] = data
    
    total_bytes = 0
    observed_bytes = 0
    unknown_bytes = 0
    
    with open(output_path, "wb") as output:
        for item in reconstruction_map:
            filename = item["filename"]
            size = item["size"]
            status = item["status"]
            
            if status == "OBSERVED" and filename in fragment_lookup:
                data = fragment_lookup[filename]
                output.write(data)
                observed_bytes += len(data)
                total_bytes += len(data)
            else:
                # Zero-filled placeholder - NOT claimed as recovered
                output.write(b"\x00" * size)
                unknown_bytes += size
                total_bytes += size
    
    observed_pct = round((observed_bytes / total_bytes) * 100, 2) if total_bytes > 0 else 0
    
    return {
        "total_bytes": total_bytes,
        "observed_bytes": observed_bytes,
        "unknown_bytes": unknown_bytes,
        "observed_percentage": observed_pct
    }


def generate_candidate_file(
    reconstruction_map: List[Dict[str, Any]],
    damaged_fragments: List[Dict[str, Any]],
    output_path: str
) -> Dict[str, Any]:
    """
    Legacy function for generating candidate from damaged fragments.
    Kept for backward compatibility with controlled demo.
    """
    fragment_lookup = {
        fragment["filename"]: fragment["data"]
        for fragment in damaged_fragments
    }
    
    total_bytes = 0
    recovered_bytes = 0
    missing_bytes = 0
    
    with open(output_path, "wb") as output:
        for item in reconstruction_map:
            filename = item["filename"]
            if filename is not None and filename in fragment_lookup:
                data = fragment_lookup[filename]
                output.write(data)
                recovered_bytes += len(data)
                total_bytes += len(data)
            else:
                missing_size = item["size"]
                output.write(b"\x00" * missing_size)
                missing_bytes += missing_size
                total_bytes += missing_size
    
    recovery_percentage = (
        recovered_bytes / total_bytes * 100
        if total_bytes else 0
    )
    
    return {
        "output_file": output_path,
        "total_bytes": total_bytes,
        "recovered_bytes": recovered_bytes,
        "missing_bytes": missing_bytes,
        "recovery_percentage": round(recovery_percentage, 2)
    }


def create_reconstruction_report_standalone(reconstruction_map: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create reconstruction report for standalone analysis."""
    observed = sum(1 for item in reconstruction_map if item["status"] == "OBSERVED")
    suspected = sum(1 for item in reconstruction_map if item["status"] == "SUSPECTED")
    unknown = sum(1 for item in reconstruction_map if item["status"] == "UNKNOWN")
    total = len(reconstruction_map)
    
    return {
        "total_fragments": total,
        "observed_fragments": observed,
        "suspected_fragments": suspected,
        "unknown_fragments": unknown,
        "observed_percentage": round((observed / total) * 100, 2) if total > 0 else 0,
        "suspected_percentage": round((suspected / total) * 100, 2) if total > 0 else 0,
        "unknown_percentage": round((unknown / total) * 100, 2) if total > 0 else 0,
        "disclaimer": "Standalone analysis: reconstruction map reflects observed evidence only. No reference original was available for comparison."
    }


def create_reconstruction_report(reconstruction_map: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility with controlled demo.
    """
    recovered = 0
    missing = 0
    for item in reconstruction_map:
        if item["status"] == "RECOVERED":
            recovered += 1
        elif item["status"] == "MISSING":
            missing += 1
    total = len(reconstruction_map)
    coverage = (recovered / total * 100) if total else 0
    return {
        "total_original_fragments": total,
        "recovered_fragments": recovered,
        "missing_fragments": missing,
        "fragment_coverage_percentage": round(coverage, 2)
    }


if __name__ == "__main__":
    fragment_dir = "data/fragments"
    output_path = "data/recovered_candidate.pdf"
    
    # This is kept for backward compatibility
    fragments = []
    for filename in sorted(os.listdir(fragment_dir)):
        if not filename.endswith(".bin"):
            continue
        path = os.path.join(fragment_dir, filename)
        with open(path, "rb") as f:
            data = f.read()
        fragments.append({
            "filename": filename,
            "data": data,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data)
        })
    
    # We need original_fragment_count for legacy demo
    original_fragment_count = 79
    
    # For demo, we'll use the legacy approach
    # In production, use standalone functions
    
    print("ANVAYA RECONSTRUCTION (Legacy Demo)")
    print("=====================")
    print(f"Original fragments (demo): {original_fragment_count}")
    print(f"Available fragments: {len(fragments)}")
    print(f"Candidate output: {output_path}")