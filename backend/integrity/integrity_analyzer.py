import os
import hashlib
from collections import defaultdict
from typing import List, Dict, Any


def scan_fragments(fragment_dir: str) -> List[Dict[str, Any]]:
    """
    Scan all fragment files and calculate their hashes.
    """
    fragments = []
    for filename in sorted(os.listdir(fragment_dir)):
        if not filename.endswith(".bin"):
            continue
        path = os.path.join(fragment_dir, filename)
        with open(path, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        fragments.append({
            "filename": filename,
            "size": len(data),
            "sha256": sha256
        })
    return fragments


def find_duplicates(fragments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify fragments having identical SHA-256 hashes.
    """
    hash_groups = defaultdict(list)
    for fragment in fragments:
        hash_groups[fragment["sha256"]].append(fragment["filename"])
    duplicate_groups = []
    for sha256, filenames in hash_groups.items():
        if len(filenames) > 1:
            duplicate_groups.append({
                "sha256": sha256,
                "files": filenames,
                "count": len(filenames)
            })
    return duplicate_groups


def generate_integrity_report(fragments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate integrity report from fragments.
    For standalone analysis, no original_fragment_count is needed.
    Reports physical fragments found, unique fragments, and duplicates.
    """
    duplicate_groups = find_duplicates(fragments)
    duplicate_files = sum(group["count"] for group in duplicate_groups)
    unique_fragments = len(fragments) - (duplicate_files - len(duplicate_groups))
    
    # For standalone analysis, physical fragments = total fragments
    # No "missing estimate" since we don't have a reference original
    coverage = 100.0 if fragments else 0.0
    
    return {
        "total_fragments": len(fragments),
        "unique_fragments": unique_fragments,
        "duplicate_groups": len(duplicate_groups),
        "duplicate_files": duplicate_files,
        "duplicate_details": duplicate_groups,
        "coverage_percentage": round(coverage, 2),
        "disclaimer": "Standalone analysis: coverage reflects physical fragments present in uploaded evidence. No reference original was provided for comparison."
    }


def generate_integrity_report_with_reference(
    fragments: List[Dict[str, Any]], 
    original_fragment_count: int
) -> Dict[str, Any]:
    """
    Legacy function for comparison against a reference original.
    Kept for backward compatibility with controlled demo datasets.
    """
    duplicate_groups = find_duplicates(fragments)
    duplicate_files = sum(group["count"] for group in duplicate_groups)
    unique_fragments = len(fragments) - (duplicate_files - len(duplicate_groups))
    missing_estimate = max(0, original_fragment_count - unique_fragments)
    coverage = (unique_fragments / original_fragment_count * 100) if original_fragment_count else 0
    return {
        "original_fragments": original_fragment_count,
        "physical_fragments": len(fragments),
        "unique_fragments": unique_fragments,
        "duplicate_groups": len(duplicate_groups),
        "duplicate_files": duplicate_files,
        "missing_estimate": missing_estimate,
        "coverage_percentage": round(coverage, 2),
        "duplicate_details": duplicate_groups
    }


if __name__ == "__main__":
    fragment_dir = "data/fragments"
    fragments = scan_fragments(fragment_dir)
    
    # Use standalone report by default
    report = generate_integrity_report(fragments)
    
    print("\nANVAYA INTEGRITY REPORT (Standalone)")
    print("=======================")
    print(f"Total fragments       : {report['total_fragments']}")
    print(f"Unique fragments      : {report['unique_fragments']}")
    print(f"Duplicate groups      : {report['duplicate_groups']}")
    print(f"Duplicate files       : {report['duplicate_files']}")
    print(f"Coverage              : {report['coverage_percentage']}%")
    print(f"\nDisclaimer: {report['disclaimer']}")
    
    if report["duplicate_details"]:
        print("\nDuplicate details:")
        for group in report["duplicate_details"]:
            print(f"- {group['files']} ({group['count']} copies)")