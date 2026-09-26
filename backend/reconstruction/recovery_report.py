"""
Recovery Report Module

Generates comprehensive recovery reports with:
- Recovered regions
- Repaired regions
- Inferred regions
- Unresolved regions
- Confidence scores
- Validation results
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict


def generate_recovery_report(
    case_id: str,
    evidence_info: Dict[str, Any],
    fragment_classifications: List[Dict[str, Any]],
    evidence_classifications: List[Dict[str, Any]],
    recovered_data: bytes,
    validation_result: Dict[str, Any],
    recovery_metrics: Dict[str, Any],
    audit_events: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate comprehensive recovery report.
    """
    report = {
        "case_id": case_id,
        "generated_at": datetime.now().isoformat(),
        "report_version": "2.0",
        "evidence": evidence_info,
        "fragment_analysis": generate_fragment_analysis_section(fragment_classifications),
        "recovery_analysis": generate_recovery_analysis_section(evidence_classifications, recovery_metrics),
        "validation": validation_result,
        "recovered_file": generate_recovered_file_section(recovered_data),
        "confidence_assessment": generate_confidence_assessment(evidence_classifications),
        "limitations_and_disclaimers": generate_limitations(),
        "audit_trail": audit_events or []
    }
    
    return report


def generate_fragment_analysis_section(
    fragment_classifications: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generate fragment analysis section of report."""
    total = len(fragment_classifications)
    if total == 0:
        return {"total_fragments": 0}
    
    counts = defaultdict(int)
    for fc in fragment_classifications:
        cls = fc.get("classification", "UNKNOWN")
        counts[cls] += 1
    
    # Group by classification
    fragments_by_class = defaultdict(list)
    for fc in fragment_classifications:
        cls = fc.get("classification", "UNKNOWN")
        fragments_by_class[cls].append({
            "fragment_id": fc.get("fragment_id"),
            "offset": fc.get("offset"),
            "size": fc.get("size"),
            "sha256": fc.get("sha256"),
            "confidence": fc.get("confidence"),
            "reasons": fc.get("reasons", [])
        })
    
    return {
        "total_fragments": total,
        "classification_summary": {
            "intact": counts.get("INTACT", 0),
            "corrupted": counts.get("CORRUPTED", 0),
            "missing": counts.get("MISSING", 0),
            "duplicate": counts.get("DUPLICATE", 0),
            "unknown": counts.get("UNKNOWN", 0)
        },
        "classification_percentages": {
            "intact": round(counts.get("INTACT", 0) / total * 100, 2),
            "corrupted": round(counts.get("CORRUPTED", 0) / total * 100, 2),
            "missing": round(counts.get("MISSING", 0) / total * 100, 2),
            "duplicate": round(counts.get("DUPLICATE", 0) / total * 100, 2),
            "unknown": round(counts.get("UNKNOWN", 0) / total * 100, 2)
        },
        "fragments_by_classification": dict(fragments_by_class)
    }


def generate_recovery_analysis_section(
    evidence_classifications: List[Dict[str, Any]],
    recovery_metrics: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate recovery analysis section."""
    total = len(evidence_classifications)
    if total == 0:
        return {"total_regions": 0}
    
    # Status distribution
    status_counts = defaultdict(int)
    status_bytes = defaultdict(int)
    strategy_counts = defaultdict(int)
    confidence_sum = 0.0
    
    regions_by_status = defaultdict(list)
    
    for ec in evidence_classifications:
        status = ec.get("evidence_status", "UNKNOWN")
        strategy = ec.get("recovery_strategy", "unknown")
        confidence = ec.get("confidence", 0.0)
        size = ec.get("region_size", 0)
        
        status_counts[status] += 1
        status_bytes[status] += size
        strategy_counts[strategy] += 1
        confidence_sum += confidence
        
        regions_by_status[status].append({
            "offset": ec.get("region_offset"),
            "size": size,
            "strategy": strategy,
            "confidence": confidence,
            "reasons": ec.get("reasons", [])
        })
    
    avg_confidence = confidence_sum / total if total > 0 else 0.0
    
    return {
        "total_regions": total,
        "status_distribution": dict(status_counts),
        "status_byte_distribution": dict(status_bytes),
        "strategy_distribution": dict(strategy_counts),
        "average_confidence": round(avg_confidence, 3),
        "recovery_metrics": recovery_metrics,
        "regions_by_status": dict(regions_by_status)
    }


def generate_recovered_file_section(recovered_data: bytes) -> Dict[str, Any]:
    """Generate recovered file information section."""
    sha256 = hashlib.sha256(recovered_data).hexdigest()
    non_zero = sum(1 for b in recovered_data if b != 0)
    
    return {
        "size_bytes": len(recovered_data),
        "sha256": sha256,
        "non_zero_bytes": non_zero,
        "zero_bytes": len(recovered_data) - non_zero,
        "non_zero_percentage": round(non_zero / len(recovered_data) * 100, 2) if recovered_data else 0,
        "entropy": calculate_entropy(recovered_data)
    }


def generate_confidence_assessment(
    evidence_classifications: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generate confidence assessment section."""
    if not evidence_classifications:
        return {"overall_confidence": 0.0}
    
    # Weight by region size
    total_size = sum(ec.get("region_size", 0) for ec in evidence_classifications)
    weighted_confidence = 0.0
    
    status_confidence = defaultdict(list)
    
    for ec in evidence_classifications:
        size = ec.get("region_size", 0)
        confidence = ec.get("confidence", 0.0)
        status = ec.get("evidence_status", "UNKNOWN")
        
        if total_size > 0:
            weight = size / total_size
            weighted_confidence += confidence * weight
        
        status_confidence[status].append(confidence)
    
    # Average confidence per status
    status_avg_confidence = {}
    for status, confidences in status_confidence.items():
        status_avg_confidence[status] = round(sum(confidences) / len(confidences), 3) if confidences else 0.0
    
    # Overall assessment
    if weighted_confidence >= 0.8:
        overall = "HIGH"
    elif weighted_confidence >= 0.5:
        overall = "MEDIUM"
    elif weighted_confidence >= 0.25:
        overall = "LOW"
    else:
        overall = "VERY_LOW"
    
    return {
        "overall_confidence": round(weighted_confidence, 3),
        "overall_assessment": overall,
        "status_confidence": status_avg_confidence,
        "confidence_distribution": {
            "high": sum(1 for ec in evidence_classifications if ec.get("confidence", 0) >= 0.75),
            "medium": sum(1 for ec in evidence_classifications if 0.4 <= ec.get("confidence", 0) < 0.75),
            "low": sum(1 for ec in evidence_classifications if ec.get("confidence", 0) < 0.4)
        }
    }


def generate_limitations() -> List[str]:
    """Generate standard limitations and disclaimers."""
    return [
        "This recovery analysis is based solely on the submitted evidence file. No reference original was available for comparison.",
        "Classifications (RECOVERED, REPAIRED, AI-INFERRED, UNKNOWN) describe the method used to reconstruct each region, not the historical accuracy of the content.",
        "RECOVERED regions are based on exact hash matches or physically intact fragments.",
        "REPAIRED regions use file format structural knowledge (headers, tables, references) to reconstruct missing data.",
        "AI-INFERRED regions use heuristic inference from surrounding context and have the lowest confidence.",
        "UNKNOWN regions had insufficient evidence for any recovery strategy and are zero-filled.",
        "Validation results indicate structural well-formedness, not content correctness.",
        "This analysis should not be used as sole basis for legal or forensic conclusions without independent verification."
    ]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    
    return round(entropy, 4)


def save_recovery_report(report: Dict[str, Any], output_dir: str, case_id: str) -> Dict[str, Any]:
    """Save recovery report as JSON with hash verification."""
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{case_id}_recovery_report.json")
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Calculate hash
    sha256 = hashlib.sha256()
    with open(report_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    
    return {
        "report_path": report_path,
        "report_sha256": sha256.hexdigest(),
        "size_bytes": os.path.getsize(report_path)
    }


def generate_executive_summary(report: Dict[str, Any]) -> str:
    """Generate human-readable executive summary."""
    evidence = report.get("evidence", {})
    fragment_analysis = report.get("fragment_analysis", {})
    recovery_analysis = report.get("recovery_analysis", {})
    confidence = report.get("confidence_assessment", {})
    validation = report.get("validation", {})
    
    lines = []
    lines.append("=" * 60)
    lines.append("ANVAYA DIGITAL EVIDENCE RECOVERY REPORT")
    lines.append("=" * 60)
    lines.append(f"Case ID: {report.get('case_id', 'N/A')}")
    lines.append(f"Generated: {report.get('generated_at', 'N/A')}")
    lines.append("")
    lines.append("EVIDENCE:")
    lines.append(f"  Filename: {evidence.get('filename', 'N/A')}")
    lines.append(f"  File Type: {evidence.get('file_type', 'N/A')}")
    lines.append(f"  Size: {evidence.get('size_bytes', 'N/A')} bytes")
    lines.append(f"  SHA-256: {evidence.get('sha256', 'N/A')}")
    lines.append("")
    lines.append("FRAGMENT ANALYSIS:")
    lines.append(f"  Total Fragments: {fragment_analysis.get('total_fragments', 0)}")
    cls_summary = fragment_analysis.get('classification_summary', {})
    lines.append(f"  INTACT: {cls_summary.get('intact', 0)} ({fragment_analysis.get('classification_percentages', {}).get('intact', 0)}%)")
    lines.append(f"  CORRUPTED: {cls_summary.get('corrupted', 0)} ({fragment_analysis.get('classification_percentages', {}).get('corrupted', 0)}%)")
    lines.append(f"  MISSING: {cls_summary.get('missing', 0)} ({fragment_analysis.get('classification_percentages', {}).get('missing', 0)}%)")
    lines.append(f"  DUPLICATE: {cls_summary.get('duplicate', 0)} ({fragment_analysis.get('classification_percentages', {}).get('duplicate', 0)}%)")
    lines.append("")
    lines.append("RECOVERY ANALYSIS:")
    lines.append(f"  Total Regions: {recovery_analysis.get('total_regions', 0)}")
    status_dist = recovery_analysis.get('status_distribution', {})
    for status, count in status_dist.items():
        lines.append(f"  {status}: {count}")
    lines.append(f"  Average Confidence: {recovery_analysis.get('average_confidence', 0):.2f}")
    lines.append("")
    lines.append("VALIDATION:")
    lines.append(f"  Format Valid: {validation.get('valid_header', 'N/A') if isinstance(validation.get('valid_header'), bool) else 'N/A'}")
    if isinstance(validation, dict):
        for key in ['valid_eof', 'has_xref', 'has_trailer', 'has_startxref', 'object_count', 'page_count']:
            if key in validation:
                lines.append(f"  {key}: {validation[key]}")
    lines.append("")
    lines.append("CONFIDENCE ASSESSMENT:")
    lines.append(f"  Overall: {confidence.get('overall_assessment', 'N/A')} ({confidence.get('overall_confidence', 0):.2f})")
    lines.append("")
    lines.append("DISCLAIMER:")
    for lim in report.get("limitations_and_disclaimers", [])[:3]:
        lines.append(f"  - {lim}")
    lines.append("  ...")
    lines.append("=" * 60)
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Test report generation
    test_report = generate_recovery_report(
        case_id="TEST-001",
        evidence_info={"filename": "test.pdf", "file_type": "PDF", "size_bytes": 10000, "sha256": "abc123"},
        fragment_classifications=[],
        evidence_classifications=[],
        recovered_data=b"test",
        validation_result={"valid_header": True},
        recovery_metrics={},
        audit_events=[]
    )
    print(json.dumps(test_report, indent=2))