"""
Text Analyzer

Format-specific analysis for plain text files.
"""

from typing import Dict, List, Any, Optional
from backend.analyzers.base_analyzer import BaseAnalyzer, FragmentAnalysis, DamageRegion, RecoveryResult, ValidationResult


class TextAnalyzer(BaseAnalyzer):
    """Analyzer for plain text files."""
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["TXT"]
    
    @property
    def magic_bytes(self) -> List[bytes]:
        return []  # No magic bytes for plain text
    
    def identify(self, data: bytes) -> bool:
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """Analyze a text fragment for encoding validity and anomalies."""
        import hashlib
        
        entropy = self.calculate_entropy(fragment_data)
        zero_ratio = self.calculate_zero_ratio(fragment_data)
        unique_ratio = self.calculate_unique_ratio(fragment_data)
        fragment_hash = self.get_fragment_hash(fragment_data)
        fragment_id = f"F{offset // 4096 + 1:04d}"
        
        format_analysis = {
            "anomalies": [],
            "warnings": [],
            "structures_found": [],
            "encoding": "utf-8",
            "line_count": 0,
            "printable_ratio": 0.0,
        }
        
        # Check UTF-8 validity
        try:
            text = fragment_data.decode("utf-8")
            format_analysis["utf8_valid"] = True
            format_analysis["line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        except UnicodeDecodeError as e:
            format_analysis["utf8_valid"] = False
            format_analysis["anomalies"].append(f"Invalid UTF-8 sequence at position {e.start}")
            # Try to decode with replacement for analysis
            text = fragment_data.decode("utf-8", errors="replace")
            format_analysis["line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        
        # Count null bytes
        null_count = fragment_data.count(0)
        if null_count > 0:
            format_analysis["anomalies"].append(f"Contains {null_count} null bytes")
        
        # Calculate printable ratio
        if len(fragment_data) > 0:
            printable = sum(1 for b in fragment_data if 32 <= b <= 126 or b in (9, 10, 13))  # tab, LF, CR
            format_analysis["printable_ratio"] = round(printable / len(fragment_data), 4)
            if format_analysis["printable_ratio"] < 0.5:
                format_analysis["anomalies"].append("Low printable character ratio")
        
        # Calculate anomaly score
        anomaly_score = 0.0
        reasons = []
        
        if not format_analysis["utf8_valid"]:
            anomaly_score += 0.4
            reasons.append("Invalid UTF-8 encoding")
        
        if null_count > 0:
            anomaly_score += 0.3
            reasons.append(f"Contains {null_count} null bytes")
        
        if format_analysis["printable_ratio"] < 0.3:
            anomaly_score += 0.3
            reasons.append("Very low printable character ratio")
        
        if entropy < 1.0:
            anomaly_score += 0.2
            reasons.append("Very low entropy (highly repetitive)")
        
        if zero_ratio > 0.5:
            anomaly_score += 0.3
            reasons.append("High zero-byte concentration")
        
        if format_analysis["warnings"]:
            anomaly_score += 0.15 * len(format_analysis["warnings"])
            reasons.extend(format_analysis["warnings"])
        
        # Classify fragment
        if anomaly_score >= 0.6:
            status = "RED"
        elif anomaly_score >= 0.3:
            status = "ORANGE"
        else:
            status = "GREEN"
        
        reasoning = [f"WHAT: Fragment at offset {offset} classified as {status}"]
        for reason in reasons:
            reasoning.append(f"WHY: {reason}")
        if status == "RED":
            reasoning.append("LIMITATION: Original content cannot be determined from this evidence alone")
        elif status == "GREEN":
            reasoning.append("WHY: Fragment is valid UTF-8 text with expected character distribution")
        
        return FragmentAnalysis(
            fragment_id=fragment_id,
            offset=offset,
            size=len(fragment_data),
            sha256=fragment_hash,
            entropy=entropy,
            zero_ratio=zero_ratio,
            unique_byte_ratio=unique_ratio,
            anomaly_score=round(min(anomaly_score, 1.0), 2),
            status=status,
            format_analysis=format_analysis,
            reasoning=reasoning
        )
    
    def map_damage(self, fragment_analyses: List[FragmentAnalysis], full_file_data: bytes) -> List[DamageRegion]:
        """Map damaged fragments to text regions (lines, encoding issues)."""
        damage_regions = []
        
        for frag in fragment_analyses:
            if frag.status in ("ORANGE", "RED"):
                affected = []
                reason_parts = []
                
                if not frag.format_analysis.get("utf8_valid", True):
                    affected.append("UTF-8 encoding")
                    reason_parts.append("Invalid UTF-8 sequence")
                
                if frag.format_analysis.get("anomalies"):
                    for anomaly in frag.format_analysis["anomalies"]:
                        if "null" in anomaly.lower():
                            affected.append("Null bytes")
                            reason_parts.append(anomaly)
                
                if frag.format_analysis.get("printable_ratio", 1.0) < 0.5:
                    affected.append("Non-printable characters")
                    reason_parts.append("Low printable character ratio")
                
                severity = frag.status
                reason = "; ".join(reason_parts) if reason_parts else "Text encoding/structure anomaly"
                
                damage_regions.append(DamageRegion(
                    offset=frag.offset,
                    size=frag.size,
                    fragment_ids=[frag.fragment_id],
                    severity=severity,
                    affected_structures=affected if affected else ["Byte region only"],
                    corruption_reason=reason,
                    recovery_status="UNKNOWN"
                ))
        
        return damage_regions
    
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """Attempt text-specific recovery strategies."""
        results = {}
        
        for region in damage_regions:
            offset = region.offset
            size = region.size
            
            # Strategy 1: Exact surviving duplicate
            fragment_id = region.fragment_ids[0] if region.fragment_ids else ""
            if fragment_id and fragment_id in fragment_data_map:
                fragment_data = fragment_data_map[fragment_id]
                if fragment_data and len(fragment_data) == size:
                    analysis = self.analyze_fragment(fragment_data, offset, full_file_data)
                    if analysis.status == "GREEN":
                        results[offset] = RecoveryResult(
                            success=True,
                            data=fragment_data,
                            strategy="exact_duplicate",
                            confidence=0.95,
                            validation={"valid": True, "message": "Exact surviving fragment"},
                            errors=[],
                            warnings=[]
                        )
                        continue
            
            # Strategy 2: Structural repair - fix encoding
            if "UTF-8 encoding" in region.affected_structures:
                repair_data = self._attempt_encoding_repair(region, full_file_data)
                if repair_data:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=repair_data,
                        strategy="structural_repair",
                        confidence=0.7,
                        validation={"valid": True, "message": "Encoding repaired"},
                        errors=[],
                        warnings=["Encoding repaired - content may differ from original"]
                    )
                    continue
            
            # Strategy 3: Content inference from neighbors
            inferred_data = self._attempt_content_inference(region, fragment_data_map, full_file_data)
            if inferred_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=inferred_data,
                    strategy="content_inference",
                    confidence=0.3,
                    validation={"valid": False, "message": "AI-INFERRED - NOT VERIFIED ORIGINAL EVIDENCE"},
                    errors=[],
                    warnings=["AI-INFERRED — NOT VERIFIED ORIGINAL EVIDENCE", "Inferred from surrounding text context"]
                )
                continue
            
            # No recovery
            results[offset] = RecoveryResult(
                success=False,
                data=b"\x00" * size,
                strategy="none",
                confidence=0.0,
                validation={"valid": False, "message": "No recovery strategy succeeded"},
                errors=["Insufficient evidence for recovery"],
                warnings=["Region zero-filled - original content unknown"]
            )
        
        return results
    
    def _attempt_encoding_repair(self, region: DamageRegion, full_file_data: bytes) -> Optional[bytes]:
        """Attempt to repair encoding by replacing invalid sequences."""
        offset = region.offset
        size = region.size
        
        # Extract the region from full file data
        region_data = full_file_data[offset:offset+size]
        
        # Try to decode with replacement
        try:
            text = region_data.decode("utf-8", errors="replace")
            return text.encode("utf-8")
        except:
            return None
    
    def _attempt_content_inference(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Optional[bytes]:
        """Infer text content from surrounding intact fragments."""
        offset = region.offset
        size = region.size
        
        # Find intact neighbors in full file data
        # Look for text before and after the damaged region
        before_start = max(0, offset - 200)
        before_text = full_file_data[before_start:offset].decode("utf-8", errors="ignore")
        after_text = full_file_data[offset+size:offset+size+200].decode("utf-8", errors="ignore")
        
        # Simple inference: if we have context, try to bridge
        if before_text and after_text:
            # Find last words before and first words after
            before_words = before_text.split()[-5:] if before_text.split() else []
            after_words = after_text.split()[:5] if after_text.split() else []
            
            if before_words and after_words:
                inferred = " ".join(before_words) + " [INFERRED] " + " ".join(after_words)
                inferred_bytes = inferred.encode("utf-8")
                return inferred_bytes[:size].ljust(size, b" ")
        
        # Just return spaces as placeholder
        return b" " * size
    
    def validate(self, data: bytes) -> ValidationResult:
        """Validate text file structure."""
        checks = {}
        anomalies = []
        warnings = []
        
        # UTF-8 validity
        try:
            text = data.decode("utf-8")
            checks["utf8_valid"] = True
            checks["line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            checks["char_count"] = len(text)
        except UnicodeDecodeError as e:
            checks["utf8_valid"] = False
            anomalies.append(f"Invalid UTF-8 at position {e.start}")
            text = data.decode("utf-8", errors="replace")
            checks["line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        
        # Null bytes
        null_count = data.count(0)
        checks["null_bytes"] = null_count
        if null_count > 0:
            anomalies.append(f"Contains {null_count} null bytes")
        
        # Printable ratio
        if len(data) > 0:
            printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
            checks["printable_ratio"] = round(printable / len(data), 4)
            if checks["printable_ratio"] < 0.5:
                anomalies.append("Low printable character ratio")
        
        # Line ending consistency
        lf_count = data.count(b"\n")
        crlf_count = data.count(b"\r\n")
        cr_count = data.count(b"\r") - crlf_count
        checks["line_endings"] = {"lf": lf_count, "crlf": crlf_count, "cr": cr_count}
        
        valid = len(anomalies) == 0
        
        return ValidationResult(
            valid=valid,
            format="TXT",
            checks=checks,
            anomalies=anomalies,
            warnings=warnings
        )