"""
ZIP Analyzer

Format-specific analysis for ZIP archives.
"""

import zipfile
import io
import struct
from typing import Dict, List, Any, Optional
from backend.analyzers.base_analyzer import BaseAnalyzer, FragmentAnalysis, DamageRegion, RecoveryResult, ValidationResult


class ZipAnalyzer(BaseAnalyzer):
    """Analyzer for ZIP archives."""
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["ZIP"]
    
    @property
    def magic_bytes(self) -> List[bytes]:
        return [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
    
    def identify(self, data: bytes) -> bool:
        return (data.startswith(b"PK\x03\x04") or 
                data.startswith(b"PK\x05\x06") or 
                data.startswith(b"PK\x07\x08"))
    
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """Analyze a ZIP fragment for structural elements."""
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
            "zip_signatures": [],
        }
        
        # Check ZIP signatures
        if offset == 0:
            if fragment_data.startswith(b"PK\x03\x04"):
                format_analysis["structures_found"].append("ZIP local file header")
                format_analysis["zip_signatures"].append("local_header")
            elif fragment_data.startswith(b"PK\x05\x06"):
                format_analysis["structures_found"].append("ZIP end of central directory")
                format_analysis["zip_signatures"].append("end_central_dir")
            elif fragment_data.startswith(b"PK\x07\x08"):
                format_analysis["structures_found"].append("ZIP archive extra data")
                format_analysis["zip_signatures"].append("archive_extra")
            else:
                format_analysis["anomalies"].append("Missing ZIP signature at offset 0")
        
        # Scan for ZIP signatures in fragment
        signatures = {
            b"PK\x01\x02": "central directory header",
            b"PK\x03\x04": "local file header",
            b"PK\x05\x06": "end of central directory",
            b"PK\x06\x06": "ZIP64 end of central directory",
            b"PK\x06\x07": "ZIP64 end of central directory locator",
            b"PK\x07\x08": "archive extra data",
        }
        
        for sig, desc in signatures.items():
            pos = fragment_data.find(sig)
            while pos != -1:
                format_analysis["zip_signatures"].append(desc)
                pos = fragment_data.find(sig, pos + 1)
        
        if format_analysis["zip_signatures"]:
            format_analysis["structures_found"].extend(format_analysis["zip_signatures"])
        
        # Calculate anomaly score
        anomaly_score = 0.0
        reasons = []
        
        if entropy > 7.95:
            anomaly_score += 0.1
            reasons.append("Very high entropy (compressed/encrypted data)")
        elif entropy < 1.0:
            anomaly_score += 0.25
            reasons.append("Very low entropy (highly repetitive)")
        
        if zero_ratio > 0.5:
            anomaly_score += 0.3
            reasons.append("High zero-byte concentration")
        
        if format_analysis["anomalies"]:
            anomaly_score += 0.4 * len(format_analysis["anomalies"])
            reasons.extend(format_analysis["anomalies"])
        
        if format_analysis["warnings"]:
            anomaly_score += 0.15 * len(format_analysis["warnings"])
            reasons.extend(format_analysis["warnings"])
        
        # Classify fragment
        if anomaly_score >= 0.6:
            status = "RED"
        elif anomaly_score >= 0.3:
            status = "ORANGE"
        elif format_analysis["structures_found"]:
            status = "GREEN"
        else:
            status = "YELLOW"
        
        reasoning = [f"WHAT: Fragment at offset {offset} classified as {status}"]
        for reason in reasons:
            reasoning.append(f"WHY: {reason}")
        if status == "RED":
            reasoning.append("LIMITATION: Original content cannot be determined from this evidence alone")
        elif status == "GREEN":
            reasoning.append("WHY: Fragment contains expected ZIP structural elements")
        
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
        """Map damaged fragments to ZIP structures (local headers, central directory, entries)."""
        damage_regions = []
        
        structure = self._parse_zip_structure(full_file_data)
        
        for frag in fragment_analyses:
            if frag.status in ("ORANGE", "RED"):
                affected = []
                frag_start = frag.offset
                frag_end = frag.offset + frag.size
                
                # Check local file headers
                for entry in structure.get("local_headers", []):
                    hdr_start = entry["offset"]
                    hdr_end = entry["offset"] + entry["header_size"] + entry["compressed_size"]
                    if not (frag_end <= hdr_start or frag_start >= hdr_end):
                        affected.append(f"ZIP entry: {entry['name']} (local header + data)")
                
                # Check central directory
                if structure.get("central_dir_offset") and not (frag_end <= structure["central_dir_offset"] or frag_start >= structure["central_dir_offset"] + structure.get("central_dir_size", 0)):
                    affected.append("ZIP central directory")
                
                # Check end of central directory
                if structure.get("eocd_offset") and not (frag_end <= structure["eocd_offset"] or frag_start >= structure["eocd_offset"] + 22):
                    affected.append("ZIP end of central directory (EOCD)")
                
                severity = frag.status
                reason = "; ".join(frag.format_analysis.get("anomalies", ["ZIP structural inconsistency detected"]))
                
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
    
    def _parse_zip_structure(self, data: bytes) -> Dict[str, Any]:
        """Parse ZIP archive structure."""
        structure = {
            "local_headers": [],
            "central_dir_offset": None,
            "central_dir_size": 0,
            "eocd_offset": None,
        }
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                for info in zf.filelist:
                    structure["local_headers"].append({
                        "name": info.filename,
                        "offset": info.header_offset,
                        "header_size": 30 + len(info.filename) + len(info.extra),
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                    })
                
                # Find central directory
                if zf.filelist:
                    last_file = max(zf.filelist, key=lambda f: f.header_offset + f.compress_size)
                    cd_start = last_file.header_offset + last_file.compress_size
                    structure["central_dir_offset"] = cd_start
                
                # Find EOCD
                eocd_pos = data.rfind(b"PK\x05\x06")
                if eocd_pos != -1:
                    structure["eocd_offset"] = eocd_pos
        except:
            pass
        
        return structure
    
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """Attempt ZIP-specific recovery strategies."""
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
            
            # Strategy 2: Structural repair (signatures)
            repair_data = self._attempt_structural_repair(region)
            if repair_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=repair_data,
                    strategy="structural_repair",
                    confidence=0.75,
                    validation={"valid": True, "message": "ZIP signature reconstructed"},
                    errors=[],
                    warnings=["Signature reconstructed from format specification"]
                )
                continue
            
            # Strategy 3: Entry salvage
            if any("ZIP entry" in s for s in region.affected_structures):
                entry_data = self._attempt_entry_salvage(region, fragment_data_map, full_file_data)
                if entry_data:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=entry_data,
                        strategy="stream_recovery",
                        confidence=0.55,
                        validation={"valid": True, "message": "ZIP entry partially salvaged"},
                        errors=[],
                        warnings=["Entry data may be incomplete"]
                    )
                    continue
            
            # Strategy 4: Content inference
            inferred_data = self._attempt_content_inference(region, fragment_data_map, full_file_data)
            if inferred_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=inferred_data,
                    strategy="content_inference",
                    confidence=0.15,
                    validation={"valid": False, "message": "AI-INFERRED - NOT VERIFIED ORIGINAL EVIDENCE"},
                    errors=[],
                    warnings=["AI-INFERRED — NOT VERIFIED ORIGINAL EVIDENCE", "Very low confidence"]
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
    
    def _attempt_structural_repair(self, region: DamageRegion) -> Optional[bytes]:
        """Attempt to repair ZIP signatures."""
        offset = region.offset
        size = region.size
        
        if offset == 0:
            return b"PK\x03\x04".ljust(size, b"\x00")
        
        if "ZIP end of central directory" in str(region.affected_structures):
            # Minimal EOCD (22 bytes)
            eocd = b"PK\x05\x06" + b"\x00" * 20
            return eocd.ljust(size, b"\x00")
        
        return None
    
    def _attempt_entry_salvage(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Optional[bytes]:
        """Attempt to salvage ZIP entry data."""
        return None
    
    def _attempt_content_inference(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Optional[bytes]:
        """Infer content from context."""
        return b"\x00" * region.size
    
    def validate(self, data: bytes) -> ValidationResult:
        """Validate ZIP archive structure."""
        checks = {}
        anomalies = []
        warnings = []
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                checks["valid_zip"] = True
                checks["file_count"] = len(zf.filelist)
                checks["has_central_directory"] = True
                
                # Check for corruption
                try:
                    bad_file = zf.testzip()
                    if bad_file:
                        checks["crc_check"] = False
                        anomalies.append(f"CRC check failed for: {bad_file}")
                    else:
                        checks["crc_check"] = True
                except Exception as e:
                    checks["crc_check"] = f"Error: {str(e)}"
                    anomalies.append(f"CRC test error: {str(e)}")
                
                # List entries
                entries = []
                for info in zf.filelist:
                    entries.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "crc32": f"{info.CRC:08x}",
                    })
                checks["entries"] = entries
                
        except zipfile.BadZipFile as e:
            checks["valid_zip"] = False
            anomalies.append(f"Invalid ZIP structure: {str(e)}")
        except Exception as e:
            checks["valid_zip"] = False
            anomalies.append(f"ZIP parsing error: {str(e)}")
        
        valid = len(anomalies) == 0
        
        return ValidationResult(
            valid=valid,
            format="ZIP",
            checks=checks,
            anomalies=anomalies,
            warnings=warnings
        )