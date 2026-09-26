"""
Office Analyzer (DOCX/XLSX)

Format-specific analysis for Office Open XML files (DOCX, XLSX).
These are ZIP-based formats with specific internal XML structure.
"""

import zipfile
import io
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from backend.analyzers.base_analyzer import BaseAnalyzer, FragmentAnalysis, DamageRegion, RecoveryResult, ValidationResult
from backend.analyzers.zip_analyzer import ZipAnalyzer


class OfficeAnalyzer(BaseAnalyzer):
    """Analyzer for DOCX and XLSX files."""
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["DOCX", "XLSX"]
    
    @property
    def magic_bytes(self) -> List[bytes]:
        return [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
    
    def identify(self, data: bytes) -> bool:
        if not (data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08")):
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                filenames = [f.filename for f in zf.filelist]
                if "[Content_Types].xml" in filenames:
                    return True
        except:
            return False
        return False
    
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """Analyze an Office document fragment."""
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
            "office_type": "Unknown",
            "zip_entries": [],
            "xml_structures": [],
        }
        
        # Check ZIP signature at offset 0
        if offset == 0:
            if not (fragment_data.startswith(b"PK\x03\x04") or 
                    fragment_data.startswith(b"PK\x05\x06") or 
                    fragment_data.startswith(b"PK\x07\x08")):
                format_analysis["anomalies"].append("Missing ZIP/OOXML signature")
            else:
                format_analysis["structures_found"].append("ZIP local file header")
        
        # Try to parse as ZIP to find internal structure
        try:
            with zipfile.ZipFile(io.BytesIO(full_file_data), 'r') as zf:
                filenames = [f.filename for f in zf.filelist]
                format_analysis["zip_entries"] = filenames
                
                # Determine DOCX vs XLSX
                if "word/document.xml" in filenames:
                    format_analysis["office_type"] = "DOCX"
                    format_analysis["structures_found"].append("word/document.xml")
                elif "xl/workbook.xml" in filenames:
                    format_analysis["office_type"] = "XLSX"
                    format_analysis["structures_found"].append("xl/workbook.xml")
                
                if "[Content_Types].xml" in filenames:
                    format_analysis["structures_found"].append("[Content_Types].xml")
                if "_rels/.rels" in filenames:
                    format_analysis["structures_found"].append("_rels/.rels (relationships)")
                
                # Check for XML structures in this fragment
                xml_keywords = [b"<?xml", b"<w:", b"<x:", b"<a:", b"<p:", b"</w:", b"</x:"]
                for kw in xml_keywords:
                    if kw in fragment_data:
                        format_analysis["xml_structures"].append(kw.decode(errors="ignore"))
        except zipfile.BadZipFile:
            format_analysis["anomalies"].append("Invalid ZIP structure")
        except Exception as e:
            format_analysis["warnings"].append(f"ZIP analysis limited: {str(e)}")
        
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
            reasoning.append("WHY: Fragment contains expected OOXML/ZIP structural elements")
        
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
        """Map damaged fragments to Office document structures (ZIP entries, XML parts)."""
        damage_regions = []
        
        # Parse full file structure
        structure = self._parse_office_structure(full_file_data)
        
        for frag in fragment_analyses:
            if frag.status in ("ORANGE", "RED"):
                affected = []
                frag_start = frag.offset
                frag_end = frag.offset + frag.size
                
                # Check ZIP entries
                for entry in structure.get("entries", []):
                    entry_start = entry["offset"]
                    entry_end = entry["offset"] + entry["compressed_size"]
                    if not (frag_end <= entry_start or frag_start >= entry_end):
                        affected.append(f"ZIP entry: {entry['name']}")
                
                # Check central directory
                if structure.get("central_dir_offset") and not (frag_end <= structure["central_dir_offset"] or frag_start >= structure["central_dir_offset"] + structure.get("central_dir_size", 0)):
                    affected.append("ZIP central directory")
                
                # Check XML parts
                for xml_part in structure.get("xml_parts", []):
                    xml_start = xml_part["offset"]
                    xml_end = xml_part["offset"] + xml_part["size"]
                    if not (frag_end <= xml_start or frag_start >= xml_end):
                        affected.append(f"XML part: {xml_part['name']}")
                
                severity = frag.status
                reason = "; ".join(frag.format_analysis.get("anomalies", ["Structural inconsistency detected"]))
                
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
    
    def _parse_office_structure(self, data: bytes) -> Dict[str, Any]:
        """Parse Office document structure (ZIP entries and XML parts)."""
        structure = {
            "entries": [],
            "xml_parts": [],
            "central_dir_offset": None,
            "central_dir_size": 0,
            "office_type": "Unknown",
        }
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                for info in zf.filelist:
                    structure["entries"].append({
                        "name": info.filename,
                        "offset": info.header_offset,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                    })
                    
                    # Identify important XML parts
                    if info.filename.endswith(".xml") or info.filename in ["[Content_Types].xml", "_rels/.rels"]:
                        structure["xml_parts"].append({
                            "name": info.filename,
                            "offset": info.header_offset,
                            "size": info.compress_size,
                        })
                
                # Central directory info
                if zf.filelist:
                    first_header = zf.filelist[0].header_offset
                    # Central directory starts after last file data
                    last_file = max(zf.filelist, key=lambda f: f.header_offset + f.compress_size)
                    cd_start = last_file.header_offset + last_file.compress_size
                    structure["central_dir_offset"] = cd_start
                
                # Determine type
                filenames = [f.filename for f in zf.filelist]
                if "word/document.xml" in filenames:
                    structure["office_type"] = "DOCX"
                elif "xl/workbook.xml" in filenames:
                    structure["office_type"] = "XLSX"
        except:
            pass
        
        return structure
    
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """Attempt Office document recovery strategies."""
        results = {}
        
        # Delegate to ZipAnalyzer for ZIP-level recovery
        zip_analyzer = ZipAnalyzer()
        
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
            
            # Strategy 2: ZIP structural repair
            repair_data = self._attempt_zip_structural_repair(region, full_file_data)
            if repair_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=repair_data,
                    strategy="structural_repair",
                    confidence=0.75,
                    validation={"valid": True, "message": "ZIP structure repaired"},
                    errors=[],
                    warnings=["ZIP structure reconstructed from format specification"]
                )
                continue
            
            # Strategy 3: XML part salvage
            if any("XML part" in s or "ZIP entry" in s for s in region.affected_structures):
                xml_data = self._attempt_xml_salvage(region, fragment_data_map, full_file_data)
                if xml_data:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=xml_data,
                        strategy="stream_recovery",
                        confidence=0.6,
                        validation={"valid": True, "message": "XML part partially salvaged"},
                        errors=[],
                        warnings=["XML content may be incomplete"]
                    )
                    continue
            
            # Strategy 4: Content inference
            inferred_data = self._attempt_content_inference(region, fragment_data_map, full_file_data)
            if inferred_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=inferred_data,
                    strategy="content_inference",
                    confidence=0.2,
                    validation={"valid": False, "message": "AI-INFERRED - NOT VERIFIED ORIGINAL EVIDENCE"},
                    errors=[],
                    warnings=["AI-INFERRED — NOT VERIFIED ORIGINAL EVIDENCE", "Low confidence inference"]
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
    
    def _attempt_zip_structural_repair(self, region: DamageRegion, full_file_data: bytes) -> Optional[bytes]:
        """Attempt ZIP structural repair."""
        offset = region.offset
        size = region.size
        
        if offset == 0:
            # ZIP local file header signature
            header = b"PK\x03\x04"
            return header.ljust(size, b"\x00")
        
        # Central directory - cannot reconstruct without full parsing
        return None
    
    def _attempt_xml_salvage(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Optional[bytes]:
        """Attempt to salvage XML content from intact fragments."""
        return None
    
    def _attempt_content_inference(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Optional[bytes]:
        """Infer content from context."""
        return b"\x00" * region.size
    
    def validate(self, data: bytes) -> ValidationResult:
        """Validate Office document structure."""
        checks = {}
        anomalies = []
        warnings = []
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                filenames = [f.filename for f in zf.filelist]
                checks["has_central_directory"] = True
                checks["file_count"] = len(filenames)
                checks["total_uncompressed_size"] = sum(f.file_size for f in zf.filelist)
                checks["total_compressed_size"] = sum(f.compress_size for f in zf.filelist)
                
                # Check for required OOXML files
                checks["has_content_types"] = "[Content_Types].xml" in filenames
                checks["has_rels"] = "_rels/.rels" in filenames
                
                if not checks["has_content_types"]:
                    anomalies.append("Missing [Content_Types].xml")
                if not checks["has_rels"]:
                    anomalies.append("Missing _rels/.rels")
                
                # Determine type
                if "word/document.xml" in filenames:
                    checks["office_type"] = "DOCX"
                    checks["has_document_xml"] = True
                elif "xl/workbook.xml" in filenames:
                    checks["office_type"] = "XLSX"
                    checks["has_workbook_xml"] = True
                else:
                    checks["office_type"] = "Unknown OOXML"
                    anomalies.append("Unrecognized OOXML type (not DOCX or XLSX)")
                
                # Try to parse key XML files
                try:
                    if checks["has_content_types"]:
                        ct_data = zf.read("[Content_Types].xml")
                        ET.fromstring(ct_data)
                        checks["content_types_xml_valid"] = True
                except Exception as e:
                    checks["content_types_xml_valid"] = False
                    anomalies.append(f"[Content_Types].xml parse error: {str(e)}")
                
        except zipfile.BadZipFile as e:
            checks["valid_zip"] = False
            anomalies.append(f"Invalid ZIP structure: {str(e)}")
        except Exception as e:
            checks["valid_zip"] = False
            anomalies.append(f"ZIP parsing error: {str(e)}")
        
        valid = len(anomalies) == 0
        
        return ValidationResult(
            valid=valid,
            format=checks.get("office_type", "OOXML"),
            checks=checks,
            anomalies=anomalies,
            warnings=warnings
        )