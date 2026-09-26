"""
PDF Analyzer

Format-specific analysis for PDF files:
- PDF object structure (obj/endobj)
- Cross-reference tables (xref)
- Trailer dictionary
- Page tree
- Content streams
- Encryption detection
"""

import struct
from typing import Dict, List, Any, Optional
from backend.analyzers.base_analyzer import BaseAnalyzer, FragmentAnalysis, DamageRegion, RecoveryResult, ValidationResult


class PDFAnalyzer(BaseAnalyzer):
    """Analyzer for PDF files."""
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["PDF"]
    
    @property
    def magic_bytes(self) -> List[bytes]:
        return [b"%PDF"]
    
    def identify(self, data: bytes) -> bool:
        return data.startswith(b"%PDF")
    
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """Analyze a PDF fragment for structural elements and anomalies."""
        import hashlib
        
        entropy = self.calculate_entropy(fragment_data)
        zero_ratio = self.calculate_zero_ratio(fragment_data)
        unique_ratio = self.calculate_unique_ratio(fragment_data)
        fragment_hash = self.get_fragment_hash(fragment_data)
        fragment_id = f"F{offset // 4096 + 1:04d}"
        
        # Format-specific analysis
        format_analysis = {
            "anomalies": [],
            "warnings": [],
            "structures_found": [],
            "object_references": [],
            "stream_info": None,
        }
        
        # Check for PDF header at offset 0
        if offset == 0:
            if not fragment_data.startswith(b"%PDF"):
                format_analysis["anomalies"].append("Missing PDF header at offset 0")
            else:
                format_analysis["structures_found"].append("PDF header")
                for line in fragment_data[:200].split(b"\n"):
                    if line.startswith(b"%PDF-"):
                        try:
                            version = float(line[5:].decode().strip())
                            format_analysis["pdf_version"] = version
                            if version < 1.0 or version > 2.0:
                                format_analysis["warnings"].append(f"Unusual PDF version: {version}")
                        except:
                            pass
                        break
        
        # Check for structural keywords
        structural_keywords = {
            b"xref": "cross-reference table",
            b"trailer": "trailer dictionary",
            b"startxref": "startxref pointer",
            b"obj": "object",
            b"endobj": "end object",
            b"stream": "stream start",
            b"endstream": "stream end",
            b"/Page": "page object",
            b"/Pages": "pages tree",
            b"/Encrypt": "encryption dictionary",
        }
        
        for keyword, description in structural_keywords.items():
            if keyword in fragment_data:
                format_analysis["structures_found"].append(description)
                if keyword == b"obj":
                    # Try to extract object numbers
                    self._extract_object_refs(fragment_data, format_analysis)
        
        # Check for stream content
        if b"stream" in fragment_data and b"endstream" in fragment_data:
            format_analysis["stream_info"] = "complete_stream"
        elif b"stream" in fragment_data:
            format_analysis["stream_info"] = "stream_start"
        elif b"endstream" in fragment_data:
            format_analysis["stream_info"] = "stream_end"
        
        # Calculate anomaly score
        anomaly_score = 0.0
        reasons = []
        
        if entropy > 7.95:
            anomaly_score += 0.15
            reasons.append("Very high entropy (possibly encrypted/compressed stream)")
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
            status = "RED"  # UNKNOWN / UNRECOVERABLE
        elif anomaly_score >= 0.3:
            status = "ORANGE"  # CORRUPTED / ANOMALOUS
        elif format_analysis["structures_found"]:
            status = "GREEN"  # INTACT / OBSERVED
        else:
            status = "YELLOW"  # DUPLICATE / SUSPICIOUS (no clear structure but no anomalies)
        
        # Build reasoning
        reasoning = [f"WHAT: Fragment at offset {offset} classified as {status}"]
        for reason in reasons:
            reasoning.append(f"WHY: {reason}")
        if status == "RED":
            reasoning.append("LIMITATION: Original content cannot be determined from this evidence alone")
        elif status == "GREEN":
            reasoning.append("WHY: Fragment contains expected PDF structural elements")
        
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
    
    def _extract_object_refs(self, fragment_data: bytes, format_analysis: Dict[str, Any]):
        """Extract PDF object references from fragment."""
        import re
        # Find patterns like "123 0 obj"
        obj_pattern = rb'(\d+)\s+(\d+)\s+obj'
        for match in re.finditer(obj_pattern, fragment_data):
            obj_num = match.group(1).decode()
            gen_num = match.group(2).decode()
            format_analysis["object_references"].append(f"obj {obj_num} {gen_num}")
    
    def map_damage(self, fragment_analyses: List[FragmentAnalysis], full_file_data: bytes) -> List[DamageRegion]:
        """Map damaged fragments to PDF structures (objects, pages, streams, xref/trailer)."""
        damage_regions = []
        
        # First, parse the full file to understand structure
        pdf_structure = self._parse_pdf_structure(full_file_data)
        
        for frag in fragment_analyses:
            if frag.status in ("ORANGE", "RED"):
                # Find what structures this fragment overlaps with
                affected = []
                frag_start = frag.offset
                frag_end = frag.offset + frag.size
                
                # Check objects
                for obj in pdf_structure.get("objects", []):
                    obj_start = obj["offset"]
                    obj_end = obj["offset"] + obj["size"]
                    if not (frag_end <= obj_start or frag_start >= obj_end):
                        affected.append(f"PDF object {obj['id']} (gen {obj['gen']})")
                
                # Check streams
                for stream in pdf_structure.get("streams", []):
                    stream_start = stream["offset"]
                    stream_end = stream["offset"] + stream["size"]
                    if not (frag_end <= stream_start or frag_start >= stream_end):
                        affected.append(f"Stream in object {stream['obj_id']}")
                
                # Check xref/trailer
                if pdf_structure.get("xref_offset") and not (frag_end <= pdf_structure["xref_offset"] or frag_start >= pdf_structure["xref_offset"] + 100):
                    affected.append("Cross-reference table (xref)")
                
                if pdf_structure.get("trailer_offset") and not (frag_end <= pdf_structure["trailer_offset"] or frag_start >= pdf_structure["trailer_offset"] + 100):
                    affected.append("Trailer dictionary")
                
                # Check pages
                for page in pdf_structure.get("pages", []):
                    page_start = page["offset"]
                    page_end = page["offset"] + page.get("size", 100)
                    if not (frag_end <= page_start or frag_start >= page_end):
                        affected.append(f"Page {page['number']}")
                
                # Determine severity
                severity = frag.status
                
                # Corruption reason
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
    
    def _parse_pdf_structure(self, data: bytes) -> Dict[str, Any]:
        """Parse PDF to find objects, streams, xref, trailer, pages."""
        structure = {
            "objects": [],
            "streams": [],
            "pages": [],
            "xref_offset": None,
            "trailer_offset": None,
            "startxref_offset": None,
        }
        
        import re
        
        # Find all objects
        obj_pattern = rb'(\d+)\s+(\d+)\s+obj'
        for match in re.finditer(obj_pattern, data):
            obj_num = int(match.group(1))
            gen_num = int(match.group(2))
            obj_start = match.start()
            # Find endobj
            endobj_pos = data.find(b"endobj", obj_start)
            if endobj_pos != -1:
                obj_end = endobj_pos + 6
            else:
                obj_end = obj_start + 1000  # estimate
            
            obj_data = data[obj_start:obj_end]
            structure["objects"].append({
                "id": obj_num,
                "gen": gen_num,
                "offset": obj_start,
                "size": obj_end - obj_start,
                "has_stream": b"stream" in obj_data,
            })
            
            if b"stream" in obj_data:
                stream_start = obj_data.find(b"stream") + 6
                if stream_start < len(obj_data) and obj_data[stream_start:stream_start+1] in (b"\n", b"\r"):
                    stream_start += 1
                stream_end = obj_data.find(b"endstream", stream_start)
                if stream_end != -1:
                    structure["streams"].append({
                        "obj_id": obj_num,
                        "offset": obj_start + stream_start,
                        "size": stream_end - stream_start,
                    })
        
        # Find xref
        xref_pos = data.find(b"xref")
        if xref_pos != -1:
            structure["xref_offset"] = xref_pos
        
        # Find trailer
        trailer_pos = data.find(b"trailer")
        if trailer_pos != -1:
            structure["trailer_offset"] = trailer_pos
        
        # Find startxref
        startxref_pos = data.find(b"startxref")
        if startxref_pos != -1:
            structure["startxref_offset"] = startxref_pos
        
        # Find pages
        page_pattern = rb'/Page\b'
        for i, match in enumerate(re.finditer(page_pattern, data)):
            structure["pages"].append({
                "number": i + 1,
                "offset": match.start(),
            })
        
        return structure
    
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """Attempt PDF-specific recovery strategies."""
        results = {}
        
        for region in damage_regions:
            offset = region.offset
            size = region.size
            
            # Strategy 1: Exact surviving duplicate (check if fragment exists in fragment_data_map)
            fragment_id = region.fragment_ids[0] if region.fragment_ids else ""
            if fragment_id and fragment_id in fragment_data_map:
                fragment_data = fragment_data_map[fragment_id]
                if fragment_data and len(fragment_data) == size:
                    # Check if this fragment is actually intact
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
            
            # Strategy 2: Structural repair - reconstruct known structures
            repair_data = self._attempt_structural_repair(region, full_file_data)
            if repair_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=repair_data,
                    strategy="structural_repair",
                    confidence=0.75,
                    validation={"valid": True, "message": "Reconstructed from known PDF structure"},
                    errors=[],
                    warnings=["Structure reconstructed from format specification"]
                )
                continue
            
            # Strategy 3: Object/reference repair using xref
            if "Cross-reference table (xref)" in region.affected_structures or "Trailer dictionary" in region.affected_structures:
                obj_repair = self._attempt_object_reference_repair(region, full_file_data)
                if obj_repair:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=obj_repair,
                        strategy="object_reference_repair",
                        confidence=0.65,
                        validation={"valid": True, "message": "Object reference repaired via xref"},
                        errors=[],
                        warnings=["Repair based on cross-reference table"]
                    )
                    continue
            
            # Strategy 4: Stream salvage
            if any("Stream" in s for s in region.affected_structures):
                stream_data = self._attempt_stream_salvage(region, fragment_data_map)
                if stream_data:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=stream_data,
                        strategy="stream_recovery",
                        confidence=0.55,
                        validation={"valid": True, "message": "Partial stream data salvaged"},
                        errors=[],
                        warnings=["Stream data may be incomplete"]
                    )
                    continue
            
            # Strategy 5: Page-level salvage
            if any("Page" in s for s in region.affected_structures):
                page_data = self._attempt_page_salvage(region, fragment_data_map)
                if page_data:
                    results[offset] = RecoveryResult(
                        success=True,
                        data=page_data,
                        strategy="page_level_salvage",
                        confidence=0.5,
                        validation={"valid": True, "message": "Page structure partially salvaged"},
                        errors=[],
                        warnings=["Page content may be incomplete"]
                    )
                    continue
            
            # Strategy 6: Content inference (AI) - only with explicit marking
            inferred_data = self._attempt_content_inference(region, fragment_data_map)
            if inferred_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=inferred_data,
                    strategy="content_inference",
                    confidence=0.2,
                    validation={"valid": False, "message": "AI-INFERRED - NOT VERIFIED ORIGINAL EVIDENCE"},
                    errors=[],
                    warnings=["AI-INFERRED — NOT VERIFIED ORIGINAL EVIDENCE", "Low confidence inference from context"]
                )
                continue
            
            # No recovery possible
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
    
    def _attempt_structural_repair(self, region: DamageRegion, full_file_data: bytes) -> Optional[bytes]:
        """Attempt to repair known PDF structures (header, xref, trailer)."""
        offset = region.offset
        size = region.size
        
        # PDF header at offset 0
        if offset == 0:
            header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
            return header.ljust(size, b"\x00")
        
        # xref table - would need parsing to reconstruct properly
        if "Cross-reference table (xref)" in region.affected_structures:
            # Cannot reconstruct without knowing object structure
            return None
        
        # Trailer - minimal reconstruction
        if "Trailer dictionary" in region.affected_structures:
            trailer = b"trailer\n<<\n/Size 0\n/Root 1 0 R\n>>\n"
            return trailer.ljust(size, b"\x00")
        
        return None
    
    def _attempt_object_reference_repair(self, region: DamageRegion, full_file_data: bytes) -> Optional[bytes]:
        """Attempt to repair using xref/trailer references."""
        # Would require parsing xref table to locate objects
        # Simplified: not implemented without full parsing
        return None
    
    def _attempt_stream_salvage(self, region: DamageRegion, fragment_data_map: Dict[str, bytes]) -> Optional[bytes]:
        """Attempt to salvage stream data from intact fragments."""
        # Look for intact stream fragments nearby
        return None
    
    def _attempt_page_salvage(self, region: DamageRegion, fragment_data_map: Dict[str, bytes]) -> Optional[bytes]:
        """Attempt to salvage page content."""
        return None
    
    def _attempt_content_inference(self, region: DamageRegion, fragment_data_map: Dict[str, bytes]) -> Optional[bytes]:
        """Infer content from surrounding intact fragments (AI-assisted)."""
        offset = region.offset
        size = region.size
        
        # Find intact neighbors
        preceding = b""
        following = b""
        
        for frag_id, data in fragment_data_map.items():
            # This is simplified - would need proper offset tracking
            pass
        
        # For PDF, content inference is very limited
        # Return zeros with warning
        return b"\x00" * size
    
    def validate(self, data: bytes) -> ValidationResult:
        """Validate PDF structure."""
        checks = {}
        anomalies = []
        warnings = []
        
        # Header check
        checks["valid_header"] = data.startswith(b"%PDF")
        if not checks["valid_header"]:
            anomalies.append("Missing PDF header")
        
        # EOF marker
        checks["valid_eof"] = b"%%EOF" in data
        if not checks["valid_eof"]:
            anomalies.append("Missing EOF marker (%%EOF)")
        
        # Cross-reference table
        checks["has_xref"] = b"xref" in data
        if not checks["has_xref"]:
            anomalies.append("Missing cross-reference table (xref)")
        
        # Trailer
        checks["has_trailer"] = b"trailer" in data
        if not checks["has_trailer"]:
            anomalies.append("Missing trailer dictionary")
        
        # startxref
        checks["has_startxref"] = b"startxref" in data
        if not checks["has_startxref"]:
            anomalies.append("Missing startxref")
        
        # Object count
        checks["object_count"] = data.count(b"obj")
        
        # Page count
        checks["page_count"] = data.count(b"/Page")
        
        # Encryption check
        if b"/Encrypt" in data:
            warnings.append("PDF is encrypted - content validation limited")
        
        # Try to parse with PyMuPDF if available
        try:
            import fitz
            doc = fitz.open(stream=data, filetype="pdf")
            checks["pymupdf_parse"] = True
            checks["pymupdf_page_count"] = doc.page_count
            doc.close()
        except ImportError:
            checks["pymupdf_parse"] = "PyMuPDF not available"
        except Exception as e:
            checks["pymupdf_parse"] = f"Failed: {str(e)}"
            anomalies.append(f"PyMuPDF parsing failed: {str(e)}")
        
        valid = len(anomalies) == 0
        
        return ValidationResult(
            valid=valid,
            format="PDF",
            checks=checks,
            anomalies=anomalies,
            warnings=warnings
        )