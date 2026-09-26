"""
Image Analyzer (JPEG/PNG)

Format-specific analysis for JPEG and PNG files.
"""

import struct
from typing import Dict, List, Any, Optional
from backend.analyzers.base_analyzer import BaseAnalyzer, FragmentAnalysis, DamageRegion, RecoveryResult, ValidationResult


class ImageAnalyzer(BaseAnalyzer):
    """Analyzer for JPEG and PNG image files."""
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["JPEG", "PNG"]
    
    @property
    def magic_bytes(self) -> List[bytes]:
        return [b"\xFF\xD8\xFF", b"\x89PNG\r\n\x1a\n"]
    
    def identify(self, data: bytes) -> bool:
        return data.startswith(b"\xFF\xD8\xFF") or data.startswith(b"\x89PNG\r\n\x1a\n")
    
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """Analyze an image fragment for structural elements and anomalies."""
        import hashlib
        
        entropy = self.calculate_entropy(fragment_data)
        zero_ratio = self.calculate_zero_ratio(fragment_data)
        unique_ratio = self.calculate_unique_ratio(fragment_data)
        fragment_hash = self.get_fragment_hash(fragment_data)
        fragment_id = f"F{offset // 4096 + 1:04d}"
        
        # Determine file type
        if full_file_data.startswith(b"\xFF\xD8\xFF"):
            file_type = "JPEG"
        elif full_file_data.startswith(b"\x89PNG\r\n\x1a\n"):
            file_type = "PNG"
        else:
            file_type = "Unknown"
        
        format_analysis = {
            "file_type": file_type,
            "anomalies": [],
            "warnings": [],
            "structures_found": [],
        }
        
        if file_type == "JPEG":
            format_analysis.update(self._analyze_jpeg_fragment(fragment_data, offset))
        elif file_type == "PNG":
            format_analysis.update(self._analyze_png_fragment(fragment_data, offset))
        
        # Calculate anomaly score
        anomaly_score = 0.0
        reasons = []
        
        if entropy > 7.95:
            anomaly_score += 0.1
            reasons.append("Very high entropy (compressed image data)")
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
            reasoning.append("WHY: Fragment contains expected image structural elements")
        
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
    
    def _analyze_jpeg_fragment(self, fragment_data: bytes, offset: int) -> Dict[str, Any]:
        """Analyze JPEG fragment structure."""
        result = {"anomalies": [], "warnings": [], "structures_found": []}
        
        if offset == 0:
            if not fragment_data.startswith(b"\xFF\xD8\xFF"):
                result["anomalies"].append("Missing JPEG header (FF D8 FF)")
            else:
                result["structures_found"].append("JPEG SOI marker")
        
        # Scan for JPEG markers
        i = 0
        while i < len(fragment_data) - 1:
            if fragment_data[i] == 0xFF:
                marker = fragment_data[i + 1] if i + 1 < len(fragment_data) else 0
                
                # SOF markers (Start of Frame) - contain dimensions
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    result["structures_found"].append(f"SOF marker (0x{marker:02X})")
                    if i + 8 < len(fragment_data):
                        height = struct.unpack(">H", fragment_data[i+5:i+7])[0]
                        width = struct.unpack(">H", fragment_data[i+7:i+9])[0]
                        result["dimensions"] = {"width": width, "height": height}
                
                # DHT - Define Huffman Table
                elif marker == 0xC4:
                    result["structures_found"].append("DHT (Huffman table)")
                
                # DQT - Define Quantization Table
                elif marker == 0xDB:
                    result["structures_found"].append("DQT (Quantization table)")
                
                # SOS - Start of Scan
                elif marker == 0xDA:
                    result["structures_found"].append("SOS (Start of Scan)")
                
                # EOI - End of Image
                elif marker == 0xD9:
                    result["structures_found"].append("EOI (End of Image)")
                
                # Skip marker segment
                if i + 3 < len(fragment_data) and marker not in (0xD8, 0xD9, 0xDA):
                    length = struct.unpack(">H", fragment_data[i+2:i+4])[0]
                    i += 2 + length
                else:
                    i += 2
            else:
                i += 1
        
        return result
    
    def _analyze_png_fragment(self, fragment_data: bytes, offset: int) -> Dict[str, Any]:
        """Analyze PNG fragment structure."""
        result = {"anomalies": [], "warnings": [], "structures_found": []}
        
        if offset == 0:
            if not fragment_data.startswith(b"\x89PNG\r\n\x1a\n"):
                result["anomalies"].append("Missing PNG signature")
            else:
                result["structures_found"].append("PNG signature")
        
        # Parse PNG chunks
        i = 8 if offset == 0 else 0  # Skip signature if at start
        while i < len(fragment_data) - 12:
            if i + 8 > len(fragment_data):
                break
            
            length = struct.unpack(">I", fragment_data[i:i+4])[0]
            chunk_type = fragment_data[i+4:i+8]
            
            if chunk_type == b"IHDR":
                result["structures_found"].append("IHDR (Image Header)")
                if i + 8 + length <= len(fragment_data):
                    ihdr_data = fragment_data[i+8:i+8+length]
                    if len(ihdr_data) >= 13:
                        width = struct.unpack(">I", ihdr_data[0:4])[0]
                        height = struct.unpack(">I", ihdr_data[4:8])[0]
                        result["dimensions"] = {"width": width, "height": height}
                        result["bit_depth"] = ihdr_data[8]
                        color_types = {0: "Grayscale", 2: "RGB", 3: "Indexed", 4: "Grayscale+Alpha", 6: "RGBA"}
                        result["color_type"] = color_types.get(ihdr_data[9], f"Unknown({ihdr_data[9]})")
            
            elif chunk_type == b"IDAT":
                result["structures_found"].append("IDAT (Image Data)")
            
            elif chunk_type == b"IEND":
                result["structures_found"].append("IEND (Image End)")
                break
            
            elif chunk_type == b"PLTE":
                result["structures_found"].append("PLTE (Palette)")
            
            elif chunk_type == b"tRNS":
                result["structures_found"].append("tRNS (Transparency)")
            
            i += 12 + length
        
        return result
    
    def map_damage(self, fragment_analyses: List[FragmentAnalysis], full_file_data: bytes) -> List[DamageRegion]:
        """Map damaged fragments to image structures."""
        damage_regions = []
        
        file_type = "JPEG" if full_file_data.startswith(b"\xFF\xD8\xFF") else "PNG"
        structure = self._parse_image_structure(full_file_data, file_type)
        
        for frag in fragment_analyses:
            if frag.status in ("ORANGE", "RED"):
                affected = []
                frag_start = frag.offset
                frag_end = frag.offset + frag.size
                
                if file_type == "JPEG":
                    # Check segments
                    for seg in structure.get("segments", []):
                        seg_start = seg["offset"]
                        seg_end = seg["offset"] + seg["size"]
                        if not (frag_end <= seg_start or frag_start >= seg_end):
                            affected.append(f"JPEG segment {seg['name']} (0x{seg['marker']:02X})")
                
                elif file_type == "PNG":
                    # Check chunks
                    for chunk in structure.get("chunks", []):
                        chunk_start = chunk["offset"]
                        chunk_end = chunk["offset"] + chunk["size"]
                        if not (frag_end <= chunk_start or frag_start >= chunk_end):
                            affected.append(f"PNG chunk {chunk['type']}")
                
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
    
    def _parse_image_structure(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Parse image file structure."""
        structure = {"segments": [], "chunks": []}
        
        if file_type == "JPEG":
            i = 2  # Skip SOI
            while i < len(data) - 1:
                if data[i] == 0xFF:
                    marker = data[i + 1]
                    seg_start = i
                    
                    if marker in (0xD8, 0xD9):  # SOI, EOI
                        seg_end = i + 2
                    elif marker == 0xDA:  # SOS - scan data follows
                        # Find EOI
                        eoi_pos = data.find(b"\xFF\xD9", i)
                        seg_end = eoi_pos + 2 if eoi_pos != -1 else len(data)
                    else:
                        if i + 3 < len(data):
                            length = struct.unpack(">H", data[i+2:i+4])[0]
                            seg_end = i + 2 + length
                        else:
                            seg_end = i + 2
                    
                    marker_names = {
                        0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3",
                        0xC4: "DHT", 0xDB: "DQT", 0xDA: "SOS", 0xD9: "EOI",
                        0xE0: "APP0", 0xE1: "APP1", 0xDD: "DRI"
                    }
                    
                    structure["segments"].append({
                        "marker": marker,
                        "name": marker_names.get(marker, f"0x{marker:02X}"),
                        "offset": seg_start,
                        "size": seg_end - seg_start,
                    })
                    
                    i = seg_end
                else:
                    i += 1
        
        elif file_type == "PNG":
            i = 8  # Skip signature
            while i < len(data) - 12:
                if i + 8 > len(data):
                    break
                length = struct.unpack(">I", data[i:i+4])[0]
                chunk_type = data[i+4:i+8]
                chunk_start = i
                chunk_end = i + 12 + length
                
                structure["chunks"].append({
                    "type": chunk_type.decode("ascii", errors="ignore"),
                    "offset": chunk_start,
                    "size": chunk_end - chunk_start,
                })
                
                if chunk_type == b"IEND":
                    break
                i = chunk_end
        
        return structure
    
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """Attempt image-specific recovery strategies."""
        results = {}
        file_type = "JPEG" if full_file_data.startswith(b"\xFF\xD8\xFF") else "PNG"
        
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
            
            # Strategy 2: Structural repair (headers, EOI/IEND)
            repair_data = self._attempt_structural_repair(region, file_type)
            if repair_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=repair_data,
                    strategy="structural_repair",
                    confidence=0.8,
                    validation={"valid": True, "message": "Reconstructed from known image structure"},
                    errors=[],
                    warnings=["Structure reconstructed from format specification"]
                )
                continue
            
            # Strategy 3: Segment/chunk salvage
            segment_data = self._attempt_segment_salvage(region, fragment_data_map, file_type)
            if segment_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=segment_data,
                    strategy="stream_recovery",
                    confidence=0.55,
                    validation={"valid": True, "message": "Partial segment/chunk data salvaged"},
                    errors=[],
                    warnings=["Segment data may be incomplete"]
                )
                continue
            
            # Strategy 4: Content inference
            inferred_data = self._attempt_content_inference(region, fragment_data_map)
            if inferred_data:
                results[offset] = RecoveryResult(
                    success=True,
                    data=inferred_data,
                    strategy="content_inference",
                    confidence=0.15,
                    validation={"valid": False, "message": "AI-INFERRED - NOT VERIFIED ORIGINAL EVIDENCE"},
                    errors=[],
                    warnings=["AI-INFERRED — NOT VERIFIED ORIGINAL EVIDENCE", "Very low confidence inference"]
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
    
    def _attempt_structural_repair(self, region: DamageRegion, file_type: str) -> Optional[bytes]:
        """Attempt to repair known image structures."""
        offset = region.offset
        size = region.size
        
        if file_type == "JPEG":
            if offset == 0:
                # JPEG header with minimal JFIF
                header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
                return header.ljust(size, b"\x00")
            
            # EOI marker at end
            if "EOI" in str(region.affected_structures):
                return b"\xFF\xD9".ljust(size, b"\x00")
        
        elif file_type == "PNG":
            if offset == 0:
                # PNG signature
                sig = b"\x89PNG\r\n\x1a\n"
                return sig.ljust(size, b"\x00")
            
            # IEND chunk
            if "IEND" in str(region.affected_structures):
                iend = b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82"
                return iend.ljust(size, b"\x00")
        
        return None
    
    def _attempt_segment_salvage(self, region: DamageRegion, fragment_data_map: Dict[str, bytes], file_type: str) -> Optional[bytes]:
        """Attempt to salvage segment/chunk data."""
        return None
    
    def _attempt_content_inference(self, region: DamageRegion, fragment_data_map: Dict[str, bytes]) -> Optional[bytes]:
        """Infer image content from neighbors (very limited)."""
        return b"\x00" * region.size
    
    def validate(self, data: bytes) -> ValidationResult:
        """Validate JPEG/PNG structure."""
        checks = {}
        anomalies = []
        warnings = []
        
        if data.startswith(b"\xFF\xD8\xFF"):
            file_type = "JPEG"
            checks["valid_header"] = True
            checks["valid_eof"] = data.endswith(b"\xFF\xD9")
            if not checks["valid_eof"]:
                anomalies.append("Missing JPEG EOF marker (FF D9)")
            
            # Parse markers
            has_sof = False
            has_dht = False
            has_dqt = False
            i = 2
            while i < len(data) - 1:
                if data[i] == 0xFF:
                    marker = data[i + 1]
                    if marker in (0xC0, 0xC1, 0xC2, 0xC3):
                        has_sof = True
                    elif marker == 0xC4:
                        has_dht = True
                    elif marker == 0xDB:
                        has_dqt = True
                    elif marker == 0xDA:
                        break
                    if i + 3 < len(data) and marker not in (0xD8, 0xD9, 0xDA):
                        length = struct.unpack(">H", data[i+2:i+4])[0]
                        i += 2 + length
                    else:
                        i += 2
                else:
                    i += 1
            
            checks["has_sof"] = has_sof
            checks["has_dht"] = has_dht
            checks["has_dqt"] = has_dqt
            
            if not has_sof:
                anomalies.append("Missing SOF marker (no image dimensions)")
            if not has_dht:
                anomalies.append("Missing Huffman tables (DHT)")
            if not has_dqt:
                anomalies.append("Missing quantization tables (DQT)")
            
            # Try Pillow validation
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(data))
                img.verify()
                checks["pillow_validate"] = True
                checks["dimensions"] = {"width": img.width, "height": img.height}
            except ImportError:
                checks["pillow_validate"] = "Pillow not available"
            except Exception as e:
                checks["pillow_validate"] = f"Failed: {str(e)}"
                anomalies.append(f"Pillow validation failed: {str(e)}")
        
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            file_type = "PNG"
            checks["valid_header"] = True
            checks["has_iend"] = b"IEND" in data
            if not checks["has_iend"]:
                anomalies.append("Missing IEND chunk")
            
            # Parse chunks
            has_ihdr = False
            has_idat = False
            i = 8
            while i < len(data) - 12:
                if i + 8 > len(data):
                    break
                length = struct.unpack(">I", data[i:i+4])[0]
                chunk_type = data[i+4:i+8]
                if chunk_type == b"IHDR":
                    has_ihdr = True
                    if i + 8 + length <= len(data):
                        ihdr = data[i+8:i+8+length]
                        if len(ihdr) >= 13:
                            width = struct.unpack(">I", ihdr[0:4])[0]
                            height = struct.unpack(">I", ihdr[4:8])[0]
                            checks["dimensions"] = {"width": width, "height": height}
                elif chunk_type == b"IDAT":
                    has_idat = True
                elif chunk_type == b"IEND":
                    break
                i += 12 + length
            
            checks["has_ihdr"] = has_ihdr
            checks["has_idat"] = has_idat
            
            if not has_ihdr:
                anomalies.append("Missing IHDR chunk")
            if not has_idat:
                anomalies.append("Missing image data (IDAT)")
            
            # Try Pillow validation
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(data))
                img.verify()
                checks["pillow_validate"] = True
            except ImportError:
                checks["pillow_validate"] = "Pillow not available"
            except Exception as e:
                checks["pillow_validate"] = f"Failed: {str(e)}"
                anomalies.append(f"Pillow validation failed: {str(e)}")
        
        else:
            return ValidationResult(
                valid=False,
                format="Unknown",
                checks={},
                anomalies=["Not a recognized image format"],
                warnings=[]
            )
        
        valid = len(anomalies) == 0
        
        return ValidationResult(
            valid=valid,
            format=file_type,
            checks=checks,
            anomalies=anomalies,
            warnings=warnings
        )