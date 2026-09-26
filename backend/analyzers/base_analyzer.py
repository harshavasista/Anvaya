"""
Base Analyzer Interface

Defines the contract for all format-specific analyzers.
Each analyzer must implement these methods for the generic pipeline.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class FragmentAnalysis:
    """Result of analyzing a single fragment."""
    fragment_id: str
    offset: int
    size: int
    sha256: str
    entropy: float
    zero_ratio: float
    unique_byte_ratio: float
    anomaly_score: float
    status: str  # GREEN, ORANGE, YELLOW, RED
    format_analysis: Dict[str, Any]
    reasoning: List[str]


@dataclass
class DamageRegion:
    """A region of damage mapped to format structures."""
    offset: int
    size: int
    fragment_ids: List[str]
    severity: str  # GREEN, ORANGE, YELLOW, RED
    affected_structures: List[str]  # e.g., ["PDF object 5", "Page 3"]
    corruption_reason: str
    recovery_status: str  # RECOVERED, REPAIRED, PARTIAL_SALVAGE, AI_INFERRED, UNKNOWN


@dataclass
class RecoveryResult:
    """Result of a recovery attempt."""
    success: bool
    data: bytes
    strategy: str  # exact_duplicate, structural_repair, object_reference_repair, stream_recovery, page_level_salvage, content_inference
    confidence: float
    validation: Dict[str, Any]
    errors: List[str]
    warnings: List[str]


@dataclass
class ValidationResult:
    """Result of format-specific validation."""
    valid: bool
    format: str
    checks: Dict[str, Any]
    anomalies: List[str]
    warnings: List[str]


class BaseAnalyzer(ABC):
    """
    Base class for all format-specific analyzers.
    
    The generic pipeline uses this interface to:
    1. Identify file type
    2. Analyze fragments in context of the format
    3. Map damage to meaningful structures
    4. Attempt format-specific recovery
    5. Validate results
    """
    
    @property
    @abstractmethod
    def supported_file_types(self) -> List[str]:
        """List of file type identifiers this analyzer supports."""
        pass
    
    @property
    @abstractmethod
    def magic_bytes(self) -> List[bytes]:
        """Magic byte signatures for file identification."""
        pass
    
    @abstractmethod
    def identify(self, data: bytes) -> bool:
        """
        Check if this analyzer can handle the given data.
        Uses magic bytes and structural validation.
        """
        pass
    
    @abstractmethod
    def analyze_fragment(self, fragment_data: bytes, offset: int, full_file_data: bytes) -> FragmentAnalysis:
        """
        Analyze a single fragment in the context of the file format.
        
        Returns FragmentAnalysis with format-specific insights.
        """
        pass
    
    @abstractmethod
    def map_damage(self, fragment_analyses: List[FragmentAnalysis], full_file_data: bytes) -> List[DamageRegion]:
        """
        Map suspicious/corrupted fragments to meaningful format structures.
        
        Examples:
        - PDF: Fragment -> object, page, stream, xref/trailer
        - PNG: Fragment -> PNG chunk (IHDR, IDAT, IEND)
        - JPEG: Fragment -> JPEG segment / image region
        - DOCX/XLSX: Fragment -> ZIP entry / XML structure
        - SQLite: Fragment -> page / database structure
        """
        pass
    
    @abstractmethod
    def attempt_recovery(self, damage_regions: List[DamageRegion], fragment_data_map: Dict[str, bytes], full_file_data: bytes) -> Dict[int, RecoveryResult]:
        """
        Attempt recovery for damaged regions using format-specific strategies.
        
        Strategy order:
        1. Exact surviving duplicate
        2. Structural repair (headers, footers, tables)
        3. Object/reference repair (xref, FAT, B-tree)
        4. Stream/chunk/segment salvage
        5. Page/region-level salvage
        6. Contextual AI inference (only when justified)
        
        Returns mapping of region offset -> RecoveryResult.
        """
        pass
    
    @abstractmethod
    def validate(self, data: bytes) -> ValidationResult:
        """
        Validate the recovered/repaired file using format-specific checks.
        
        Must verify structural integrity, not just that the file opens.
        """
        pass
    
    def get_fragment_hash(self, fragment_data: bytes) -> str:
        """Calculate SHA-256 hash of fragment."""
        import hashlib
        return hashlib.sha256(fragment_data).hexdigest()
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        import math
        from collections import Counter
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return round(entropy, 4)
    
    def calculate_zero_ratio(self, data: bytes) -> float:
        """Calculate percentage of zero bytes."""
        if not data:
            return 0.0
        return round(data.count(0) / len(data), 4)
    
    def calculate_unique_ratio(self, data: bytes) -> float:
        """Calculate byte diversity ratio."""
        if not data:
            return 0.0
        return round(len(set(data)) / 256, 4)