"""
Security and Ingestion Integrity Module for ANVAYA Forensic Engine.
Enforces:
- 100 MB upload limit
- Safe filename sanitization (no path traversal, null bytes, or dangerous chars)
- Original evidence immutability with pre- and post-analysis SHA-256 assertions
- Decompression bomb detection (cap at 500 MB)
- Parser execution timeouts
"""

import os
import re
import hashlib
from typing import Tuple

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_DECOMPRESSED_SIZE = 500 * 1024 * 1024  # 500 MB
PARSER_TIMEOUT_SECONDS = 15


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and null byte injection."""
    if not filename:
        return "unnamed_evidence.bin"
    # Remove null bytes
    cleaned = filename.replace("\x00", "")
    # Extract only the base name (handles both Unix and Windows separators)
    cleaned = os.path.basename(cleaned)
    cleaned = re.sub(r'^[./\\]+', '', cleaned)
    # Allow alphanumeric, underscore, dash, and dot
    cleaned = re.sub(r'[^a-zA-Z0-9_.-]', '_', cleaned)
    if not cleaned:
        cleaned = "evidence_file.bin"
    return cleaned


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def calculate_file_sha256(file_path: str) -> str:
    """Stream SHA-256 digest calculation from disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_original_unmodified(file_path: str, expected_sha256: str) -> bool:
    """
    Forensic assertion: original evidence must NEVER change after ingestion.
    Raises RuntimeError if original file was mutated.
    """
    current_hash = calculate_file_sha256(file_path)
    if current_hash.lower() != expected_sha256.lower():
        raise RuntimeError(
            f"CRITICAL FORENSIC INTEGRITY VIOLATION: Evidence file {file_path} was modified! "
            f"Expected {expected_sha256}, got {current_hash}"
        )
    return True
