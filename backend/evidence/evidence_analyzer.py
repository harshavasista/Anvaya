"""Stream and summarize the contents of a supplied evidence file.

This module reports hashes for the bytes that are actually present. It does
not reconstruct missing data or infer whether supplied bytes are authentic.
"""

import hashlib
import os
from pathlib import Path


_MAGIC_FILE_TYPES = (
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"SQLite format 3\x00", "SQLite"),
)


def _normalize_reference_hashes(
    reference_hashes: dict[int, str] | list[dict[str, int | str]] | None,
) -> dict[int, str]:
    """Convert supported reference-hash formats into an index-to-hash map."""
    if reference_hashes is None:
        return {}

    normalized = {}
    if isinstance(reference_hashes, dict):
        records = reference_hashes.items()
    elif isinstance(reference_hashes, list):
        records = []
        for record in reference_hashes:
            if not isinstance(record, dict) or "index" not in record or "sha256" not in record:
                raise ValueError("Each reference hash record must contain 'index' and 'sha256'.")
            records.append((record["index"], record["sha256"]))
    else:
        raise TypeError("reference_hashes must be a dictionary, a list of records, or None.")

    for index, digest in records:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("Reference fragment indexes must be non-negative integers.")
        if not isinstance(digest, str) or not digest:
            raise ValueError(f"Reference hash for fragment {index} must be a non-empty string.")
        normalized[index] = digest.lower()
    return normalized


def _normalize_expected_indexes(
    expected_indexes: list[int] | set[int] | tuple[int, ...] | None,
) -> set[int]:
    """Validate expected indexes and return them as a set."""
    if expected_indexes is None:
        return set()
    if not isinstance(expected_indexes, (list, set, tuple)):
        raise TypeError("expected_indexes must be a list, set, tuple, or None.")

    indexes = set()
    for index in expected_indexes:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("Expected fragment indexes must be non-negative integers.")
        indexes.add(index)
    return indexes


def _detect_file_type(first_chunk: bytes, path: str) -> str:
    """Identify common formats from their signatures, then use the extension."""
    for signature, file_type in _MAGIC_FILE_TYPES:
        if first_chunk.startswith(signature):
            return file_type

    # DOCX files are ZIP containers, so their extension distinguishes them
    # from a generic ZIP archive when the ZIP signature is present.
    is_zip = first_chunk.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    extension = Path(path).suffix.lower()
    if is_zip:
        return "DOCX" if extension == ".docx" else "ZIP"

    extension_types = {
        ".pdf": "PDF",
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".zip": "ZIP",
        ".sqlite": "SQLite",
        ".sqlite3": "SQLite",
        ".db": "SQLite",
        ".txt": "TXT",
        ".docx": "DOCX",
    }
    return extension_types.get(extension, "UNKNOWN")


class EvidenceAnalyzer:
    """Analyze file fragments without loading the complete file into memory.

    ``observed`` means bytes were supplied and hashed, but no reference hash
    confirms their original integrity. Recovery percentages without reference
    hashes describe observation against optional expected indexes only; they
    are not proof that the original evidence has been recovered.
    """

    def __init__(self, fragment_size: int = 4096) -> None:
        if isinstance(fragment_size, bool) or not isinstance(fragment_size, int) or fragment_size <= 0:
            raise ValueError("fragment_size must be a positive integer.")
        self.fragment_size = fragment_size

    def analyze(
        self,
        file_path: str | os.PathLike[str],
        reference_hashes: dict[int, str] | list[dict[str, int | str]] | None = None,
        expected_indexes: list[int] | set[int] | tuple[int, ...] | None = None,
    ) -> dict[str, object]:
        """Read and hash one fragment at a time, returning a JSON-safe summary."""
        if not isinstance(file_path, (str, os.PathLike)):
            raise TypeError("file_path must be a string or path-like value.")
        path = os.fspath(file_path)
        if not isinstance(path, str) or not path.strip():
            raise ValueError("file_path must not be empty and must be a valid filesystem path.")

        references = _normalize_reference_hashes(reference_hashes)
        expected = _normalize_expected_indexes(expected_indexes)
        expected.update(references)

        whole_file_hash = hashlib.sha256()
        fragments = []
        seen_fragment_hashes = set()
        duplicate_fragments = 0
        size_bytes = 0
        first_chunk = b""

        try:
            with open(path, "rb") as f:
                index = 0
                while True:
                    # Keep exactly one fragment in memory at a time.
                    chunk = f.read(self.fragment_size)
                    if not chunk:
                        break
                    if index == 0:
                        first_chunk = chunk

                    whole_file_hash.update(chunk)
                    fragment_hash = hashlib.sha256(chunk).hexdigest()
                    size = len(chunk)
                    size_bytes += size

                    if fragment_hash in seen_fragment_hashes:
                        duplicate_fragments += 1
                    else:
                        seen_fragment_hashes.add(fragment_hash)

                    reference_hash = references.get(index)
                    if reference_hash is None:
                        status = "observed"
                    elif fragment_hash.lower() == reference_hash:
                        status = "intact"
                    else:
                        status = "corrupted"

                    fragments.append(
                        {
                            "index": index,
                            "id": f"fragment_{index:04d}",
                            "filename": f"fragment_{index:04d}.bin",
                            "offset": index * self.fragment_size,
                            "size": size,
                            "sha256": fragment_hash,
                            "status": status,
                        }
                    )
                    index += 1
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Evidence file was not found: {path}") from exc
        except OSError as exc:
            raise RuntimeError(f"Evidence file could not be read: {path}: {exc}") from exc

        present_indexes = {fragment["index"] for fragment in fragments}
        missing_indexes = sorted(expected - present_indexes)
        intact_fragments = sum(fragment["status"] == "intact" for fragment in fragments)
        corrupted_fragments = sum(fragment["status"] == "corrupted" for fragment in fragments)

        if references:
            # Reference indexes and explicit expectations form the known set
            # of fragments against which recovery can be measured.
            expected_total = len(expected)
            recovery_percentage = (
                round(intact_fragments / expected_total * 100, 2) if expected_total else 0.0
            )
        elif expected:
            observed_expected = len(expected & present_indexes)
            recovery_percentage = round(observed_expected / len(expected) * 100, 2)
        else:
            # Every supplied fragment was observed, but authenticity is unknown.
            recovery_percentage = 100.0

        return {
            "filename": os.path.basename(path),
            "file_type": _detect_file_type(first_chunk, path),
            "size_bytes": size_bytes,
            "sha256": whole_file_hash.hexdigest(),
            "fragment_size": self.fragment_size,
            "total_fragments": len(fragments),
            "intact_fragments": intact_fragments,
            "corrupted_fragments": corrupted_fragments,
            "missing_fragments": len(missing_indexes),
            "duplicate_fragments": duplicate_fragments,
            "recovery_percentage": recovery_percentage,
            "fragments": fragments,
            "missing_fragment_indexes": missing_indexes,
        }


def analyze_evidence(
    file_path: str | os.PathLike[str],
    fragment_size: int = 4096,
    reference_hashes: dict[int, str] | list[dict[str, int | str]] | None = None,
    expected_indexes: list[int] | set[int] | tuple[int, ...] | None = None,
) -> dict[str, object]:
    """Convenience wrapper for analyzing a file with a chosen fragment size."""
    return EvidenceAnalyzer(fragment_size=fragment_size).analyze(
        file_path,
        reference_hashes=reference_hashes,
        expected_indexes=expected_indexes,
    )
