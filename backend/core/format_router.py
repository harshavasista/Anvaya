"""
Format Router and Detection Engine for ANVAYA.
Accurately identifies digital evidence format using magic bytes, container inspection,
and encoding analysis, without relying solely on file extensions.
"""

import io
import json
import csv
import zipfile
from typing import Dict, Any, Optional
from pathlib import Path


MIME_MAP = {
    "PDF": "application/pdf",
    "JSON": "application/json",
    "TXT": "text/plain",
    "CSV": "text/csv",
    "XML": "application/xml",
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "ZIP": "application/zip",
    "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "SQLite": "application/vnd.sqlite3",
    "GENERIC_BINARY": "application/octet-stream"
}


def detect_format(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Detect format with precision:
    Returns {
        "file_type": str,
        "mime_type": str,
        "extension": str,
        "detected_by": str,  # "magic_bytes" | "container_inspection" | "content_heuristic"
        "parseable": bool
    }
    """
    ext = Path(filename).suffix.lower() if filename else ""

    # 1. PDF
    if data.startswith(b"%PDF") or (len(data) > 10 and b"%PDF-" in data[:1024]):
        return {
            "file_type": "PDF",
            "mime_type": MIME_MAP["PDF"],
            "extension": ext or ".pdf",
            "detected_by": "magic_bytes",
            "parseable": True
        }

    # 2. PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return {
            "file_type": "PNG",
            "mime_type": MIME_MAP["PNG"],
            "extension": ext or ".png",
            "detected_by": "magic_bytes",
            "parseable": True
        }

    # 3. JPEG
    if data.startswith(b"\xFF\xD8\xFF"):
        return {
            "file_type": "JPEG",
            "mime_type": MIME_MAP["JPEG"],
            "extension": ext or ".jpg",
            "detected_by": "magic_bytes",
            "parseable": True
        }

    # 4. SQLite
    if data.startswith(b"SQLite format 3\x00"):
        return {
            "file_type": "SQLite",
            "mime_type": MIME_MAP["SQLite"],
            "extension": ext or ".sqlite",
            "detected_by": "magic_bytes",
            "parseable": True
        }

    # 5. ZIP containers (ZIP, DOCX, XLSX)
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
                if "word/document.xml" in names or any(n.startswith("word/") for n in names):
                    return {
                        "file_type": "DOCX",
                        "mime_type": MIME_MAP["DOCX"],
                        "extension": ext or ".docx",
                        "detected_by": "container_inspection",
                        "parseable": True
                    }
                if "xl/workbook.xml" in names or any(n.startswith("xl/") for n in names):
                    return {
                        "file_type": "XLSX",
                        "mime_type": MIME_MAP["XLSX"],
                        "extension": ext or ".xlsx",
                        "detected_by": "container_inspection",
                        "parseable": True
                    }
                return {
                    "file_type": "ZIP",
                    "mime_type": MIME_MAP["ZIP"],
                    "extension": ext or ".zip",
                    "detected_by": "magic_bytes",
                    "parseable": True
                }
        except Exception:
            # Corrupted ZIP container
            if ext == ".docx":
                return {
                    "file_type": "DOCX",
                    "mime_type": MIME_MAP["DOCX"],
                    "extension": ".docx",
                    "detected_by": "container_heuristic",
                    "parseable": False
                }
            if ext == ".xlsx":
                return {
                    "file_type": "XLSX",
                    "mime_type": MIME_MAP["XLSX"],
                    "extension": ".xlsx",
                    "detected_by": "container_heuristic",
                    "parseable": False
                }
            return {
                "file_type": "ZIP",
                "mime_type": MIME_MAP["ZIP"],
                "extension": ext or ".zip",
                "detected_by": "magic_bytes",
                "parseable": False
            }

    # 6. JSON Check
    stripped = data.strip()
    if (stripped.startswith(b"{") and b"}" in stripped) or (stripped.startswith(b"[") and b"]" in stripped) or ext == ".json":
        try:
            json.loads(data.decode("utf-8"))
            return {
                "file_type": "JSON",
                "mime_type": MIME_MAP["JSON"],
                "extension": ext or ".json",
                "detected_by": "content_heuristic",
                "parseable": True
            }
        except Exception:
            if stripped.startswith(b"{") or stripped.startswith(b"[") or ext == ".json":
                return {
                    "file_type": "JSON",
                    "mime_type": MIME_MAP["JSON"],
                    "extension": ext or ".json",
                    "detected_by": "content_heuristic",
                    "parseable": False
                }

    # 7. XML Check
    if stripped.startswith(b"<?xml") or (stripped.startswith(b"<") and b">" in stripped and b"</" in stripped):
        return {
            "file_type": "XML",
            "mime_type": MIME_MAP["XML"],
            "extension": ext or ".xml",
            "detected_by": "content_heuristic",
            "parseable": True
        }

    # 8. CSV Check
    if ext == ".csv":
        return {
            "file_type": "CSV",
            "mime_type": MIME_MAP["CSV"],
            "extension": ".csv",
            "detected_by": "extension_and_content",
            "parseable": True
        }

    # 9. Plain Text
    if ext == ".txt":
        return {
            "file_type": "TXT",
            "mime_type": MIME_MAP["TXT"],
            "extension": ".txt",
            "detected_by": "extension_and_content",
            "parseable": True
        }

    try:
        decoded = data.decode("utf-8")
        # Check printable character ratio
        printable_count = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
        if len(decoded) > 0 and (printable_count / len(decoded)) > 0.85:
            # Check if it could be CSV without .csv extension
            lines = [l for l in decoded.splitlines() if l.strip()]
            if len(lines) >= 2 and ("," in lines[0] or ";" in lines[0] or "\t" in lines[0]):
                delim = "," if "," in lines[0] else (";" if ";" in lines[0] else "\t")
                row_lens = [len(l.split(delim)) for l in lines[:5]]
                if len(set(row_lens)) == 1 and row_lens[0] > 1:
                    return {
                        "file_type": "CSV",
                        "mime_type": MIME_MAP["CSV"],
                        "extension": ext or ".csv",
                        "detected_by": "content_heuristic",
                        "parseable": True
                    }

            return {
                "file_type": "TXT",
                "mime_type": MIME_MAP["TXT"],
                "extension": ext or ".txt",
                "detected_by": "content_heuristic",
                "parseable": True
            }
    except UnicodeDecodeError:
        pass

    # 10. Fallback: Generic Binary
    return {
        "file_type": "GENERIC_BINARY",
        "mime_type": MIME_MAP["GENERIC_BINARY"],
        "extension": ext or ".bin",
        "detected_by": "fallback",
        "parseable": False
    }
