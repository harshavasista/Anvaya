"""
File format validators for standalone forensic integrity analysis.

Provides format-specific integrity checks for standalone evidence analysis.
No reference original required - analyzes what is observable in the uploaded file.
"""

import struct
import zipfile
import sqlite3
import io
from typing import Dict, List, Any, Optional, Tuple


def validate_pdf(data: bytes) -> Dict[str, Any]:
    """
    Validate PDF structure and detect anomalies.
    
    Returns dict with validation results and anomaly indicators.
    """
    result = {
        "format": "PDF",
        "valid_header": False,
        "valid_eof": False,
        "has_xref": False,
        "has_trailer": False,
        "has_startxref": False,
        "object_count": 0,
        "page_count": 0,
        "readable_text_ratio": 0.0,
        "anomalies": [],
        "warnings": []
    }
    
    if not data.startswith(b"%PDF"):
        result["anomalies"].append("Missing PDF header (%PDF)")
        return result
    
    result["valid_header"] = True
    
    # Check for EOF marker
    if b"%%EOF" in data:
        result["valid_eof"] = True
    else:
        result["anomalies"].append("Missing EOF marker (%%EOF)")
    
    # Check for cross-reference table
    if b"xref" in data:
        result["has_xref"] = True
    else:
        result["anomalies"].append("Missing cross-reference table (xref)")
    
    # Check for trailer
    if b"trailer" in data:
        result["has_trailer"] = True
    else:
        result["anomalies"].append("Missing trailer dictionary")
    
    # Check for startxref
    if b"startxref" in data:
        result["has_startxref"] = True
    else:
        result["anomalies"].append("Missing startxref")
    
    # Count objects (rough estimate)
    result["object_count"] = data.count(b"obj")
    
    # Count pages (rough estimate)
    result["page_count"] = data.count(b"/Page")
    
    # Check for readable text content
    text_segments = []
    # Extract text between stream/endstream or in text objects
    # Simple heuristic: look for readable ASCII sequences
    try:
        # Look for text in content streams
        text_content = b""
        in_stream = False
        for i in range(len(data)):
            if data[i:i+6] == b"stream":
                in_stream = True
            elif data[i:i+9] == b"endstream":
                in_stream = False
            elif in_stream and 32 <= data[i] <= 126:
                text_content += bytes([data[i]])
        
        if len(text_content) > 0:
            printable = sum(1 for b in text_content if 32 <= b <= 126)
            result["readable_text_ratio"] = printable / len(text_content)
    except:
        pass
    
    # Check for encryption
    if b"/Encrypt" in data:
        result["warnings"].append("PDF is encrypted - content analysis limited")
    
    return result


def validate_jpeg(data: bytes) -> Dict[str, Any]:
    """
    Validate JPEG structure and detect anomalies.
    """
    result = {
        "format": "JPEG",
        "valid_header": False,
        "valid_eof": False,
        "has_sof": False,
        "has_dht": False,
        "has_dqt": False,
        "dimensions": None,
        "anomalies": [],
        "warnings": []
    }
    
    if not data.startswith(b"\xFF\xD8\xFF"):
        result["anomalies"].append("Missing JPEG header (FF D8 FF)")
        return result
    
    result["valid_header"] = True
    
    # Check for EOF marker
    if data.endswith(b"\xFF\xD9"):
        result["valid_eof"] = True
    else:
        result["anomalies"].append("Missing JPEG EOF marker (FF D9)")
    
    # Parse JPEG markers
    i = 2
    while i < len(data) - 1:
        if data[i] == 0xFF:
            marker = data[i+1]
            
            # SOF markers (Start of Frame) - contain dimensions
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                result["has_sof"] = True
                if i + 8 < len(data):
                    height = struct.unpack(">H", data[i+5:i+7])[0]
                    width = struct.unpack(">H", data[i+7:i+9])[0]
                    result["dimensions"] = {"width": width, "height": height}
            
            # DHT - Define Huffman Table
            elif marker == 0xC4:
                result["has_dht"] = True
            
            # DQT - Define Quantization Table
            elif marker == 0xDB:
                result["has_dqt"] = True
            
            # SOS - Start of Scan (compressed data follows)
            elif marker == 0xDA:
                break
            
            # Skip marker segment
            if i + 3 < len(data):
                length = struct.unpack(">H", data[i+2:i+4])[0]
                i += 2 + length
            else:
                break
        else:
            i += 1
    
    if not result["has_sof"]:
        result["anomalies"].append("Missing SOF marker (no image dimensions)")
    if not result["has_dht"]:
        result["anomalies"].append("Missing Huffman tables (DHT)")
    if not result["has_dqt"]:
        result["anomalies"].append("Missing quantization tables (DQT)")
    
    return result


def validate_png(data: bytes) -> Dict[str, Any]:
    """
    Validate PNG structure and detect anomalies.
    """
    result = {
        "format": "PNG",
        "valid_header": False,
        "valid_eof": False,
        "has_ihdr": False,
        "has_idat": False,
        "has_iend": False,
        "dimensions": None,
        "color_type": None,
        "bit_depth": None,
        "anomalies": [],
        "warnings": []
    }
    
    # Check PNG signature
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        result["anomalies"].append("Missing PNG signature")
        return result
    
    result["valid_header"] = True
    
    # Check for IEND chunk
    if b"IEND" in data:
        result["valid_eof"] = True
    else:
        result["anomalies"].append("Missing IEND chunk")
    
    # Parse chunks
    i = 8  # Skip signature
    while i < len(data) - 12:
        if i + 8 > len(data):
            break
        
        length = struct.unpack(">I", data[i:i+4])[0]
        chunk_type = data[i+4:i+8]
        
        if chunk_type == b"IHDR":
            result["has_ihdr"] = True
            if i + 8 + length <= len(data):
                ihdr_data = data[i+8:i+8+length]
                if len(ihdr_data) >= 13:
                    width = struct.unpack(">I", ihdr_data[0:4])[0]
                    height = struct.unpack(">I", ihdr_data[4:8])[0]
                    result["dimensions"] = {"width": width, "height": height}
                    result["bit_depth"] = ihdr_data[8]
                    color_types = {0: "Grayscale", 2: "RGB", 3: "Indexed", 4: "Grayscale+Alpha", 6: "RGBA"}
                    result["color_type"] = color_types.get(ihdr_data[9], f"Unknown({ihdr_data[9]})")
        
        elif chunk_type == b"IDAT":
            result["has_idat"] = True
        
        elif chunk_type == b"IEND":
            result["has_iend"] = True
            break
        
        i += 12 + length
    
    if not result["has_ihdr"]:
        result["anomalies"].append("Missing IHDR chunk")
    if not result["has_idat"]:
        result["anomalies"].append("Missing image data (IDAT)")
    if not result["has_iend"]:
        result["anomalies"].append("Missing IEND chunk")
    
    return result


def validate_txt(data: bytes) -> Dict[str, Any]:
    """
    Validate text file structure and detect anomalies.
    """
    result = {
        "format": "TXT",
        "utf8_valid": False,
        "invalid_sequences": 0,
        "line_count": 0,
        "printable_ratio": 0.0,
        "null_bytes": 0,
        "anomalies": [],
        "warnings": []
    }
    
    # Check UTF-8 validity
    try:
        text = data.decode("utf-8")
        result["utf8_valid"] = True
    except UnicodeDecodeError as e:
        result["anomalies"].append(f"Invalid UTF-8 sequence at position {e.start}")
        result["invalid_sequences"] += 1
        # Try to decode with replacement
        text = data.decode("utf-8", errors="replace")
    
    # Count lines
    result["line_count"] = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    
    # Count null bytes
    result["null_bytes"] = data.count(0)
    if result["null_bytes"] > 0:
        result["anomalies"].append(f"Contains {result['null_bytes']} null bytes")
    
    # Calculate printable ratio
    if len(data) > 0:
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))  # tab, LF, CR
        result["printable_ratio"] = printable / len(data)
    
    if result["printable_ratio"] < 0.5:
        result["anomalies"].append("Low printable character ratio")
    
    return result


def validate_zip(data: bytes) -> Dict[str, Any]:
    """
    Validate ZIP/DOCX/XLSX structure and detect anomalies.
    """
    result = {
        "format": "ZIP/DOCX/XLSX",
        "valid_header": False,
        "has_central_directory": False,
        "file_count": 0,
        "total_uncompressed_size": 0,
        "total_compressed_size": 0,
        "files": [],
        "anomalies": [],
        "warnings": []
    }
    
    if not data.startswith(b"PK\x03\x04") and not data.startswith(b"PK\x05\x06") and not data.startswith(b"PK\x07\x08"):
        result["anomalies"].append("Missing ZIP signature")
        return result
    
    result["valid_header"] = True
    
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            # Check central directory
            if zf.filelist:
                result["has_central_directory"] = True
                result["file_count"] = len(zf.filelist)
                
                for info in zf.filelist:
                    result["total_uncompressed_size"] += info.file_size
                    result["total_compressed_size"] += info.compress_size
                    result["files"].append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "compression_ratio": round(info.compress_size / info.file_size, 2) if info.file_size > 0 else 0
                    })
                
                # Check for DOCX/XLSX specific structures
                filenames = [f.filename for f in zf.filelist]
                if "[Content_Types].xml" in filenames:
                    result["format"] = "DOCX/XLSX (Office Open XML)"
                    if "word/document.xml" in filenames:
                        result["format"] = "DOCX"
                    elif "xl/workbook.xml" in filenames:
                        result["format"] = "XLSX"
            else:
                result["anomalies"].append("ZIP archive is empty")
    
    except zipfile.BadZipFile as e:
        result["anomalies"].append(f"Invalid ZIP structure: {str(e)}")
    except Exception as e:
        result["anomalies"].append(f"ZIP parsing error: {str(e)}")
    
    return result


def validate_sqlite(data: bytes) -> Dict[str, Any]:
    """
    Validate SQLite database structure and detect anomalies.
    """
    result = {
        "format": "SQLite",
        "valid_header": False,
        "page_size": 0,
        "database_size": 0,
        "table_count": 0,
        "tables": [],
        "anomalies": [],
        "warnings": []
    }
    
    if not data.startswith(b"SQLite format 3\x00"):
        result["anomalies"].append("Missing SQLite header")
        return result
    
    result["valid_header"] = True
    
    # Parse header
    if len(data) >= 100:
        result["page_size"] = struct.unpack(">H", data[16:18])[0]
        result["database_size"] = struct.unpack(">I", data[28:32])[0] * result["page_size"]
    
    # Try to open and query
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        
        # Get table count
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        result["table_count"] = cursor.fetchone()[0]
        
        # Get table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        result["tables"] = [row[0] for row in cursor.fetchall()]
        
        # Quick integrity check
        cursor.execute("PRAGMA integrity_check")
        integrity_result = cursor.fetchone()[0]
        if integrity_result != "ok":
            result["anomalies"].append(f"Integrity check failed: {integrity_result}")
        
        conn.close()
        import os
        os.unlink(tmp_path)
        
    except Exception as e:
        result["anomalies"].append(f"SQLite analysis error: {str(e)}")
    
    return result


def validate_generic_binary(data: bytes) -> Dict[str, Any]:
    """
    Generic binary file analysis.
    """
    result = {
        "format": "Unknown Binary",
        "size": len(data),
        "entropy": 0.0,
        "zero_ratio": 0.0,
        "unique_ratio": 0.0,
        "printable_ratio": 0.0,
        "anomalies": [],
        "warnings": []
    }
    
    if len(data) == 0:
        result["anomalies"].append("Empty file")
        return result
    
    from collections import Counter
    import math
    
    # Entropy
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    result["entropy"] = round(entropy, 4)
    
    # Zero ratio
    zero_bytes = data.count(0)
    result["zero_ratio"] = round(zero_bytes / length, 4)
    if result["zero_ratio"] > 0.5:
        result["anomalies"].append("Large proportion of zero-filled bytes")
    
    # Unique byte ratio
    result["unique_ratio"] = round(len(counts) / 256, 4)
    if result["unique_ratio"] < 0.1:
        result["anomalies"].append("Very low byte diversity")
    
    # Printable ratio
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    result["printable_ratio"] = round(printable / length, 4)
    
    if result["entropy"] > 7.95:
        result["anomalies"].append("Very high entropy / random-looking data")
    elif result["entropy"] < 1.0:
        result["anomalies"].append("Very low entropy / highly repetitive data")
    
    return result


def validate_file(data: bytes, file_type: str) -> Dict[str, Any]:
    """
    Dispatch to appropriate validator based on file type.
    """
    validators = {
        "PDF": validate_pdf,
        "JPEG": validate_jpeg,
        "PNG": validate_png,
        "TXT": validate_txt,
        "ZIP/DOCX/XLSX": validate_zip,
        "SQLite": validate_sqlite,
    }
    
    validator = validators.get(file_type, validate_generic_binary)
    return validator(data)


# For struct import
import struct