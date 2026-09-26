"""
Anvaya Analyzers Package

Modular format-specific analyzers for digital evidence analysis.
Each analyzer implements the BaseAnalyzer interface.
"""

from backend.analyzers.base_analyzer import BaseAnalyzer
from backend.analyzers.pdf_analyzer import PDFAnalyzer
from backend.analyzers.image_analyzer import ImageAnalyzer
from backend.analyzers.text_analyzer import TextAnalyzer
from backend.analyzers.office_analyzer import OfficeAnalyzer
from backend.analyzers.zip_analyzer import ZipAnalyzer
from backend.analyzers.sqlite_analyzer import SQLiteAnalyzer
from backend.analyzers.generic_analyzer import GenericBinaryAnalyzer

__all__ = [
    "BaseAnalyzer",
    "PDFAnalyzer",
    "ImageAnalyzer",
    "TextAnalyzer",
    "OfficeAnalyzer",
    "ZipAnalyzer",
    "SQLiteAnalyzer",
    "GenericBinaryAnalyzer",
    "get_analyzer_for_file_type",
]


def get_analyzer_for_file_type(file_type: str) -> BaseAnalyzer:
    """Factory function to get the appropriate analyzer for a file type."""
    analyzers = {
        "PDF": PDFAnalyzer(),
        "JPEG": ImageAnalyzer(),
        "PNG": ImageAnalyzer(),
        "TXT": TextAnalyzer(),
        "DOCX": OfficeAnalyzer(),
        "XLSX": OfficeAnalyzer(),
        "ZIP": ZipAnalyzer(),
        "SQLite": SQLiteAnalyzer(),
    }
    return analyzers.get(file_type, GenericBinaryAnalyzer())