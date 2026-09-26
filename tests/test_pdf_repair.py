"""Unit tests for PDF recovery and independent candidate validation."""
import os
import pymupdf
import pytest
from backend.recovery.pdf_repairer import repair_pdf


def test_pdf_repair_with_reference():
    with open("data/demo/corrupted_evidence.pdf", "rb") as f:
        damaged_data = f.read()
    with open("data/demo/clean_evidence.pdf", "rb") as f:
        reference_data = f.read()

    candidate, details = repair_pdf(damaged_data, reference_data)
    assert candidate is not None
    assert details["validation"]["status"] == "VALIDATED"
    assert details["validation"]["valid"] is True
    assert details["recovered_sha256"] is not None

    # Reopen to guarantee valid PDF
    doc = pymupdf.open(stream=candidate, filetype="pdf")
    assert doc.page_count > 0
    doc.close()


def test_pdf_native_repair():
    # Minor damage: missing EOF
    with open("data/demo/clean_evidence.pdf", "rb") as f:
        clean_data = f.read()
    damaged_no_eof = clean_data.replace(b"%%EOF", b"     ")
    candidate, details = repair_pdf(damaged_no_eof, reference_data=None)
    assert candidate is not None
    assert details["validation"]["valid"] is True
