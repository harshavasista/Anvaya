"""Unit tests for corruption detector and format identification."""
import os
import pytest
from backend.core.format_router import detect_format
from backend.integrity.corruption_detector import analyze_corruption


def test_clean_pdf_healthy():
    pdf_path = os.path.join("data", "demo", "clean_evidence.pdf")
    with open(pdf_path, "rb") as f:
        data = f.read()
    fmt = detect_format(data, "clean_evidence.pdf")
    assert fmt["file_type"] == "PDF"
    res = analyze_corruption(data, "PDF", "clean_evidence.pdf")
    assert res["status"] == "HEALTHY"
    assert res["corruption_detected"] is False
    assert res["affected_ratio"] == 0.0


def test_corrupted_pdf_detected():
    pdf_path = os.path.join("data", "demo", "corrupted_evidence.pdf")
    with open(pdf_path, "rb") as f:
        data = f.read()
    fmt = detect_format(data, "corrupted_evidence.pdf")
    assert fmt["file_type"] == "PDF"
    res = analyze_corruption(data, "PDF", "corrupted_evidence.pdf")
    assert res["status"] in ("CORRUPTED", "PARTIALLY_CORRUPTED", "SEVERELY_CORRUPTED")
    assert res["corruption_detected"] is True
    assert len(res["reasons"]) > 0


def test_clean_json_healthy():
    json_path = os.path.join("data", "demo", "clean_evidence.json")
    with open(json_path, "rb") as f:
        data = f.read()
    fmt = detect_format(data, "clean_evidence.json")
    assert fmt["file_type"] == "JSON"
    res = analyze_corruption(data, "JSON", "clean_evidence.json")
    assert res["status"] == "HEALTHY"
    assert res["corruption_detected"] is False


def test_corrupted_json_detected():
    json_path = os.path.join("data", "demo", "corrupted_evidence.json")
    with open(json_path, "rb") as f:
        data = f.read()
    fmt = detect_format(data, "corrupted_evidence.json")
    assert fmt["file_type"] == "JSON"
    res = analyze_corruption(data, "JSON", "corrupted_evidence.json")
    assert res["status"] in ("CORRUPTED", "PARTIALLY_CORRUPTED", "SEVERELY_CORRUPTED")
    assert res["corruption_detected"] is True
