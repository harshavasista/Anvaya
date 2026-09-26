"""Unit tests asserting reproducible severity rubric calculations per Section 27a."""
import pytest
from backend.integrity.corruption_detector import analyze_corruption


def test_severity_rubric_thresholds():
    # Empty file: catastrophic failure -> SEVERELY_CORRUPTED
    empty_res = analyze_corruption(b"", "PDF", "empty.pdf")
    assert empty_res["status"] == "SEVERELY_CORRUPTED"
    assert empty_res["severity"] == "SEVERELY_CORRUPTED"
    assert empty_res["affected_ratio"] == 1.0

    # Partially damaged TXT: 1 check failed out of 3 checks (ratio = 1/3 ~ 0.33)
    damaged_txt = b"Hello world with some nulls\x00\x00\x00"
    txt_res = analyze_corruption(damaged_txt, "TXT", "damaged.txt")
    assert txt_res["corruption_detected"] is True
    assert txt_res["status"] in ("PARTIALLY_CORRUPTED", "CORRUPTED")
