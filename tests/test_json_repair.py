"""Unit tests for JSON repair and strict reparse validation."""
import json
import pytest
from backend.recovery.json_repairer import repair_json


def test_json_native_repair_unclosed_brace():
    damaged = b'{"status": "active", "code": 200, "details": "all clear'
    candidate, details = repair_json(damaged, reference_data=None)
    assert candidate is not None
    assert details["validation"]["status"] == "VALIDATED"
    assert details["validation"]["valid"] is True
    # Verify strict re-parse
    obj = json.loads(candidate.decode("utf-8"))
    assert obj["status"] == "active"
    assert obj["code"] == 200


def test_json_failed_repair_not_falsely_claimed():
    # Complete garbage that cannot be repaired
    garbage = b"}{][THIS_IS_NOT_JSON_AT_ALL---x9928"
    candidate, details = repair_json(garbage, reference_data=None)
    # If it fails to parse, it MUST NOT be called valid or recovered
    assert candidate is None
    assert details["validation"]["valid"] is False
    assert details["validation"]["status"] == "VALIDATION_FAILED"
