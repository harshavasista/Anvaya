import hashlib
import json
import os
from datetime import datetime


def calculate_file_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(8192)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def create_audit_event(
    event,
    description,
    file_path=None,
    metadata=None
):
    """
    Create one tamper-evident audit event.
    """

    event_data = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "description": description
    }

    if file_path and os.path.exists(file_path):

        event_data["file"] = {
            "path": file_path,
            "sha256": calculate_file_hash(
                file_path
            ),
            "size_bytes": os.path.getsize(
                file_path
            )
        }

    if metadata:

        event_data["metadata"] = metadata

    return event_data


def save_audit_log(
    case_id,
    events,
    output_dir="results"
):
    """
    Save the case audit trail as JSON.
    """

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    audit_path = os.path.join(
        output_dir,
        f"{case_id}_audit.json"
    )

    audit_data = {
        "case_id": case_id,
        "audit_version": "1.0",
        "created_at": datetime.now().isoformat(),
        "events": events
    }

    with open(
        audit_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            audit_data,
            file,
            indent=4
        )

    audit_hash = calculate_file_hash(
        audit_path
    )

    return {
        "audit_file": audit_path,
        "audit_sha256": audit_hash,
        "event_count": len(events)
    }