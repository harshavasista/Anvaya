import os
import hashlib
from collections import Counter


def load_fragments(fragment_dir):
    fragments = []

    for filename in sorted(os.listdir(fragment_dir)):
        if not filename.endswith(".bin"):
            continue

        path = os.path.join(fragment_dir, filename)

        with open(path, "rb") as f:
            data = f.read()

        fragments.append({
            "filename": filename,
            "data": data,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data)
        })

    return fragments


def detect_duplicates(fragments):
    hash_counts = Counter(
        fragment["sha256"] for fragment in fragments
    )

    duplicates = []

    for fragment in fragments:
        if hash_counts[fragment["sha256"]] > 1:
            duplicates.append(fragment["filename"])

    return duplicates


def reconstruct_by_available_order(fragments, output_path):
    """
    Baseline reconstruction.

    The current damaged dataset has shuffled fragments,
    so this function does NOT claim that alphabetical order
    is the true original order. It creates a candidate output
    for integrity testing only.
    """

    with open(output_path, "wb") as output:

        for fragment in fragments:
            output.write(fragment["data"])


def create_recovery_report(
    fragments,
    duplicates,
    original_fragment_count
):
    available = len(fragments)

    duplicate_count = len(duplicates)

    return {
        "original_fragments": original_fragment_count,
        "available_fragments": available,
        "duplicate_fragments": duplicate_count,
        "missing_fragments_estimate":
            max(0, original_fragment_count - available),
        "recovery_coverage":
            round((available / original_fragment_count) * 100, 2)
            if original_fragment_count else 0
    }


if __name__ == "__main__":

    fragment_dir = "data/fragments"
    output_path = "data/recovered_candidate.pdf"

    fragments = load_fragments(fragment_dir)

    duplicates = detect_duplicates(fragments)

    # We know this for our controlled test dataset.
    original_fragment_count = 79

    reconstruct_by_available_order(
        fragments,
        output_path
    )

    report = create_recovery_report(
        fragments,
        duplicates,
        original_fragment_count
    )

    print("ANVAYA RECONSTRUCTION")
    print("=====================")

    print(f"Original fragments : {report['original_fragments']}")
    print(f"Available fragments: {report['available_fragments']}")
    print(f"Duplicate fragments: {report['duplicate_fragments']}")
    print(f"Missing estimate   : {report['missing_fragments_estimate']}")
    print(f"Coverage           : {report['recovery_coverage']}%")

    print(f"\nCandidate output: {output_path}")