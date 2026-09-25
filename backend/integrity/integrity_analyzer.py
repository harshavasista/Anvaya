import os
import hashlib
from collections import defaultdict


def scan_fragments(fragment_dir):
    """
    Scan all fragment files and calculate their hashes.
    """

    fragments = []

    for filename in sorted(os.listdir(fragment_dir)):

        if not filename.endswith(".bin"):
            continue

        path = os.path.join(fragment_dir, filename)

        with open(path, "rb") as f:
            data = f.read()

        sha256 = hashlib.sha256(data).hexdigest()

        fragments.append({
            "filename": filename,
            "size": len(data),
            "sha256": sha256
        })

    return fragments


def find_duplicates(fragments):
    """
    Identify fragments having identical SHA-256 hashes.
    """

    hash_groups = defaultdict(list)

    for fragment in fragments:
        hash_groups[fragment["sha256"]].append(
            fragment["filename"]
        )

    duplicate_groups = []

    for sha256, filenames in hash_groups.items():

        if len(filenames) > 1:
            duplicate_groups.append({
                "sha256": sha256,
                "files": filenames,
                "count": len(filenames)
            })

    return duplicate_groups


def generate_integrity_report(
    fragments,
    original_fragment_count
):

    duplicate_groups = find_duplicates(fragments)

    duplicate_files = sum(
        group["count"]
        for group in duplicate_groups
    )

    unique_fragments = len(fragments) - (
        duplicate_files - len(duplicate_groups)
    )

    missing_estimate = max(
        0,
        original_fragment_count - unique_fragments
    )

    coverage = (
        unique_fragments / original_fragment_count * 100
        if original_fragment_count
        else 0
    )

    return {
        "original_fragments": original_fragment_count,
        "physical_fragments": len(fragments),
        "unique_fragments": unique_fragments,
        "duplicate_groups": len(duplicate_groups),
        "duplicate_files": duplicate_files,
        "missing_estimate": missing_estimate,
        "coverage_percentage": round(coverage, 2),
        "duplicate_details": duplicate_groups
    }


if __name__ == "__main__":

    fragment_dir = "data/fragments"

    fragments = scan_fragments(fragment_dir)

    report = generate_integrity_report(
        fragments,
        original_fragment_count=79
    )

    print("\nANVAYA INTEGRITY REPORT")
    print("=======================")

    print(
        f"Original fragments       : "
        f"{report['original_fragments']}"
    )

    print(
        f"Physical fragments found : "
        f"{report['physical_fragments']}"
    )

    print(
        f"Unique fragments         : "
        f"{report['unique_fragments']}"
    )

    print(
        f"Duplicate groups         : "
        f"{report['duplicate_groups']}"
    )

    print(
        f"Duplicate files          : "
        f"{report['duplicate_files']}"
    )

    print(
        f"Missing estimate         : "
        f"{report['missing_estimate']}"
    )

    print(
        f"Coverage                 : "
        f"{report['coverage_percentage']}%"
    )

    if report["duplicate_details"]:

        print("\nDuplicate details:")

        for group in report["duplicate_details"]:

            print(
                f"- {group['files']} "
                f"({group['count']} copies)"
            )