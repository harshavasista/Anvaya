import os
import hashlib


def split_original_file(source_file, fragment_size=4096):
    """
    Split the original evidence file into reference fragments.
    """

    fragments = []

    with open(source_file, "rb") as file:

        index = 0

        while True:

            data = file.read(fragment_size)

            if not data:
                break

            fragments.append({
                "original_index": index,
                "data": data,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data)
            })

            index += 1

    return fragments


def load_damaged_fragments(fragment_dir):
    """
    Load all surviving physical fragments.
    """

    fragments = []

    for filename in sorted(os.listdir(fragment_dir)):

        if not filename.endswith(".bin"):
            continue

        path = os.path.join(
            fragment_dir,
            filename
        )

        with open(path, "rb") as file:
            data = file.read()

        fragments.append({
            "filename": filename,
            "data": data,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data)
        })

    return fragments


def compare_fragments(
    original_fragments,
    damaged_fragments
):
    """
    Compare damaged fragments against the original.

    Each original fragment receives exactly ONE
    classification:

        INTACT
        CORRUPTED
        MISSING

    Duplicate physical copies are not counted as
    separate original fragments.
    """

    results = []

    # -------------------------------------------------
    # SHA-256 lookup for original fragments
    # -------------------------------------------------

    original_by_hash = {}

    for fragment in original_fragments:
        fragment_hash = fragment["sha256"]

        if fragment_hash not in original_by_hash:
            original_by_hash[fragment_hash] = []

        original_by_hash[fragment_hash].append(
            fragment["original_index"]
        )

    # -------------------------------------------------
    # Track original fragments already identified
    # -------------------------------------------------

    matched_original_indexes = set()

    # Store the physical filename associated with
    # each original fragment.
    intact_matches = {}

    # -------------------------------------------------
    # STEP 1: Exact SHA-256 matching
    # -------------------------------------------------

    for damaged in damaged_fragments:

        possible_indexes = original_by_hash.get(
            damaged["sha256"]
        )

        if not possible_indexes:
            continue

        # Assign this physical fragment to one original position
        # that has not already been matched.
        original_index = next(
            (
                index
                for index in possible_indexes
                if index not in matched_original_indexes
            ),
            None
        )

        # Extra physical copies do not represent new originals.
        if original_index is None:
            continue

        matched_original_indexes.add(
            original_index
        )

        intact_matches[original_index] = {
            "filename": damaged["filename"],
            "original_index": original_index,
            "status": "INTACT",
            "sha256_match": True,
            "changed_bytes": 0
        }

    # -------------------------------------------------
    # STEP 2: Find original fragments that don't have
    # an exact SHA-256 match.
    # -------------------------------------------------

    unmatched_originals = [
        fragment
        for fragment in original_fragments
        if fragment["original_index"]
        not in matched_original_indexes
    ]

    # -------------------------------------------------
    # STEP 3: Find physical fragments that don't have
    # an exact original SHA-256 match.
    # -------------------------------------------------

    unmatched_damaged = [
        fragment
        for fragment in damaged_fragments
        if fragment["sha256"]
        not in original_by_hash
    ]

    # -------------------------------------------------
    # STEP 4: Match corrupted fragments using
    # byte-by-byte comparison.
    # -------------------------------------------------

    corrupted_matches = {}

    used_original_indexes = set()

    for damaged in unmatched_damaged:

        best_match = None
        best_difference = None

        for original in unmatched_originals:

            original_index = original[
                "original_index"
            ]

            if original_index in used_original_indexes:
                continue

            # Corrupted fragments from our simulator
            # retain the original size.
            if len(original["data"]) != len(
                damaged["data"]
            ):
                continue

            difference_count = 0

            for a, b in zip(
                original["data"],
                damaged["data"]
            ):

                if a != b:
                    difference_count += 1

            if (
                best_difference is None
                or difference_count < best_difference
            ):

                best_difference = difference_count
                best_match = original

        # Only classify as corrupted if we found
        # a non-identical candidate.
        if (
            best_match is not None
            and best_difference is not None
            and best_difference > 0
        ):

            original_index = best_match[
                "original_index"
            ]

            used_original_indexes.add(
                original_index
            )

            corrupted_matches[original_index] = {
                "filename": damaged["filename"],
                "original_index": original_index,
                "status": "CORRUPTED",
                "sha256_match": False,
                "changed_bytes": best_difference
            }

    # -------------------------------------------------
    # STEP 5: Build exactly ONE result per original
    # fragment.
    # -------------------------------------------------

    for original in original_fragments:

        index = original["original_index"]

        if index in intact_matches:

            results.append(
                intact_matches[index]
            )

        elif index in corrupted_matches:

            results.append(
                corrupted_matches[index]
            )

        else:

            results.append({
                "filename": None,
                "original_index": index,
                "status": "MISSING",
                "sha256_match": False,
                "changed_bytes": None
            })

    return results


def generate_corruption_report(results):
    """
    Generate statistics using the original fragment
    count as the denominator.
    """

    intact = 0
    corrupted = 0
    missing = 0

    total_changed_bytes = 0

    for result in results:

        status = result["status"]

        if status == "INTACT":

            intact += 1

        elif status == "CORRUPTED":

            corrupted += 1

            total_changed_bytes += (
                result["changed_bytes"] or 0
            )

        elif status == "MISSING":

            missing += 1

    original_fragments = len(results)

    # Evidence represented by either an intact or
    # corrupted fragment.
    coverage_percentage = (
        (
            (intact + corrupted)
            / original_fragments
        ) * 100
        if original_fragments
        else 0
    )

    # Exact matches against the original evidence.
    intact_percentage = (
        (
            intact
            / original_fragments
        ) * 100
        if original_fragments
        else 0
    )

    return {
        "original_fragments": original_fragments,
        "intact_fragments": intact,
        "corrupted_fragments": corrupted,
        "missing_fragments": missing,
        "total_changed_bytes": total_changed_bytes,
        "coverage_percentage": round(
            coverage_percentage,
            2
        ),
        "intact_percentage": round(
            intact_percentage,
            2
        )
    }


if __name__ == "__main__":

    # =================================================
    # CONFIGURATION
    # =================================================

    source_file = (
        "data/input/"
        "mini_project_front-merged.pdf"
    )

    fragment_dir = "data/fragments"

    # =================================================
    # HEADER
    # =================================================

    print()
    print(
        "ANVAYA CORRUPTION DETECTION"
    )
    print(
        "==========================="
    )

    # =================================================
    # CHECK INPUTS
    # =================================================

    if not os.path.exists(source_file):

        print(
            f"Source file not found: "
            f"{source_file}"
        )

        raise SystemExit

    if not os.path.exists(fragment_dir):

        print(
            f"Fragment directory not found: "
            f"{fragment_dir}"
        )

        raise SystemExit

    # =================================================
    # LOAD ORIGINAL
    # =================================================

    original_fragments = split_original_file(
        source_file,
        fragment_size=4096
    )

    # =================================================
    # LOAD DAMAGED DATASET
    # =================================================

    damaged_fragments = load_damaged_fragments(
        fragment_dir
    )

    print(
        f"Original fragments : "
        f"{len(original_fragments)}"
    )

    print(
        f"Damaged fragments  : "
        f"{len(damaged_fragments)}"
    )

    # =================================================
    # COMPARE
    # =================================================

    results = compare_fragments(
        original_fragments,
        damaged_fragments
    )

    # =================================================
    # REPORT
    # =================================================

    report = generate_corruption_report(
        results
    )

    print()
    print("SUMMARY")
    print("-------")

    print(
        f"Intact fragments    : "
        f"{report['intact_fragments']}"
    )

    print(
        f"Corrupted fragments : "
        f"{report['corrupted_fragments']}"
    )

    print(
        f"Missing fragments   : "
        f"{report['missing_fragments']}"
    )

    print(
        f"Changed bytes       : "
        f"{report['total_changed_bytes']}"
    )

    print(
        f"Coverage            : "
        f"{report['coverage_percentage']}%"
    )

    print(
        f"Intact percentage   : "
        f"{report['intact_percentage']}%"
    )

    # =================================================
    # DETAILED RESULTS
    # =================================================

    print()
    print("DETAILED RESULTS")
    print("-----------------")

    for result in results:

        if result["status"] != "INTACT":

            print(
                f"Original index "
                f"{result['original_index']} | "
                f"Status: "
                f"{result['status']} | "
                f"File: "
                f"{result['filename']} | "
                f"Changed bytes: "
                f"{result['changed_bytes']}"
            )