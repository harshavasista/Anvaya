import os
import hashlib


def load_fragments(fragment_dir):
    """
    Load all surviving fragment files.
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


def build_reconstruction_map(
    original_fragments,
    damaged_fragments
):
    """
    Match surviving fragments to their original positions.

    Handles duplicate fragment hashes by keeping
    all original positions for the same hash.
    """

    original_by_hash = {}

    for fragment in original_fragments:
        fragment_hash = fragment["sha256"]

        if fragment_hash not in original_by_hash:
            original_by_hash[fragment_hash] = []

        original_by_hash[fragment_hash].append(
            fragment["original_index"]
        )

    reconstruction = []

    matched_indexes = set()

    # Match surviving fragments to original positions
    for damaged in damaged_fragments:

        fragment_hash = damaged["sha256"]

        possible_indexes = original_by_hash.get(
            fragment_hash,
            []
        )

        # No matching original fragment
        if not possible_indexes:
            continue

        # Find an original position that has not
        # already been matched
        original_index = None

        for index in possible_indexes:
            if index not in matched_indexes:
                original_index = index
                break

        # Extra duplicate fragment
        if original_index is None:
            continue

        matched_indexes.add(original_index)

        reconstruction.append({
            "original_index": original_index,
            "filename": damaged["filename"],
            "status": "RECOVERED",
            "sha256": damaged["sha256"],
            "size": damaged["size"]
        })

    # Add missing positions
    for original in original_fragments:

        index = original["original_index"]

        if index not in matched_indexes:

            reconstruction.append({
                "original_index": index,
                "filename": None,
                "status": "MISSING",
                "sha256": None,
                "size": original["size"]
            })

    reconstruction.sort(
        key=lambda item: item["original_index"]
    )

    return reconstruction
def generate_candidate_file(
    reconstruction_map,
    damaged_fragments,
    output_path
):
    """
    Create a reconstruction candidate.

    IMPORTANT:
    Missing fragments are NOT fabricated.

    A zero-filled placeholder is used only to
    preserve the original file position.

    Therefore the output is explicitly a
    reconstruction candidate, not a verified
    recovered original.
    """

    fragment_lookup = {
        fragment["filename"]: fragment
        for fragment in damaged_fragments
    }

    total_bytes = 0
    recovered_bytes = 0
    missing_bytes = 0

    with open(output_path, "wb") as output:

        for item in reconstruction_map:

            filename = item["filename"]

            if (
                filename is not None
                and filename in fragment_lookup
            ):

                data = fragment_lookup[
                    filename
                ]["data"]

                output.write(data)

                recovered_bytes += len(data)
                total_bytes += len(data)

            else:

                missing_size = item["size"]

                # Placeholder only.
                # These bytes are NOT claimed as recovered.
                output.write(
                    b"\x00" * missing_size
                )

                missing_bytes += missing_size
                total_bytes += missing_size

    recovery_percentage = (
        recovered_bytes / total_bytes * 100
        if total_bytes
        else 0
    )

    return {
        "output_file": output_path,
        "total_bytes": total_bytes,
        "recovered_bytes": recovered_bytes,
        "missing_bytes": missing_bytes,
        "recovery_percentage": round(
            recovery_percentage,
            2
        )
    }


def create_reconstruction_report(
    reconstruction_map
):
    recovered = 0
    missing = 0

    for item in reconstruction_map:

        if item["status"] == "RECOVERED":
            recovered += 1

        elif item["status"] == "MISSING":
            missing += 1

    total = len(reconstruction_map)

    coverage = (
        recovered / total * 100
        if total
        else 0
    )

    return {
        "total_original_fragments": total,
        "recovered_fragments": recovered,
        "missing_fragments": missing,
        "fragment_coverage_percentage": round(
            coverage,
            2
        )
    }