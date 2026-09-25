import os
import random
import shutil


def create_damaged_dataset(
    source_file,
    output_dir="data/fragments",
    fragment_size=4096,
    remove_count=5,
    duplicate_count=2,
    corrupt_count=2
):
    os.makedirs(output_dir, exist_ok=True)

    # Read original file
    with open(source_file, "rb") as f:
        data = f.read()

    # Split into fragments
    fragments = []

    for offset in range(0, len(data), fragment_size):
        fragment_data = data[offset:offset + fragment_size]

        fragments.append({
            "original_index": len(fragments),
            "data": fragment_data
        })

    total = len(fragments)

    # Select fragments to remove
    removable = list(range(total))
    removed = set(random.sample(removable, min(remove_count, total)))

    # Select fragments to corrupt
    available = [i for i in removable if i not in removed]
    corrupted = set(
        random.sample(available, min(corrupt_count, len(available)))
    )

    # Create working fragment list
    working_fragments = []

    for i, fragment in enumerate(fragments):

        if i in removed:
            continue

        fragment_data = bytearray(fragment["data"])

        # Corrupt a few bytes
        if i in corrupted and len(fragment_data) > 10:
            for _ in range(min(10, len(fragment_data))):
                position = random.randint(0, len(fragment_data) - 1)
                fragment_data[position] ^= random.randint(1, 255)

        working_fragments.append({
            "original_index": i,
            "data": bytes(fragment_data),
            "corrupted": i in corrupted
        })

    # Add duplicates
    if working_fragments:
        for i in range(min(duplicate_count, len(working_fragments))):
            duplicate = working_fragments[i].copy()
            duplicate["duplicate"] = True
            working_fragments.append(duplicate)

    # Shuffle fragments
    random.shuffle(working_fragments)

    # Save fragments
    for number, fragment in enumerate(working_fragments, start=1):

        filename = os.path.join(
            output_dir,
            f"fragment_{number:04d}.bin"
        )

        with open(filename, "wb") as f:
            f.write(fragment["data"])

    # Save damage report
    report_path = os.path.join(output_dir, "damage_report.txt")

    with open(report_path, "w") as report:
        report.write("ANVAYA TEST DAMAGE REPORT\n")
        report.write("========================\n")
        report.write(f"Original fragments: {total}\n")
        report.write(f"Removed fragments: {sorted(removed)}\n")
        report.write(f"Corrupted fragments: {sorted(corrupted)}\n")
        report.write(f"Duplicates added: {duplicate_count}\n")
        report.write(f"Fragments available: {len(working_fragments)}\n")

    return {
        "original_fragments": total,
        "removed": sorted(removed),
        "corrupted": sorted(corrupted),
        "duplicates": duplicate_count,
        "available_fragments": len(working_fragments)
    }