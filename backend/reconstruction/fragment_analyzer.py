import hashlib
import math


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""

    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequency:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def analyze_fragments(file_path: str, fragment_size: int = 4096):
    """
    Split a file into fragments and analyze each fragment.
    """

    fragments = []

    with open(file_path, "rb") as file:
        offset = 0
        fragment_number = 1

        while True:
            data = file.read(fragment_size)

            if not data:
                break

            fragment_hash = hashlib.sha256(data).hexdigest()
            entropy = calculate_entropy(data)

            fragment = {
                "fragment_id": f"fragment_{fragment_number:04d}",
                "offset": offset,
                "size": len(data),
                "sha256": fragment_hash,
                "entropy": entropy
            }

            fragments.append(fragment)

            offset += len(data)
            fragment_number += 1

    return fragments