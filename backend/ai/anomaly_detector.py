import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_zero_ratio(data: bytes) -> float:
    """Calculate the percentage of zero bytes."""

    if not data:
        return 0.0

    zero_bytes = data.count(0)

    return zero_bytes / len(data)


def calculate_unique_ratio(data: bytes) -> float:
    """Calculate how diverse the bytes are."""

    if not data:
        return 0.0

    return len(set(data)) / 256


def calculate_anomaly_score(data: bytes) -> dict:
    """
    Calculate an explainable anomaly score.

    This is an AI-assisted heuristic score,
    not a trained machine-learning prediction.
    """

    entropy = calculate_entropy(data)

    zero_ratio = calculate_zero_ratio(data)

    unique_ratio = calculate_unique_ratio(data)

    score = 0.0

    reasons = []

    # ------------------------------------------
    # Entropy analysis
    # ------------------------------------------

    if entropy < 1.0:

        score += 0.25

        reasons.append(
            "Very low entropy / highly repetitive data"
        )

    elif entropy > 7.95:

        score += 0.10

        reasons.append(
            "Very high entropy / random-looking data"
        )

    # ------------------------------------------
    # Zero-byte analysis
    # ------------------------------------------

    if zero_ratio > 0.50:

        score += 0.45

        reasons.append(
            "Large proportion of zero-filled bytes"
        )

    elif zero_ratio > 0.20:

        score += 0.20

        reasons.append(
            "Elevated zero-byte concentration"
        )

    # ------------------------------------------
    # Byte diversity
    # ------------------------------------------

    if unique_ratio < 0.10:

        score += 0.25

        reasons.append(
            "Very low byte diversity"
        )

    # Limit score to 1.0

    score = min(score, 1.0)

    # ------------------------------------------
    # Classification
    # ------------------------------------------

    if score >= 0.60:

        status = "HIGH_ANOMALY"

    elif score >= 0.30:

        status = "SUSPICIOUS"

    else:

        status = "NORMAL"

    return {

        "anomaly_score": round(score, 2),

        "status": status,

        "entropy": entropy,

        "zero_ratio":
            round(zero_ratio, 4),

        "unique_byte_ratio":
            round(unique_ratio, 4),

        "reasons": reasons
    }


def analyze_fragment(fragment_path: str):

    with open(
        fragment_path,
        "rb"
    ) as f:

        data = f.read()

    result = calculate_anomaly_score(
        data
    )

    result["fragment"] = fragment_path

    result["size"] = len(data)

    return result


if __name__ == "__main__":

    import os

    fragment_dir = "data/fragments"

    print()
    print("ANVAYA AI-ASSISTED ANOMALY ANALYSIS")
    print("===================================")

    if not os.path.exists(fragment_dir):

        print("Fragment directory not found.")

        raise SystemExit

    files = [
        file
        for file in os.listdir(fragment_dir)
        if file.endswith(".bin")
    ]

    print(
        f"Fragments analyzed: {len(files)}"
    )

    print()

    for filename in files[:10]:

        path = os.path.join(
            fragment_dir,
            filename
        )

        result = analyze_fragment(
            path
        )

        print(
            f"{filename} | "
            f"Score: {result['anomaly_score']} | "
            f"Status: {result['status']} | "
            f"Entropy: {result['entropy']}"
        )

        if result["reasons"]:

            print(
                "  Reason:",
                "; ".join(
                    result["reasons"]
                )
            )