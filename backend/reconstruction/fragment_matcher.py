import os
import hashlib


def read_fragments(fragment_dir):
    """Read all binary fragments from the damaged dataset."""

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
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()
        })

    return fragments


def calculate_match_score(fragment_a, fragment_b, comparison_bytes=16):
    """
    Estimate whether fragment_b could follow fragment_a.

    This prototype compares the boundary bytes of the two fragments.
    """

    data_a = fragment_a["data"]
    data_b = fragment_b["data"]

    if not data_a or not data_b:
        return 0.0

    tail = data_a[-comparison_bytes:]
    head = data_b[:comparison_bytes]

    matching_bytes = 0

    for a, b in zip(tail, head):
        if a == b:
            matching_bytes += 1

    score = matching_bytes / comparison_bytes

    return round(score * 100, 2)


def build_match_graph(fragment_dir):
    """Build pairwise compatibility scores between fragments."""

    fragments = read_fragments(fragment_dir)

    connections = []

    for i, fragment_a in enumerate(fragments):

        for j, fragment_b in enumerate(fragments):

            if i == j:
                continue

            score = calculate_match_score(fragment_a, fragment_b)

            connections.append({
                "from": fragment_a["filename"],
                "to": fragment_b["filename"],
                "score": score
            })

    connections.sort(
        key=lambda connection: connection["score"],
        reverse=True
    )

    return connections


if __name__ == "__main__":

    fragment_dir = "data/fragments"

    connections = build_match_graph(fragment_dir)

    print("ANVAYA FRAGMENT MATCHING")
    print("========================")

    print(f"Total possible connections: {len(connections)}")

    print("\nTop 20 candidate connections:")

    for connection in connections[:20]:
        print(
            f"{connection['from']} -> "
            f"{connection['to']} : "
            f"{connection['score']}%"
        )