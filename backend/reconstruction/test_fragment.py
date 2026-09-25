from fragment_analyzer import analyze_fragments


file_path = "data/input/mini_project_front-merged.pdf"

fragments = analyze_fragments(file_path)

print(f"Total fragments: {len(fragments)}")

for fragment in fragments[:5]:
    print(fragment)