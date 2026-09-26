from damage_simulator import create_damaged_dataset


result = create_damaged_dataset(
    "data/input/mini_project_front-merged.pdf"
)

print("ANVAYA DAMAGE SIMULATION")
print("========================")

for key, value in result.items():
    print(f"{key}: {value}")