import json
import os
for file in os.listdir("./"):
    if file.endswith(".jsonl"):
        with open(file, "r") as f:
            json_file = [json.loads(line) for line in f]
        with open(file.replace(".jsonl", ".json"), "w") as f:
            json.dump(json_file, f, indent=2)
