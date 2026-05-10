import json

with open("./conflicts/resolved_conflicts.json") as f:
    resolved_samples = json.load(f)

with open("../manual_review/labels/final_labels.json", "r") as f:
    final_labels = json.load(f)

for sample in resolved_samples:
    cve_id = sample["cve_id"]
    if cve_id in final_labels:
        final_labels[cve_id]["manual_review_label"] = sample["manual_review_label"]
        final_labels[cve_id]["affected_component"] = sample["affected_component"]
    else:
        print(f"⚠️ Warning: {cve_id} not found in final labels.")

with open("./final_label_after_resolve.json", "w") as f:
    json.dump(final_labels, f, indent=2)
