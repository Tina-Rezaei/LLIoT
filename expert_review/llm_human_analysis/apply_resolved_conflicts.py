import json
from expert_review.config import RESOLVED_CONFLICTS, FINAL_LABELS_TIE_BREAK, FINAL_LABELS_AFTER_CONFLICT_RESOLVE



with open(RESOLVED_CONFLICTS) as f:
    resolved_samples = json.load(f)

with open(FINAL_LABELS_TIE_BREAK, "r") as f:
    final_labels = json.load(f)

for sample in resolved_samples:
    cve_id = sample["cve_id"]
    if cve_id in final_labels:
        final_labels[cve_id]["manual_review_label"] = sample["manual_review_label"]
        final_labels[cve_id]["affected_component"] = sample["affected_component"]
    else:
        print(f"⚠️ Warning: {cve_id} not found in final labels.")

with open(FINAL_LABELS_AFTER_CONFLICT_RESOLVE, "w") as f:
    json.dump(final_labels, f, indent=2)