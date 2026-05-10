import json

with open('labels/final_labels.json', "r") as f:
    final_output = json.load(f)

with open("reviews/tie_breaker_review.json", "r") as f:
    tie_breaker_decision = json.load(f)

for cve_review in tie_breaker_decision:
    final_output[cve_review["cve_id"]]["manual_review_label"] = cve_review["manual_review_label"]
    if cve_review["manual_review_label"] == "IoT specific":
        print(cve_review["cve_id"])
        final_output[cve_review["cve_id"]]["affected_component"] = cve_review["affected_component"]

with open("labels/final_labels_after_tie_breaking.json", "w") as f:
    json.dump(final_output, f, indent=2)