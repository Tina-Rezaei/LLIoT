import json
from expert_review.config import FINAL_LABELS

#===================================================
# filter CVEs that require re-review by a tie breaker
#===================================================
with open(FINAL_LABELS, "r") as f:
    final_labels = json.load(f)

cve_ids_to_rereview = []
for cve_id, reviews in final_labels.items():
    if isinstance(reviews["manual_review_label"], str):
        if reviews["manual_review_label"] == "IoT specific":
            if not isinstance(reviews["affected_component"], str):
                cve_ids_to_rereview.append(cve_id)
        if reviews["manual_review_label"] == "Not sure":
                cve_ids_to_rereview.append(cve_id)
    else:
        cve_ids_to_rereview.append(cve_id)


with open("../sampling_CVEs/samples_g1.json", "r") as f:
    samples_g1 = json.load(f)
with open("../sampling_CVEs/samples_g2.json", "r") as f:
    samples_g2 = json.load(f)
with open("../sampling_CVEs/samples_g3.json", "r") as f:
    samples_g3 = json.load(f)


all_samples = samples_g1 + samples_g2 + samples_g3
samples_rereview = []
cve_index = 0
for sample in all_samples:
    if sample["cve_id"] in cve_ids_to_rereview:
        sample["cveIndex"] = cve_index
        samples_rereview.append(sample)
        cve_index += 1

with open("conflicted_samples.json", "w") as f:
    json.dump(samples_rereview, f, indent=2)
