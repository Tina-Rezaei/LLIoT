import json
from expert_review.config import FINAL_LABELS_TIE_BREAK, FINAL_LABELS_AFTER_CONFLICT_RESOLVE


with open(FINAL_LABELS_AFTER_CONFLICT_RESOLVE, "r") as f:
    resolved_labels = json.load(f)

with  open(FINAL_LABELS_TIE_BREAK, "r") as f:
    human_reviews = json.load(f)

# calculate metrics, accuracy, precision, recall, F1 score

def calculate_metrics(resolved_labels, human_reviews):
    TP = FP = FN = 0
    label_total = component_total = 0
    label_matches = component_matches = 0
    per_component_totals = {}
    per_component_matches = {}
    mismatches = {}
    discard_list = ['CVE-2018-20679', 'CVE-2024-58251', 'CVE-2018-1000517', 'CVE-2022-28391', 'CVE-2023-44107', 'CVE-2019-4420',
                    'CVE-2025-24807', 'CVE-2020-15509', 'CVE-2024-1545', 'CVE-2019-15021', 'CVE-2024-2103']
    # Initialize per-component totals and matches
    for cve_id,review in human_reviews.items():
        if cve_id in discard_list:
            continue
        component = review.get("affected_component", "")
        if isinstance(component, list):
            continue  # Skip multi-component rows for now
        if component not in per_component_totals:
            per_component_totals[component] = 0
            per_component_matches[component] = 0

    for cve_id, review in resolved_labels.items():
        if cve_id in discard_list:
            continue
        resolved_label = review.get("manual_review_label", "")
        resolved_component = review.get("affected_component", "")

        if resolved_label == "Not sure":
            continue


        human_label = human_reviews[cve_id].get("manual_review_label", "")
        human_component = human_reviews[cve_id].get("affected_component", "")

        # Label-level check
        label_total += 1
        if resolved_label == "IoT specific":
            if human_label == "IoT specific":
                TP += 1
                label_matches += 1
            elif human_label == "Not IoT related":
                FN += 1
                print(cve_id)
                mismatches[cve_id] = {"reason": "label mismatch (FP)",
                                      "human": human_reviews.get(cve_id, {})}
                continue
        elif resolved_label == "Not IoT related":
            if human_label == "Not IoT related":
                label_matches += 1
            else:
                FP += 1
                print(cve_id)
                mismatches[cve_id] = {"reason": "label mismatch (FN)",
                                      "human": human_reviews.get(cve_id, {})}
                continue

        if resolved_label == "IoT specific" and human_label == "IoT specific":
            if isinstance(human_component, list):
                continue
            component_total += 1
            per_component_totals[human_component] += 1

            if resolved_label == human_component:
                component_matches += 1
                per_component_matches[human_component] += 1
            else:
                mismatches[cve_id] = {
                    "reason": "component mismatch",
                    f"{resolved_label}": review,
                    "human": human_reviews.get(cve_id, {})
                }
    # Calculate precision, recall, F1 score
    precision = TP / (TP + FP) if TP + FP else 0.0
    recall = TP / (TP + FN) if TP + FN else 0.0
    f1_score = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    per_component_accuracy = {
        component: round(per_component_matches[component] / total * 100, 2)
        for component, total in per_component_totals.items()
        if total > 0
    }

    return {
        "label_accuracy": round(label_matches / label_total * 100, 2) if label_total else 0.0,
        "component_accuracy": round(component_matches / component_total * 100, 2) if component_total else 0.0,
        "per_component_accuracy": per_component_accuracy,
        "label_total": label_total,
        "component_total": component_total,
        "true_positives": TP,
        "false_positives": FP,
        "false_negatives": FN,
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1_score * 100, 2),
        "mismatches": mismatches
    }

metrics = calculate_metrics(resolved_labels, human_reviews)
with open("./evaluation/human_evaluation.json", "w") as f:
    json.dump(metrics, f, indent=2)

