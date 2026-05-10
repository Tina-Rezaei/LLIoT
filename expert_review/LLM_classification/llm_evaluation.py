import json
from pathlib import Path
from collections import defaultdict
from expert_review.config import FINAL_LABELS, FINAL_LABELS_TIE_BREAK, LLM_EVALUATION_PATH, LLM_OUTPUT_PATH, EXPERT_REVIEWS, FINAL_LABELS_AFTER_CONFLICT_RESOLVE


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def evaluate_model(model_name: str, prompt_name: str, manual_labels: dict, human_reviews: dict) -> dict:
    result_path = Path(LLM_OUTPUT_PATH) / model_name / f"{model_name}_{prompt_name}.json"

    if not result_path.exists():
        print(f"⚠️ Result file not found for {model_name} - {prompt_name}")
        return {}

    with result_path.open() as f:
        llm_outputs = json.load(f)

    mismatches = {}
    label_matches, label_total = 0, 0
    component_matches, component_total = 0, 0
    per_component_matches = defaultdict(int)
    per_component_totals = defaultdict(int)
    discard_list = ['CVE-2018-20679', 'CVE-2024-58251', 'CVE-2018-1000517', 'CVE-2022-28391', 'CVE-2023-44107',
                    'CVE-2019-4420',
                    'CVE-2025-24807', 'CVE-2020-15509', 'CVE-2024-1545', 'CVE-2019-15021', 'CVE-2024-2103']
    #
    # discard_list = []
    # For binary classification metrics
    TP, FP, FN = 0, 0, 0
    unsure = 0
    for review in llm_outputs:
        cve_id = review["cve_id"]
        if cve_id in discard_list:
            continue
        if cve_id not in manual_labels:
            continue
        if manual_labels[cve_id]["manual_review_label"] == "Not sure":
            continue

        label_total += 1
        human_label = manual_labels[cve_id]["manual_review_label"]
        human_component = manual_labels[cve_id].get("affected_component", "")
        llm_label = review["label"]
        if llm_label == "Non-IoT":
            llm_label = "nonIoT"
        llm_component = review["component"].lower()

        if human_label == "IoT specific":
            if llm_label == "IoT":
                TP += 1
                label_matches += 1
            else:
                FN += 1
                mismatches[cve_id] = {"reason": "label mismatch (FP)", "LLM": review, "human": human_reviews.get(cve_id, {})}
                print(f"⚠️ Label mismatch for {cve_id}: LLM: {llm_label}, Human: {human_label}")
                continue
        elif human_label == "Not IoT related":
            if llm_label == "nonIoT":
                label_matches += 1
            else:
                FP += 1
                print(f"⚠️ Label mismatch for {cve_id}: LLM: {llm_label}, Human: {human_label}")
                mismatches[cve_id] = {"reason": "label mismatch (FN)", "LLM": review, "human": human_reviews.get(cve_id, {})}
                continue
        else:
            unsure += 1
            print(f"⚠️ Unsure label for {cve_id}: {llm_label}")
            continue


        # Component-level evaluation (only for correctly labeled IoT samples)
        if llm_label == "IoT" and human_label == "IoT specific":
            if isinstance(human_component, list):
                continue
            component_total += 1
            per_component_totals[human_component] += 1

            if llm_component == human_component:
                component_matches += 1
                per_component_matches[human_component] += 1
            else:
                mismatches[cve_id] = {
                    "reason": "component mismatch",
                    f"{model_name}": review,
                    "human": human_reviews.get(cve_id, {})
                }


    # Compute precision, recall, F1
    precision = TP / (TP + FP) if TP + FP else 0.0
    recall = TP / (TP + FN) if TP + FN else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
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
        "mismatches": mismatches,
        "label unsure": unsure
    }


def main():
    llm_models = ["deepseek-r1:70b", "o3", "gpt-4o", "llama4:scout"]
    prompt_variants = ["prompt_v20"]  # Add more if needed

    human_reviews = load_json(EXPERT_REVIEWS)
    manual_labels = load_json(FINAL_LABELS_AFTER_CONFLICT_RESOLVE)

    for model in llm_models:
        for prompt in prompt_variants:
            print(f"🔍 Evaluating {model} with {prompt}")
            result = evaluate_model(model, prompt, manual_labels, human_reviews)

            if not result:
                continue

            accuracy_path = Path(LLM_EVALUATION_PATH) / model /  f"{model.replace(':', '_')}_{prompt}_accuracy.json"
            mismatches_path = Path(LLM_EVALUATION_PATH) / model /f"{model.replace(':', '_')}_{prompt}_mismatches.json"
            accuracy_path.parent.mkdir(parents=True, exist_ok=True)

            with accuracy_path.open("w") as f:
                json.dump({
                    "model": model,
                    "prompt": prompt,
                    "label_accuracy": result["label_accuracy"],
                    "component_accuracy": result["component_accuracy"],
                    "per_component_accuracy": result["per_component_accuracy"],
                    "precision": result["precision"],
                    "recall": result["recall"],
                    "f1_score": result["f1_score"],
                    "label_total": result["label_total"],
                    "component_total": result["component_total"],
                    "true_positives": result["true_positives"],
                    "false_positives": result["false_positives"],
                    "false_negatives": result["false_negatives"],
                    "label_unsure": result["label unsure"]
                }, f, indent=2)

            with mismatches_path.open("w") as f:
                json.dump(result["mismatches"], f, indent=2)

            print(f"✅ Results written: {accuracy_path.name}, {mismatches_path.name}\n")

if __name__ == "__main__":
    main()
