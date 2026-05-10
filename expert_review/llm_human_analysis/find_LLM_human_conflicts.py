import json
from pathlib import Path
from collections import defaultdict

OUTPUT_DIR = "../LLM_classification/LLM_output"


def load_json(path):
    """Helper to load a JSON file with UTF‑8 encoding."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def evaluate_model(model_name: str, prompt_name: str, manual_labels: dict, human_reviews: dict) -> dict:
    """Evaluate a single (model, prompt) pair and return detailed metrics + mismatches."""

    result_path = Path(OUTPUT_DIR) / model_name / f"{model_name}_{prompt_name}.json"
    if not result_path.exists():
        print(f"⚠️ Result file not found for {model_name} - {prompt_name}")
        return {}

    with result_path.open() as f:
        llm_outputs = json.load(f)

    mismatches: dict[str, dict] = {}

    for review in llm_outputs:
        cve_id = review["cve_id"]
        if cve_id not in manual_labels:
            continue

        human_label = manual_labels[cve_id]["manual_review_label"]
        if human_label == "Not sure":
            continue

        human_component = manual_labels[cve_id].get("affected_component", "")

        llm_label = review["label"]
        if llm_label == "Non-IoT":  # normalise spelling
            llm_label = "nonIoT"
        llm_component = review["component"].lower()

        ##########################
        #   Label‑level check    #
        ##########################
        label_correct = False
        if llm_label == "IoT":
            if human_label == "IoT specific":
                label_correct = True

        elif llm_label == "nonIoT":
            if human_label == "Not IoT related":
                label_correct = True

        # Record mismatches at label level immediately
        if not label_correct and llm_label!="":
            mismatches[cve_id] = {
                "reason": "label mismatch (FP)" if llm_label == "IoT" else "label mismatch (FN)",
                "LLM": review,
                "human": human_reviews.get(cve_id, {})
            }
            continue  # no component check on wrong labels

        ############################
        #   Component‑level check  #
        ############################
        if llm_label == "IoT" and human_label == "IoT specific":
            if isinstance(human_component, list):
                # Skip multi‑component rows for now
                continue

            # exclude component mismatches, uncomment for inclusion
            # if llm_component != human_component:
            #     mismatches[cve_id] = {
            #         "reason": "component mismatch",
            #         "LLM": review,
            #         "human": human_reviews.get(cve_id, {})
            #     }

    return {
        "mismatches": mismatches,
    }


########################
#       main()         #
########################

def main():
    """Evaluate multiple models & aggregate mismatches across them."""

    MANUAL_LABELS_FILE = "../manual_review/labels/final_labels.json"
    HUMAN_REVIEW_FILE = "../manual_review/reviews/expert_reviews.json"

    # Add as many models/prompts as you like here
    llm_models = ["gpt-4o", "o3", "deepseek-r1:70b", "llama4:scout"]
    # llm_models = ["gpt-4o", "o3"]
    prompt_variants = ["prompt_v20"]  # support multiple prompts if needed

    manual_labels = load_json(MANUAL_LABELS_FILE)
    human_reviews = load_json(HUMAN_REVIEW_FILE)

    aggregated_mismatches: dict[str, dict] = defaultdict(lambda: {"models": {}, "human": None})

    for model in llm_models:
        for prompt in prompt_variants:
            print(f"🔍 Evaluating {model} with {prompt}")
            result = evaluate_model(model, prompt, manual_labels, human_reviews)
            if not result:
                continue  # skip if result file missing

            # ── Merge mismatches into aggregated dict ──
            for cve_id, mismatch_info in result["mismatches"].items():
                aggregated = aggregated_mismatches[cve_id]
                aggregated["models"]["reason"] = mismatch_info["reason"]
                aggregated["models"][model] = {
                    "LLM": mismatch_info["LLM"],
                }
                # Save the human review once (identical across models)
                if aggregated["human"] is None:
                    aggregated["human"] = mismatch_info.get("human", {})

    # ── Write combined mismatch report ──
    combined_path = Path("conflicts") / "all_models_mismatches.json"
    combined_path.parent.mkdir(parents=True, exist_ok=True)
    with combined_path.open("w") as f:
        json.dump(aggregated_mismatches, f, indent=2)

    review_file = Path("conflicts") / "missmatches_review.json"
    mismatches_review_entries = []
    for mismatch in aggregated_mismatches:
        mismatches_review_entries.append({
            "username": "tie_breaker",
            "cve_id": mismatch,
            "mismatch_reason": aggregated_mismatches[mismatch]["models"]["reason"],
            "manual_review_label": "",
            "affected_component": "",
            "notes": ""
        })
    with open(review_file, "w") as f:
        json.dump(mismatches_review_entries, f, indent=2)
    print(f"✅ Combined mismatch report written to {combined_path}\n")


if __name__ == "__main__":
    main()
