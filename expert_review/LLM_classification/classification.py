import re
import sys
import json
import time
import ollama
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from expert_review.config import BASE_DIR, OUTPUT_DIR, PROMPT_DIR

SAMPLE_FILES = [BASE_DIR / "sampling_CVEs" / f"samples_{g}.json" for g in ("g1", "g2", "g3")]


def extract_json_block(text):
    match = re.search(r'{.*}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            print("⚠️ Failed to parse JSON:", match.group(0))
    return {"label": "", "component": "", "reason": "Parsing failed."}


def load_samples():
    samples = []
    for path in SAMPLE_FILES:
        with open(path, encoding="utf-8") as fp:
            samples.extend(json.load(fp))
    return samples


def main(model, prompt_name, think=None, run=1, workers=1, num_ctx=None) -> None:
    # The prompt is a Python format string ({description}, {products}, escaped {{ }}).
    prompt_template = (Path(PROMPT_DIR) / prompt_name).read_text(encoding="utf-8")

    # Runs with thinking disabled are stored under their own name, e.g. qwen3.6:27b-nothink
    run_name = f"{model}-nothink" if think is False else model
    # Repeat runs (for consistency analysis) are stored as e.g. gpt-oss:20b-run2
    if run > 1:
        run_name += f"-run{run}"
    output_path = Path(OUTPUT_DIR) / run_name / f"{run_name}_{prompt_name.replace('.txt', '')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Resume from a previous partial run
    results = json.loads(output_path.read_text()) if output_path.exists() else []
    done = {r["cve_id"] for r in results}

    samples = [s for s in load_samples() if s["cve_id"] not in done]
    print(f"{len(done)} already done, {len(samples)} remaining")
    lock = threading.Lock()

    def classify(sample):
        user_prompt = prompt_template.format(
            description=sample["description"],
            products=sample["vendor_product"],
        )

        start = time.time()
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": user_prompt}],
            stream=False,
            think=think,
            options={"num_ctx": num_ctx} if num_ctx else None,
        )
        elapsed = time.time() - start
        assistant_text = response["message"]["content"]

        structured = extract_json_block(assistant_text)
        structured["cve_id"] = sample["cve_id"]
        structured["elapsed_s"] = round(elapsed, 2)
        with lock:
            results.append(structured)
            print(f"[{len(results) - len(done)}/{len(samples)}] {sample['cve_id']} -> {structured.get('label')} / "
                  f"{structured.get('component')} ({elapsed:.1f}s)")
            output_path.write_text(json.dumps(results, indent=2))

    # With workers > 1, requests run concurrently (needs OLLAMA_NUM_PARALLEL >= workers to batch)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(classify, samples))

    print(f"✔️  Results saved to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m expert_review.LLM_classification.classification <ollama-model-name> <prompt-filename> [--no-think] [--run N] [--workers N] [--num-ctx N]")
        sys.exit(1)
    flags = sys.argv[3:]
    run = int(flags[flags.index("--run") + 1]) if "--run" in flags else 1
    workers = int(flags[flags.index("--workers") + 1]) if "--workers" in flags else 1
    num_ctx = int(flags[flags.index("--num-ctx") + 1]) if "--num-ctx" in flags else None
    main(sys.argv[1], sys.argv[2], think=False if "--no-think" in flags else None, run=run, workers=workers,
         num_ctx=num_ctx)
