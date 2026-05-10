import re
import sys
import json
import time
import ollama
from pathlib import Path
from langchain.prompts import PromptTemplate
from utils import load_samples, load_prompt, save_result
from expert_review.config import OUTPUT_DIR, PROMPT_DIR


def extract_json_block(text):
    match = re.search(r'{.*}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            print("⚠️ Failed to parse JSON:", match.group(0))
    return {"label": "", "component": "", "reason": "Parsing failed."}


def main(model, prompt_name) -> None:
    prompt_path = Path(PROMPT_DIR) / prompt_name
    prompt_template = PromptTemplate.from_template(load_prompt(prompt_path))

    output_path = Path(OUTPUT_DIR) / model / f"{model}_{prompt_name.replace('.txt', '')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not output_path.exists():
        output_path.write_text("[\n")

    with open("data/test_deepseek.json", encoding="utf-8") as fp:
        samples = json.load(fp)
    prompt_version = prompt_name.split(".")[0]

    for sample in samples:
        user_prompt = prompt_template.format(
            description=sample["description"],
            products=sample["vendor_product"],
        )

        start = time.time()
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": user_prompt}],
            stream=False,
        )
        elapsed = time.time() - start
        assistant_text = response["message"]["content"]
        print(f"time: {elapsed:.2f}s")
        print("response:", assistant_text)

        structured = extract_json_block(assistant_text)
        structured["cve_id"] = sample["cve_id"]

        # Append pretty-printed result plus trailing comma
        with output_path.open("a", encoding="utf-8") as fp:
            json.dump(structured, fp, indent=2)
            fp.write(",\n")

    print(f"✔️  Results saved to {out_path} (remember to add the closing ']').")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python classify.py <ollama-model-name> <prompt-filename>")
        sys.exit(1)
    model = sys.argv[1]
    prompt_name = sys.argv[2]
    out_path = "./LLM_output"
    main(model, prompt_name)

