import json
import re

def extract_json_block(text):
    match = re.search(r'{.*}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            print("⚠️ Failed to parse JSON:", match.group(0))
    return {"label": "", "component": "", "reason": "Parsing failed."}

# Load original samples by CVE ID
with open("../samples_g3.json", "r") as f:
    samples = json.load(f)

sample_dict = {
    sample["cve_id"]: sample
    for sample in samples
}

# Load batch responses
with open("batch_responses.jsonl", "r") as f:
    responses = [json.loads(line) for line in f]

# Parse and map each response
parsed_results = []

for response in responses:
    custom_id = response.get("custom_id")
    if not custom_id or custom_id not in sample_dict:
        print(f"⚠️ Warning: Unknown or missing custom_id: {custom_id}")
        continue

    content = response["choices"][0]["message"]["content"]
    parsed = extract_json_block(content)
    parsed["cve_id"] = custom_id  # use custom_id as CVE ID
    parsed_results.append(parsed)

# Save parsed results
with open("parsed_results.json", "w") as f:
    json.dump(parsed_results, f, indent=2)

print(f"✅ Parsed {len(parsed_results)} responses into parsed_results.json")

