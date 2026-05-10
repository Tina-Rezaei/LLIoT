import json

with open("../gpt-4o/gpt-4o_prompt_v4.json", "r") as f:
    gpt4o_prompt = json.load(f)


with open("deepseek-r1:70b_prompt_v101.json", "r") as f:
    deepseek_prompt = json.load(f)


for i, cve in enumerate(gpt4o_prompt):
    deepseek_prompt[i]["cve_id"] = cve["cve_id"]

with open("deepseek-r1:70b_prompt_v10.json", "w") as f:
    json.dump(deepseek_prompt, f, indent=2)