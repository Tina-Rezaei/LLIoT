import openai
from dotenv import load_dotenv
import os
from config import setting

load_dotenv()
client = openai.OpenAI(api_key=setting.OPEN_AI_KEY)
# Upload file first
upload = client.files.create(
    file=open("batch_prompts.jsonl", "rb"),
    purpose="batch"
)
print(f"✅ File uploaded. ID: {upload.id}")

# Create batch job
batch = client.batches.create(
    input_file_id=upload.id,
    endpoint="/v1/chat/completions",
    completion_window="24h"
)

with open("batch_ids.txt", "a") as f:
    f.write(batch.id + "\n")
print(f"🚀 Batch submitted.")
print(f"{batch.id}")  # <- print only the batch ID on its own line
