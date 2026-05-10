import openai
import sys
import datetime
from dotenv import load_dotenv
import os

load_dotenv()

if len(sys.argv) < 2:
    print("Usage: python check_batch_status.py <BATCH_ID>")
    sys.exit(1)

batch_id = sys.argv[1]

client = openai.OpenAI(api_key=os.getenv('OPEN_AI_KEY'))
batch = client.batches.retrieve(batch_id)

print(f"Status: {batch.status}")
print(f"Created: {batch.created_at}")
print(f"Finished: {batch.completed_at}")

if batch.status == "completed":
    created = datetime.datetime.fromtimestamp(batch.created_at)
    finished = datetime.datetime.fromtimestamp(batch.completed_at)
    duration = finished - created
    print(f"⏱️ Total time: {duration} (from {created} to {finished})")
    print(f"Output file ID: {batch.output_file_id}")
elif batch.status == "failed":
    print("❌ Batch failed.")
    if hasattr(batch, "errors") and batch.errors:
        print("Errors:")
        for err in batch.errors:
            print(err)
    else:
        print("No specific error info returned.")
