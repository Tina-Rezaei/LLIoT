from openai import OpenAI
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

client = OpenAI(api_key=os.getenv('OPEN_AI_KEY'))

# Fetch recent batches
batches = client.batches.list().data

# Print a summary
print(f"{'Batch ID':<40} {'Status':<15} {'Created'}")
print("=" * 70)

for batch in batches:
    created = datetime.fromtimestamp(batch.created_at).strftime('%Y-%m-%d %H:%M:%S')
    print(f"{batch.id:<40} {batch.status:<15} {created}")
    try:
        client.batches.cancel(batch.id)
    except:
        print(f"❌ Failed to cancel batch {batch.id}")
