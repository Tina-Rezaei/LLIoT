import os
import json
import psycopg2
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime, timezone
from data_collcetion.cve.datasources import insert_cve_iot
from config import setting

load_dotenv()

client = OpenAI(api_key=os.getenv('OPEN_AI_KEY'))
# if len(sys.argv) < 2:
#     print("Usage: python retrieve_result.py <file_id>")
#     sys.exit(1)

# file_id = sys.argv[1]
file_id = "file-V4xkctfX4DseN2TWXDVNmf"
file_response = client.files.content(file_id)

conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

for raw_response in getattr(file_response, "text", "").splitlines():
    raw_response = json.loads(raw_response)
    sample = json.loads(raw_response["response"]["body"]["choices"][0]["message"]["content"])

    print(raw_response["custom_id"])
    try:
        with conn.cursor() as cursor:
            created_at = datetime.now(timezone.utc)
            updated_at = datetime.now(timezone.utc)
            insert_cve_iot(
                cursor, raw_response["custom_id"],
                True if sample.get("label", "") == "IoT" else False,
                sample.get("component", ""),
                sample.get("reason", ""),
                sample.get("sector", ""),
                sample.get("category", ""),
                created_at, updated_at)
        conn.commit()
    except Exception as e:
        print(f"❌ Error inserting {['cve_id']} to the table: {e}")
exit()

with open("batch_responses.jsonl", "a", encoding="utf-8") as f:
    f.write(getattr(file_response, "text", ""))
    # f.write(file_response.text)

with open(f"batch_responses_{file_id}.jsonl", "a", encoding="utf-8") as f:
    f.write(getattr(file_response, "text", ""))
    # f.write(file_response.text)
print("✅ Downloaded to batch_responses.jsonl")

