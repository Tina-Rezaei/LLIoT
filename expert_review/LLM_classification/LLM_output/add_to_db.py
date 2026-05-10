import json
import os
import psycopg2
from data_collcetion.cve.datasources.ssvc_api import insert_cve_iot
from tqdm import tqdm
from datetime import datetime
from config import setting

def bulk_insert_results(data):
    conn = None
    try:

        conn = psycopg2.connect(
            dbname=setting.POSTGRES_DB,
            user=setting.POSTGRES_USER,
            password=setting.POSTGRES_PASSWORD,
            host=setting.POSTGRES_HOST,
            port=setting.POSTGRES_PORT
        )
        cursor = conn.cursor()

        now = datetime.now()
        for record in tqdm(data):
            insert_cve_iot(
                cursor,
                record["cve_id"],
                True if record.get("label", "") == "IoT" else False,
                record.get("component",""),
                record.get("reason", ""),
                created_at=now,
                updated_at=now
            )

        conn.commit()
    except Exception as e:
        print(f"❌ Error during bulk insert: {e}")
    finally:
        if conn:
            conn.close()

# Gather all data first
all_data = []
model = "gemma3:27b"
model = "llama4:scout"
for file in os.listdir(f"./{model}"):
    if file.endswith(".json"):
        with open(os.path.join(f"./{model}", file), "r") as f:
            print(file)
            json_file = json.load(f)
            all_data.extend(json_file)

bulk_insert_results(all_data)
