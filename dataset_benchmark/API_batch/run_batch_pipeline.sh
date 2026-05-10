#!/bin/bash

set -e

# 1. Generate JSONL file
#echo "🔧 Generating batch_prompts.jsonl..."
#python3 create_batch_jsonl.py

# 2. Submit batch job and capture Batch ID
echo "🚀 Submitting batch job..."
BATCH_ID=$(python3 submit_batch_job.py | tail -n 1)
echo "📦 Batch ID: $BATCH_ID"

# 3. Poll for completion
echo "⏳ Waiting for batch job to complete..."
STATUS="in_progress"

while [[ "$STATUS" == "in_progress" || "$STATUS" == "validating" || "$STATUS" == "finalizing" ]]; do
    sleep 30
    echo "🔄 Checking batch status..."
    STATUS=$(python3 check_batch_status.py $BATCH_ID | grep "Status:" | awk '{print $2}')
    echo "✅ Status: $STATUS"
done

if [[ "$STATUS" != "completed" && "$STATUS" != "finalizing" ]]; then
    echo "❌ Batch job failed or was canceled. Final status: $STATUS"
    exit 1
fi

# 4. Get output file ID
OUTPUT_FILE_ID=$(python3 check_batch_status.py $BATCH_ID | grep "Output file ID:" | awk '{print $4}')
echo "📂 Output File ID: $OUTPUT_FILE_ID"

# 5. Download results
echo "📥 Downloading batch responses..."
python3 retrieve_result.py "$OUTPUT_FILE_ID"

# 6. Parse final output
echo "🧠 Parsing structured responses..."
python3 parse_batch_responses.py

echo "✅ Done! Parsed results are in parsed_results.json"
