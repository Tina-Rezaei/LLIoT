import json
import random
import psycopg2
import pandas as pd
from config import setting


template = """
We define the IoT ecosystem as comprising the following four components:
1-Device layer: Physical devices that often have limited power, memory, computational capacity and either collect sensory data or perform actuation tasks. These devices also interact with other devices directly or indirectly using communication technologies with limited or no human intervention. Examples include smart thermostats, Amazon Echo, motion sensors, smart cameras, and smart TVs. Typical vulnerabilities of this component originate from the hardware, firmware, or embedded OSes/software (e.g., FreeRTOS, TinyOS, RIOT-OS).
2-Communication layer: This layer includes any protocol that facilitates data transfer and connectivity for IoT devices within the local network or outside of the network. It involves specialized low-power protocols (BLE, ZigBee). Typical vulnerabilities of this component include the flaws in the protocol design, implementation or configuration bugs in protocol stacks (e.g., unencrypted data exchange, lack of authentication).
3-Application layer: This layer includes mobile applications and orchestration systems/local controllers that sit above the hardware and enable user-space services for IoT. Examples include IoT-focused platforms and applications/companion applications (Home Assistant, SmartThings, IFTTT). Typical vulnerabilities include flaws in the design or implementation logic of these platforms and applications.
4-Cloud backend layer: Remote or public cloud endpoints that provide IoT-specific services, such as device management, remote control, and other IoT-focused functionalities. Examples include AWS IoT, Azure IoT, Google Cloud IoT, IBM Watson IoT. Typical vulnerabilities of this component include the flaws in the configuration of the infrastructure, vulnerable services, insecure cloud APIs or tokens, and improper input validation on the server side.
Given the above definition of the IoT ecosystem, CVE classification rules are:
1)IoT-specific CVE: vulnerabilities that affect technologies belonging to IoT ecosystem, where these technologies are purpose‑built for IoT and the deployment context is IoT. Moreover, the vulnerable product is itself an active, functional element of an IoT system.
2)Non-IoT CVE: When there is insufficient or no clear evidence of its relevance to IoT usage, or it does not significantly impact the IoT ecosystem, then it is nonIoT. General-purpose hardware/software such as smartphone, computers, or tablets are considered as Non-IoT. Network infrastructures such as routers, modems are also Non-IoT.
Classify the following CVE using the above rules.
Also, determine the sector of the affected product.
Also, choose a single high-level category based on the affected products. Examples include but are not limited to cameras, lighting, sensors, actuators, chisets, WiFi modules, network infrastructure/router, network infrastructure/modem, network infrastructure/gateway, switch, ...
Description: {description}
Affected Products: {products}
Respond only with a JSON object in the format below—no commentary, no markdown:
    {{
      "label": "IoT" or "nonIoT",
      "component": "device" or "communication" or "application" or "cloud backend" or "unsure",
      "reason": "Your explanation and reasoning",
      "category": "only a general category of your choice based on the affected products",
      "sector": "industrial iot" or "automative iot" or "smart cities iot" or "consumer iot" or "healthcare iot" or "smart finance" or "other".
    }}
"""


conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

query = """
select cve_id, description, vendor_product from cve_cve, cve_cpe
where 
    cve_cve.id = cve_cpe.cve_id and
    cve_cve.id ilike 'CVE-2024%' and
    cve_cve.status !='R' and
    cve_cve.id not IN (select cve_id from cve_iot_classification)
    limit 90000
"""

query = """
select cve_id, description, vendor_product from cve_cve, cve_cpe
where 
    cve_cve.id = cve_cpe.cve_id and
    cve_cve.status !='R' and
    cve_cve.id IN (select cve_id from cve_iot_classification where reason ilike '%parsing failed%')
    limit 90000
"""

IoT_cves = """
select cve_cpe.cve_id, description, vendor_product from cve_cpe, cve_cve, cve_iot_classification
where
    cve_cve.id = cve_cpe.cve_id and
    cve_cve.id = cve_iot_classification.cve_id and
    cve_iot_classification.is_iot = true 
"""

nonIoT_cves = """
select cve_cpe.cve_id, description, vendor_product from cve_cpe, cve_cve, cve_iot_classification
where
    cve_cve.id = cve_cpe.cve_id and
    cve_cve.id = cve_iot_classification.cve_id and
    cve_iot_classification.is_iot = false 
"""

def get_samples(data_df, n=500):
    samples = {}
    for index, row in data_df.iterrows():
        cve_id = row['cve_id']
        if cve_id not in samples:
            samples[cve_id] = {
                "cve_id": cve_id,
                "description": row['description'],
                "vendor_product": []
            }
        samples[cve_id]["vendor_product"].append(row['vendor_product'])
    samples = dict(random.sample(list(samples.items()), min(n, len(samples))))
    return samples

# df_IoT = pd.read_sql(IoT_cves, conn)
# df_nonIoT = pd.read_sql(nonIoT_cves, conn)

# shuffle df_IoT and df_nonIoT
# df_IoT = df_IoT.sample(frac=1).reset_index(drop=True)
# df_nonIoT = df_nonIoT.sample(frac=1).reset_index(drop=True)

# IoT_samples = get_samples(df_IoT)
# nonIoT_samples = get_samples(df_nonIoT)

# samples = {**IoT_samples, **nonIoT_samples}
# print(len(samples), "samples loaded")

df = pd.read_sql(query, conn)
samples = get_samples(df, 10000)
print(len(samples))
# print(samples)
# Load samples
# Write JSONL
#shuffle samples and limit to 100

with open("batch_prompts.jsonl", "w") as out:
    for cve_id, sample in samples.items():
        prompt = template.format(
            description=sample["description"],
            products=sample["vendor_product"]
        )
        payload = {
            "custom_id": cve_id,  # Must be unique
            "method": "POST",
            "url": "/v1/chat/completions",
            "body": {
                "model": "o3",
                 "messages": [
                    {"role": "user", "content": prompt}
                ],
            "temperature": 1,

        }}
        out.write(json.dumps(payload) + "\n")
