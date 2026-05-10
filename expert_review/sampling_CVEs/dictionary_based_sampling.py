import re
import json
import random
import psycopg2
import pandas as pd
from config import setting
from collections import Counter
import matplotlib.pyplot as plt
from collections import defaultdict
pd.set_option("display.max_columns", None)  # Show all columns


def get_samples(data_df, n, exclude_ids=None):
    if exclude_ids is None:
        exclude_ids = set()
    else:
        exclude_ids = set(exclude_ids)

    # Build keyword → list of CVE IDs (excluding previously selected ones)
    keyword_cves = {}
    for _, row in data_df.iterrows():
        cve_id = row["id"]
        if cve_id in exclude_ids:
            continue
        keyword_list = row.get("matched_keywords", [])
        if not keyword_list:
            continue
        keyword = keyword_list[0]
        keyword_cves.setdefault(keyword, set()).add(cve_id)

    # Round-robin sampling from keyword_cves
    samples = []
    keywords = list(keyword_cves.keys())
    keyword_index = 0

    while len(samples) < n and any(keyword_cves.values()):
        keyword = keywords[keyword_index]
        cve_pool = keyword_cves[keyword]
        if cve_pool:
            cve_id = random.choice(list(cve_pool))
            keyword_cves[keyword].remove(cve_id)

            matching_rows = data_df[data_df["id"] == cve_id]
            sample = {"cve_id": cve_id}

            if len(matching_rows) > 1:
                sample["vendor_product"] = [
                    r.get("vendor_product", []) for _, r in matching_rows.iterrows()
                ]
                sample["description"] = matching_rows.iloc[0]["description"]
            else:
                record = matching_rows.iloc[0].to_dict()
                cpes = record.get("vendor_product")
                sample["vendor_product"] = [cpes] if cpes else [None]
                sample["description"] = record["description"]

            samples.append(sample)

        keyword_index = (keyword_index + 1) % len(keywords)

    return samples, set(sample["cve_id"] for sample in samples)


def get_unique_ids(data_df):
    """Get unique CVE IDs from the DataFrame."""
    return set(data_df["id"].unique())


def get_non_IoT_samples(non_IoT_df, n=150):
    """Get `n` non-IoT samples, combining vendor_product values across rows with the same CVE ID."""
    # Get unique CVE IDs from non-IoT data
    unique_ids = non_IoT_df["id"].unique()
    samples = []
    grouped = non_IoT_df.groupby("id")
    unique_ids = list(grouped.groups.keys())
    all_normalized_products = set()
    np_to_ids = defaultdict(set)
    for _, row in non_IoT_df.iterrows():
        norms = row.get("normalized_vendor_product", [])
        if not isinstance(norms, list):
            norms = [norms] if norms else []
        for npv in norms:
            np_to_ids[npv].add(row["id"])

    for i in range(n):
        if len(unique_ids) == 0:
            break

        cve_id = random.sample(list(unique_ids), 1)[0]
        # matching_rows = non_IoT_df[non_IoT_df["id"] == cve_id]
        matching_rows = grouped.get_group(cve_id)
        if matching_rows.empty:
            continue

        all_products = set()
        norm_products = set()

        for _, row in matching_rows.iterrows():
            vp = row.get("vendor_product", [])
            norm = row.get("normalized_vendor_product", [])
            if isinstance(vp, list):
                all_products.update(vp)
            elif vp:
                all_products.add(vp)
            if isinstance(norm, list):
                norm_products.update(norm)
            elif norm:
                norm_products.add(norm)

        description = matching_rows.iloc[0]["description"] if "description" in matching_rows.columns else ""
        samples.append({
            "cve_id": cve_id,
            "vendor_product": sorted(all_products),
            "description": description
        })

        # Remove CVEs with the same normalized_vendor_product
        ids_to_remove = set()
        for npv in norm_products:
            ids_to_remove.update(np_to_ids.get(npv, set()))

        # Remove from unique_ids
        unique_ids = [uid for uid in unique_ids if uid not in ids_to_remove]

        # Also prune groups so get_group() won’t return removed IDs
        for rid in ids_to_remove:
            if rid in grouped.groups:
                del grouped.groups[rid]


    return samples


def normalize_vendor_product(vp):
    vp = vp.lower()
    vp = re.sub(r'\(.*?\)', '', vp)  # Remove content in parentheses
    vp = re.sub(r'version\s*\d+[\w\s.]*', '', vp)  # Remove "version xyz"
    vp = re.sub(r'[^a-z0-9:_]', '_', vp)  # Convert all non-alphanumerics to _
    vp = re.sub(r'_+', '_', vp)  # Collapse multiple underscores
    vp = vp.strip('_')

    # Split into vendor/product
    if ':' not in vp:
        return vp
    vendor, product = vp.split(':', 1)

    # Apply alias mappings
    vendor = VENDOR_ALIASES.get(vendor, vendor)

    for pattern, replacement in PRODUCT_ALIASES.items():
        if re.fullmatch(pattern, product):
            product = replacement
            break

    product = re.sub(r'_+', '_', product).strip('_')

    return f"{vendor}:{product}" if product else vendor


def add_index(dict_list):
    return [{**d, "cveIndex": i} for i, d in enumerate(dict_list)]

VENDOR_ALIASES = {
    "google_inc.": "google",
    "n/a": "unknown",
    "mozilla": "mozilla",
    "apple": "apple",
    "microsoft": "microsoft",
    "linux": "linux",
    "canonical": "canonical",
    "redhat": "redhat",
    "fedoraproject": "fedora",
}

PRODUCT_ALIASES = {
    # Windows families
    r"windows_10.*": "windows_10",
    r"windows_11.*": "windows_11",
    r"windows_8.*": "windows_8",
    r"windows_7.*": "windows_7",
    r"windows_rt.*": "windows_rt",
    r"windows_server.*": "windows_server",

    # Apple
    r"mac_os_x": "macos",
    r"ios_and_ipados": "iphone_os",

    # Linux
    r"linux_kernel": "linux",

    # Mozilla
    r"firefox_esr": "firefox",

    # Android
    r"android.*": "android",

    # RedHat naming
    r"enterprise_linux.*": "enterprise_linux",

    # Misc
    r".*-bit_systems": "",
    r".*service_pack.*": "",
    r".*,.*": "",  # strip comma + anything (edition/variant)
}


# ---------------------------------------
# 1. Connect to PostgreSQL
# ---------------------------------------
conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

# ---------------------------------------
# 2. Define queries
# ---------------------------------------
query_application = r"""
SELECT DISTINCT ON (c.id)
  c.*,cp.vendor_product,cp.vendor,cp.product,
  ARRAY(
    SELECT distinct match[1]
    FROM regexp_matches(
      c.description,
      '\y(SYLVANIA|Eclipse iot|kaa iot|tridium niagara|SwitchBot|Govee Home|Fire TV|SmartThings|IFTTT|Home Assistant|Alexa|OpenHAB|Domoticz|Apple Homekit|Homekit|Google assist|Google Nest app|Zingbox)\y',
      'gi'
    ) AS match
  ) AS matched_keywords
FROM cve_cve c
JOIN cve_cpe cp ON c.id = cp.cve_id
WHERE c.status != 'R'
  AND c.description ~* '\y(SYLVANIA|Eclipse iot|kaa iot|tridium niagara|SwitchBot|Fire TV|SmartThings|IFTTT|Home Assistant|Alexa|OpenHAB|Domoticz|Apple Homekit|Homekit|Google assist|Google Nest app|Zingbox)\y';

"""

query_device = r"""
SELECT DISTINCT ON (c.id)
  c.*,cp.vendor_product,cp.vendor,cp.product,
  ARRAY(
    SELECT distinct match[1]
    FROM regexp_matches(
      c.description,
      '\y(Philips Hue|streaming device|smart tv|smart speakers|smart lock|tower fan|smart plug|smart light switch|thermostat|smart lamp|smart doorbell|smart security camera|security camera|smart camera|ip camera|smart display|home automation hub|smart door lock|smart dimmer switch|smart outlet|smart relay switch|motion sensor|smart toy|smart meter|smart hub|smartThings hub|TinyOS|FreeRTOS|busybox|RIOT-OS|RIOT)\y',
      'gi'
    ) AS match
  ) AS matched_keywords
FROM cve_cve c
JOIN cve_cpe cp ON c.id = cp.cve_id
WHERE c.status != 'R'
  AND c.description ~* '\y(Philips Hue|streaming device|smart tv|smart speakers|smart lock|tower fan|smart plug|smart light switch|thermostat|smart lamp|smart doorbell|smart security camera|security camera|smart camera|ip camera|smart display|home automation hub|smart door lock|smart dimmer switch|smart outlet|smart relay switch|motion sensor|smart toy|smart meter|smart hub|smartThings hub|TinyOS|FreeRTOS|busybox|RIOT-OS|RIOT)\y';

"""

query_comm = r"""
SELECT DISTINCT ON (c.id)
  c.*,cp.vendor_product,cp.vendor,cp.product,
  ARRAY(
    SELECT distinct match[1]
    FROM regexp_matches(
      c.description,
      '\y(CoAP|MQTT|ZigBee|Z-Wave|6LoWPAN|LoRaWAN|Bluetooth low energy|BLE)\y',
      'gi'
    ) AS match
  ) AS matched_keywords
FROM cve_cve c
JOIN cve_cpe cp ON c.id = cp.cve_id
WHERE c.status != 'R'
  AND c.description ~* '\y(CoAP|MQTT|ZigBee|Z-Wave|6LoWPAN|LoRaWAN|Bluetooth low energy|BLE)\y';

"""

query_cloud = r"""
SELECT DISTINCT ON (c.id)
  c.*,cp.vendor_product,cp.vendor,cp.product,
  ARRAY(
    SELECT distinct match[1]
    FROM regexp_matches(
      c.description,
      '\y(AWS IoT|Azure IoT|Google Cloud IoT|IBM Watson IoT|IoT Cloud|Cisco IoT|Oracle IoT)\y',
      'gi'
    ) AS match
  ) AS matched_keywords
FROM cve_cve c
JOIN cve_cpe cp ON c.id = cp.cve_id
WHERE c.status != 'R'
  AND c.description ~* '\y(AWS IoT|Azure IoT|Google Cloud IoT|IBM Watson IoT|IoT Cloud|Cisco IoT|Oracle IoT)\y';

"""
"AeoTec MultiSensor|Amazon Alexa|Arlo Security Camera|First Alert Smoke|CO detector|Fortrezz Alarm|Google Home|iHome Switch|Philips Hue Light|Ring DoorBell|SmartThings Motion Sensor|SmartThings MultiPurpose Sensor|SmartThings Switch|Tp Link-Kasa Switch|Wemo SWITCH|Yale Assure Lock"

def extract_year(df):
    return df["id"].str.split("-").str[1].astype(int)


def resolve_cve_duplicates(df_device, df_application, df_comm, df_cloud):
    # Priority order
    dataframes = {
        "device": df_device,
        "application": df_application,
        "comm": df_comm,
        "cloud": df_cloud
    }
    priority = ["device", "application", "comm", "cloud"]

    # Create a dict to store CVE assignments
    cve_map = {}

    # Step 1: Record CVEs with their highest-priority occurrence
    for source in priority:
        df = dataframes[source]
        for idx, row in df.iterrows():
            cve = row["id"]
            if cve not in cve_map:
                cve_map[cve] = source

    # Step 2: Filter each DataFrame based on CVE's assigned source
    for source in priority:
        df = dataframes[source]
        df_cleaned = df[df["id"].apply(lambda cve: cve_map[cve] == source)].copy()
        dataframes[source] = df_cleaned

    return dataframes["device"], dataframes["application"], dataframes["comm"], dataframes["cloud"]


global_selected_ids = set()
n_samples_per_layer = 13
rounds_of_sampling = 3

# ---------------------------------------
# 3. Fetch results into Pandas DataFrames
# ---------------------------------------
df_device = pd.read_sql(query_device, conn)
df_application = pd.read_sql(query_application, conn)
df_comm = pd.read_sql(query_comm, conn)
df_cloud = pd.read_sql(query_cloud, conn)
df_device, df_application, df_comm, df_cloud = resolve_cve_duplicates(
    df_device, df_application, df_comm, df_cloud
)

# concat all dfs
df_all = pd.concat([df_device, df_application, df_comm, df_cloud], ignore_index=True)
print("Total CVEs found in all layers:", len(df_all))
print(len(df_device), "Device layer CVEs found")
print(len(df_application), "Application layer CVEs found")
print(len(df_comm), "Communication layer CVEs found")
print(len(df_cloud), "Cloud layer CVEs found")


cves_ids = list(df_device["id"])+(list(df_application["id"]))+(list(df_comm["id"]))+(list(df_cloud["id"]))
duplicates = [item for item, count in Counter(cves_ids).items() if count > 1]
duplicates = set(duplicates)
print(len(duplicates), "duplicates found")

cves_ids = set(df_device["id"]).union(set(df_application["id"])).union(set(df_comm["id"])).union(set(df_cloud["id"]))
cve_dates = {cve_id:df_all[df_all["id"] == cve_id]["date_published"].values[0] for cve_id in cves_ids if "date_published" in df_all.columns}


years_device = extract_year(df_device)
years_application = extract_year(df_application)
years_comm = extract_year(df_comm)
years_cloud = extract_year(df_cloud)
all_years = pd.concat([years_device, years_application, years_comm, years_cloud])
print("years before 2013", [year for year in all_years if year < 2013])

years_range = range(all_years.min(), all_years.max() + 1)
print(Counter(all_years))
year_counts = pd.Series(all_years).value_counts().sort_index()
years = sorted(year_counts.index)
counts = year_counts.reindex(years, fill_value=0)

# Plot using bar chartFinally, we scale the LLM-based classification to the entire NVD dataset to produce a fully annotated CVE corpus for spacing
plt.figure(figsize=(10, 6))
plt.bar(years, counts, color="#0666e5")

plt.xticks(years_range, fontsize=20, rotation=45)
plt.yticks(fontsize=22)
plt.ylabel("Number of CVEs", fontsize=24)
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("filtered_IoTcve_years_histogram.pdf", dpi=300)
plt.show()

print("Device layer CVEs:", len(df_device))
print("Application layer CVEs:", len(df_application))
print("Communication layer CVEs:", len(df_comm))
print("Cloud layer CVEs:", len(df_cloud))
print(len(df_device)+len(df_application)+len(df_comm)+len(df_cloud), "CVEs found in total across all layers")


duplicate_cves = ['CVE-2023-36161', 'CVE-2019-0729', 'CVE-2021-22547', 'CVE-2023-50124', 'CVE-2019-0741', 'CVE-2023-38372', 'CVE-2021-40831', 'CVE-2024-22472', 'CVE-2021-40829', 'CVE-2019-12101', 'CVE-2022-39368', 'CVE-2018-8119', 'CVE-2024-48544', 'CVE-2024-48786', 'CVE-2024-32134', 'CVE-2020-4207', 'CVE-2023-26494', 'CVE-2016-5054', 'CVE-2023-46892', 'CVE-2018-9070', 'CVE-2020-26701']

device_samples_g1,selected_ids = get_samples(df_device, n_samples_per_layer, global_selected_ids)
global_selected_ids.update(selected_ids)

application_samples_g1, selected_ids = get_samples(df_application, n_samples_per_layer, global_selected_ids)
global_selected_ids.update(selected_ids)

comm_samples_g1, selected_ids = get_samples(df_comm, n_samples_per_layer, global_selected_ids)
global_selected_ids.update(selected_ids)

cloud_samples_g1, selected_ids = get_samples(df_cloud, n_samples_per_layer, global_selected_ids)
global_selected_ids.update(selected_ids)
print("\n", len(device_samples_g1)+len(application_samples_g1)+len(comm_samples_g1)+len(cloud_samples_g1), "samples selected in first round")
print('\n\n', device_samples_g1,'\n\n', application_samples_g1, '\n\n', comm_samples_g1, '\n\n', cloud_samples_g1)

# ---------------------------------------
# 5. Sample Non-IoT CVEs
# ---------------------------------------

IoT_cve_ids = get_unique_ids(df_device) | get_unique_ids(df_application) | get_unique_ids(df_comm) | get_unique_ids(df_cloud)

# make a list of unique normalized vendor_products
query_unique_cpes = r"""
SELECT vendor_product, Count(*) as count FROM cve_cpe group by vendor_product order by count(*) desc;
"""
df = pd.read_sql(query_unique_cpes, conn)

# --- Normalize and aggregate ---
df['normalized_vendor_product'] = df['vendor_product'].apply(normalize_vendor_product)

# Group by normalized name and sum counts
aggregated = df.groupby('normalized_vendor_product')['count'].sum().reset_index()
aggregated = aggregated.sort_values(by='count', ascending=False)

# select samples having count more than 100
aggregated = aggregated[aggregated['count'] > 10] # df with the most common unique normalized vendor_products
# select all CVEs with vendor_product from database
query_all_CVEs = r"""
SELECT c.*, cpe.vendor_product, cpe.vendor FROM cve_cve AS c, cve_cpe as cpe WHERE c.id = cpe.cve_id and cpe.vendor != 'Microsoft'
"""
data_df = pd.read_sql(query_all_CVEs, conn)
# normalize vendor_product
data_df['normalized_vendor_product'] = data_df['vendor_product'].apply(normalize_vendor_product)
# only keep rows where the normalized vendor_product is in the aggregated list
data_df = data_df[data_df['normalized_vendor_product'].isin(aggregated['normalized_vendor_product'])]

# Exclude IoT CVEs
non_IoT_df = data_df[~data_df["id"].isin(IoT_cve_ids)]

non_iot_samples = get_non_IoT_samples(non_IoT_df, n= 150)

# ---------------------------------------
# write samples to file
# ---------------------------------------

with open(f"../manual_review/samples_g1.json", "w") as f:
    all_samples = device_samples_g1 + application_samples_g1 + comm_samples_g1 + cloud_samples_g1 + non_iot_samples[0:50]
    random.shuffle(all_samples)
    all_samples = add_index(all_samples)
    json.dump(all_samples, f, indent=2)

# more rounds of sampling
for i in range(2,rounds_of_sampling+1):
    device_samples_g2, selected_ids = get_samples(df_device, n_samples_per_layer, global_selected_ids)
    global_selected_ids.update(selected_ids)

    application_samples_g2, selected_ids = get_samples(df_application, n_samples_per_layer, global_selected_ids)
    global_selected_ids.update(selected_ids)

    comm_samples_g2, selected_ids = get_samples(df_comm, n_samples_per_layer, global_selected_ids)
    global_selected_ids.update(selected_ids)

    cloud_samples_g2, selected_ids = get_samples(df_cloud, 11, global_selected_ids)
    global_selected_ids.update(selected_ids)

    all_samples = device_samples_g2 + application_samples_g2 + comm_samples_g2 + cloud_samples_g2 + non_iot_samples[50*(i-1):50*(i)]
    random.shuffle(all_samples)
    all_samples = add_index(all_samples)
    with open(f"samples_g{i}.json", "w") as f:
        json.dump(all_samples, f, indent=2)



conn.close()

# Let's see how many rows we got in each
n_app = len(df_application)
n_dev = len(df_device)
n_com = len(df_comm)
n_cld = len(df_cloud)
print("Application layer CVEs:", n_app)
print("Device layer CVEs:", n_dev)
print("Communication layer CVEs:", n_com)
print("Cloud layer CVEs:", n_cld)


