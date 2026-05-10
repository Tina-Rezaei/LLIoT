import ast
import json
import os
import random
import sqlite3
import matplotlib.pyplot as plt
import pandas as pd
import psycopg2
from matplotlib_venn import venn2, venn3
from config import setting


conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

def dedup_chen_categories(chen_categories):
    # Process keys with "UNKNOWN" last (so others keep priority)

    keys = [k for k in chen_categories if k != "other device"]

    seen = set()

    for k in keys:
        count, cve_set = chen_categories[k]
        new_set = {c for c in cve_set if c not in seen}
        # if k == "embedded device":
        #     print({c for c in cve_set if c in seen})
        seen.update(new_set)
        # reassign the whole tuple
        chen_categories[k] = (len(new_set), new_set)
    # process other device category in the end
    count, cve_set = chen_categories["other device"]
    new_set = {c for c in cve_set if c not in seen}
    seen.update(new_set)
    # reassign the whole tuple
    chen_categories["other device"] = (len(new_set), new_set)

    # (optional) drop empty categories
    # for k in list(chen_categories.keys()):
    #     if chen_categories[k][0] == 0:
    #         del chen_categories[k]

    return chen_categories


def remove_network_category(varIoT_cves, varIoT_categories, chen_cves, chen_categories, LLIoT_cves):
    # remove network devices from VarIoT and Chen datasets
    for key, values in varIoT_categories.items():
        if key == 'NETWORK DEVICE':
            for cve_id in values[1]:
                varIoT_cves.remove(cve_id)
                if cve_id in LLIoT_cves:
                    LLIoT_cves.remove(cve_id)
                if cve_id in chen_cves:
                    chen_cves.remove(cve_id)
        if key == 'UNKNOWN':
            # print(values[1])
            print("Unkown category:", key)
    for key, values in chen_categories.items():
        if key == 'network device':
            for cve_id in values[1]:
                if cve_id in chen_cves:
                    chen_cves.remove(cve_id)
                if cve_id in LLIoT_cves:
                    LLIoT_cves.remove(cve_id)
                if cve_id in varIoT_cves:
                    varIoT_cves.remove(cve_id)
    return varIoT_cves, varIoT_categories, chen_cves, chen_categories


def plot_three_way_venn(varIoT_cves, chen_cves, LLIoT_cves, pdf_path):
    plt.figure(figsize=(8, 8))
    venn = venn3(
        [varIoT_cves, chen_cves, LLIoT_cves],
        set_labels=("VarIoT", "Chen", "LLIoT"),
        set_colors=("#F44F56", "green", "#427CAC"),
        alpha=0.8
    )

    for lab in venn.set_labels:
        lab.set_fontsize(24)
    for lab in venn.subset_labels:
        if lab:
            lab.set_fontsize(22)

    # ids: '010' = Chen only, '110' = VarIoT∩Chen, '011' = Chen∩Proposed, '111' = all three
    offsets = {
        "010": (+0.06, +0.0),
        "110": (-0.04, +0.02),
        "011": (+0.03, -0.04),
        "111": (-0.02, -0.0),
    }

    for sid, (dx, dy) in offsets.items():
        lbl = venn.get_label_by_id(sid)
        if lbl:
            x, y = lbl.get_position()
            lbl.set_position((x + dx, y + dy))
            lbl.set_clip_on(False)
            lbl.set_horizontalalignment('center')
            lbl.set_verticalalignment('center')
    if not os.path.exists('./plots'):
        os.mkdir('./plots')
    plt.savefig( os.path.join('plots',pdf_path), bbox_inches="tight")
    plt.show()


# =============================================================================
# Load VarIoT dataset
# =============================================================================
with open("./varIoT_cves.txt", "r") as f:
    varIoT_cves = {ast.literal_eval(line)[0][0] for line in f.readlines() if int(ast.literal_eval(line)[0][0].split('-')[1])>2012 and int(ast.literal_eval(line)[0][0].split('-')[1])<2025}

with open("./varIoT_cves.txt", "r") as f:
    varIoT_categories = {}
    for line in f.readlines():
        parsed = ast.literal_eval(line)
        cve_id, category = parsed[0][0], list(parsed[1])
        if cve_id not in varIoT_cves:
            continue
        if "IoT" in category:
            category.remove("IoT")
        if category:
            category = category[0].strip().upper()
        else:
            category = "UNKNOWN"
        if category in varIoT_categories.keys():
            varIoT_categories[category] = varIoT_categories[category][0]+1, varIoT_categories[category][1].union({cve_id})
        else:
            varIoT_categories[category] = [1, ({cve_id})]

print("total CVEs in VarIoT:", sum([len(values[1]) for key, values in varIoT_categories.items()]))
print("VarIoT categories:", [(key,len(values[1])) for key, values in varIoT_categories.items()])

# =============================================================================
# Load Chen dataset
# =============================================================================
conn_sqlite = sqlite3.connect("CVE_IoT.sqlite")
cur = conn_sqlite.cursor()
cur.execute("SELECT CVE_Id FROM CVE_BASIC")
chen_cves = {row[0].upper() for row in cur.fetchall() if int(row[0].strip().upper().split('-')[1])>2012 and int(row[0].strip().upper().split('-')[1])<2025}

conn_sqlite.close()
print(f"Chen dataset: {len(set(chen_cves))} CVEs")
with open("./chen_device_categories.json", "r") as f:
    data = json.load(f)

chen_categories = {}
for element in data["deviceCategories"]:
    for category, values in element.items():
        for subcategory in values:
            cve_ids = subcategory["CVEList"]
            for cve_id in cve_ids:
                if category in chen_categories:
                    if cve_id not in chen_categories[category][1]:
                        # chen_categories[category] = chen_categories[category][0]+1, 1
                        chen_categories[category] = chen_categories[category][0]+1, chen_categories[category][1].union({cve_id})
                else:
                    # chen_categories[category] = [1, set()]
                    chen_categories[category] = [1, ({cve_id})]
for cve_id in chen_cves:
    if cve_id not in [item for value in chen_categories.values() for item in value[1]]:
        # chen_categories["other device"] = chen_categories.get("other device", [0, set()])
        chen_categories["other device"] = [chen_categories["other device"][0]+1, chen_categories["other device"][1].union({cve_id})]

print("\nchen_categories before removing duplicates:\n", [(key, value[0]) for key, value in chen_categories.items()], f"total: {sum([v[0] for v in chen_categories.values()])}")
number_of_samples = sum([v[0] for v in chen_categories.values()])
chen_categories = dedup_chen_categories(chen_categories)
print("\nchen_categories after removing duplicates:\n", [(key, value[0]) for key, value in chen_categories.items()], f"total: {sum([v[0] for v in chen_categories.values()])}")
print("\nnumber of redundant samples:", number_of_samples - sum([v[0] for v in chen_categories.values()]))

# =============================================================================
# Load LLIoT dataset
# =============================================================================

sql = """
    SELECT
        cve.cve_id AS cve_id
    FROM cve_iot_classification AS cve
    WHERE cve.is_iot=true
"""

with conn, conn.cursor() as cur:
    cur.execute(sql)
    LLIoT_cves = {row[0].upper() for row in cur.fetchall()}

# =============================================================================
# Figure A — Venn (including network devices)
# =============================================================================
plot_three_way_venn(
    varIoT_cves, chen_cves, LLIoT_cves,
    "cve_datasets_venn_including_network.pdf",
)


# =============================================================================
# VarIoT and LLIoT intersection
# =============================================================================
print("LLIoT and VarIoT intersection", len(list(set(varIoT_cves) & set(LLIoT_cves))))

varIoT_LLIoT_intersection = {}
categories = varIoT_categories.keys()

for cve_id in LLIoT_cves:
    if cve_id not in varIoT_cves:
        continue
    for c in categories:
        if cve_id in varIoT_categories[c][1]:
            category = c
    if category in varIoT_LLIoT_intersection.keys():
        varIoT_LLIoT_intersection[category] = [varIoT_LLIoT_intersection[category][0]+1, varIoT_LLIoT_intersection[category][1].union({cve_id})]
    else:
        varIoT_LLIoT_intersection[category] = [1,set()]

print(varIoT_LLIoT_intersection.keys())

print("\ntotal VarIoT CVES:", len(varIoT_cves))
print("\nVarIot :", sum([v[0] for v in varIoT_categories.values()]))
print("\nVarIot :", ([(k,v[0]) for k,v in varIoT_categories.items()]))

print("\nVarIot and LLIoT intersection:", sum([v[0] for v in varIoT_LLIoT_intersection.values()]))
print("\nVarIot and LLIoT intersection:", ([(k,v[0]) for k,v in varIoT_LLIoT_intersection.items()]))

# =============================================================================
# Analyze differences between Chen and proposed method
# =============================================================================
print("chen and proposed method diff:", len(chen_cves-LLIoT_cves))
diff = (chen_cves - LLIoT_cves)
chen_diff = {}
chen_diff = {key: [0, set({})] for key in chen_categories.keys()}

Chen_LLIoT_intersection = {}
categories = chen_categories.keys()
for cve_id in LLIoT_cves:
    if cve_id not in chen_cves:
        continue
    for c in categories:
        if cve_id in chen_categories[c][1]:
            category = c
    if category in Chen_LLIoT_intersection.keys():
        Chen_LLIoT_intersection[category] = [Chen_LLIoT_intersection[category][0]+1, Chen_LLIoT_intersection[category][1].union({cve_id})]
    else:
        Chen_LLIoT_intersection[category] = [1,set()]

print(Chen_LLIoT_intersection.keys())

print("\ntotal Chen CVES:", len(chen_cves))
print("\nChen :", sum([v[0] for v in chen_categories.values()]))
print("\nChen :", ([(k,v[0]) for k,v in chen_categories.items()]))

print("\nChen and LLIoT intersection:", sum([v[0] for v in Chen_LLIoT_intersection.values()]))
print("\nChen and LLIoT intersection:", ([(k,v[0]) for k,v in Chen_LLIoT_intersection.items()]))

# =============================================================================
# Exclude network CVEs from VarIoT / Chen / LLIoT sets
# =============================================================================
varIoT_cves, varIoT_categories, chen_cves, chen_categories = (
    remove_network_category(varIoT_cves, varIoT_categories, chen_cves, chen_categories, LLIoT_cves))

# =============================================================================
# Figure B — Venn (network excluded)
# =============================================================================
plot_three_way_venn(
    varIoT_cves, chen_cves, LLIoT_cves,
    "cve_datasets_venn_network_excluded.pdf",
)


