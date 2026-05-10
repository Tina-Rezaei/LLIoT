import psycopg2
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator, FuncFormatter
from config import setting


conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

def extract_year(df):
    return df["cve_id"].str.split("-").str[1].astype(int)
BASELINE = 2013          # baseline for the ratio lines
R_TICK_STEP = 0.5        # spacing between ratio ticks on the right axis (try 1.0 for even wider spacing)
BAR_WIDTH = 0.36
BAR_GAP   = 0.06         # space between IoT / Non-IoT bars per year (visual separation)
ANNOTATE_BARS = False

if not os.path.exists('./plots'):
    os.makedirs('./plots')

# Queries
IoT_query = """
SELECT * FROM cve_iot_classification, cve_cve 
WHERE cve_cve.id = cve_iot_classification.cve_id AND is_iot = true and cve_cve.status != 'R'
"""

Non_IoT_query = """
SELECT * FROM cve_iot_classification, cve_cve 
WHERE cve_cve.id = cve_iot_classification.cve_id AND is_iot = false and cve_cve.status != 'R'
"""

# Read data
iot_df = pd.read_sql(IoT_query, conn)
non_iot_df = pd.read_sql(Non_IoT_query, conn)

# Extract years
iot_years = extract_year(iot_df)
non_iot_years = extract_year(non_iot_df)

# Count CVEs per year
iot_counts = iot_years.value_counts().sort_index()
non_iot_counts = non_iot_years.value_counts().sort_index()

# Align all years
all_years = sorted(set(iot_counts.index).union(set(non_iot_counts.index)))
iot_counts = iot_counts.reindex(all_years, fill_value=0)
non_iot_counts = non_iot_counts.reindex(all_years, fill_value=0)

# Bar positions
x = np.arange(len(all_years))
bar_width = 0.35
spacing = 0.05  # space between the bars of same year

# Plotting
plt.figure(figsize=(13, 6), dpi=300)

# IoT bars
bars1 = plt.bar(x - (bar_width / 2 + spacing / 2), iot_counts / 1000, width=bar_width,
                label="IoT", color="#0666e5", edgecolor="#0666e5")

# Non-IoT bars
bars2 = plt.bar(x + (bar_width / 2 + spacing / 2), non_iot_counts / 1000, width=bar_width,
                label="Non-IoT", color="#0f2741", edgecolor="black")

# Labels on bars
for bar in bars1:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height + 0.1, f"{round(height, 1)}",
             ha="center", va="bottom", fontsize=18)

for bar in bars2:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height + 0.1, f"{round(height,1)}",
             ha="center", va="bottom", fontsize=18)

# --- choose your baseline year for ratios ---
BASELINE = 2013
if BASELINE not in iot_counts.index or iot_counts.loc[BASELINE] == 0 or non_iot_counts.loc[BASELINE] == 0:
    raise ValueError(f"Baseline year {BASELINE} missing or has zero count.")

# Ratios (× vs baseline); safe divide
iot_ratio = iot_counts / iot_counts.loc[BASELINE]
non_iot_ratio = non_iot_counts / non_iot_counts.loc[BASELINE]

# --- plotting (add after your two bar plots and before plt.savefig) ---
ax = plt.gca()

#if ANNOTATE_BARS:
if ANNOTATE_BARS:
    for bars in (bars1, bars2):
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width()/2, h + 0.08, f"{h:.1f}",
                    ha="center", va="bottom", fontsize=18)

# Right axis for ratios, with wider tick spacing
ax2 = ax.twinx()
(line1,) = ax2.plot(x, iot_ratio.values, marker='*', linewidth=2.2, label=f"IoT × vs {BASELINE}", color="#50c1f0", markersize=10)
#make marker bigger
(line2,) = ax2.plot(x, non_iot_ratio.values, marker='o',  linewidth=2.2, label=f"Non-IoT × vs {BASELINE}", color="#9eaec4", markersize=7)
ax2.axhline(1.0, linestyle='--', linewidth=1, alpha=0.6)

# Tick spacing on the right axis (this widens distance between units)
ax2.yaxis.set_major_locator(MultipleLocator(R_TICK_STEP))
ax2.yaxis.set_major_formatter(FuncFormatter(lambda v, pos: f"{v:.1f}×"))

# Nice right-axis limit aligned to the locator
rmax = float(np.nanmax([iot_ratio.max(), non_iot_ratio.max()]))
r_top = (np.floor(rmax / R_TICK_STEP) + 1) * R_TICK_STEP
ax2.set_ylim(0, max(r_top, R_TICK_STEP*2))

# Axes cosmetics
ax.set_ylabel("Number of CVEs (thousands)", fontsize=26)
ax2.set_ylabel(f"Increase ratio vs {BASELINE}", fontsize=26)

ax.set_xticks(x)
ax.set_xticklabels(all_years, rotation=45, fontsize=20)

ax.tick_params(axis='y', labelsize=20)
ax2.tick_params(axis='y', labelsize=20)

# L-axis grid only for readability
ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.set_axisbelow(True)

# Left y-limit
ax.set_ylim(0, (max(iot_counts.max(), non_iot_counts.max()) / 1000) * 1.15)

# Single combined legend (bars + lines)
handles = [bars1, bars2, line1, line2]
labels  = ["IoT", "Non-IoT", f"IoT × vs {BASELINE}", f"Non-IoT × vs {BASELINE}"]
ax.legend(handles, labels, fontsize=24, loc="upper left", frameon=False)

plt.margins(x=0.01)
plt.tight_layout()
plt.savefig("./plots/iot_vs_non_iot_histogram.pdf", bbox_inches="tight", dpi=300)
plt.show()