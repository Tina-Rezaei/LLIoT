import os.path

import psycopg2
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from config import setting

# --- DB config ---
conn = psycopg2.connect(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)


def smooth(df, window=3):
    """Simple centered rolling mean to de-noise lines (no phase shift at ends)."""
    return df.rolling(window=window, center=True, min_periods=1).mean()

def plot_lines(pivot, title, outfile, label_to_color, highlight_top=5):
    # optional smoothing (comment out if you want raw counts)
    df = smooth(pivot, window=3)
    # df.remove_columns = df.columns['Memory safety']
    # Choose aesthetics: slightly thicker + opaque for top series, thinner + faded for the rest
    totals = df.sum(axis=0).sort_values(ascending=False)
    top = set(totals.head(highlight_top).index)
    top.add('Missing Auth (Critical)')
    top.add('Access Control')
    top.add('NULL Deref')
    # top.add('Int Overflow')
    import itertools
    default_cycle = itertools.cycle(plt.rcParams['axes.prop_cycle'].by_key()['color'])

    fig, ax = plt.subplots(figsize=(17, 6), dpi=300)

    for col in df.columns:
        lw   = 2.5 if col in top else 1.5
        alp  = 0.95 if col in top else 0.55
        ax.plot(df.index, df[col],
                label=col,
                color=label_to_color.get(col, '#888888'),
                linewidth=lw, alpha=alp)


    ax.set_ylabel('Count', fontsize=32)
    ax.tick_params(labelsize=28)
    ax.grid(axis='y', linestyle='--', alpha=0.35)


    handles, labels = ax.get_legend_handles_labels()
    last_values = df.iloc[-1]  # take the last row (latest year)
    order = np.argsort(-last_values.values)  # sort descending
    handles, labels = ax.get_legend_handles_labels()

    # Create a mapping from label to handle
    label_to_handle = dict(zip(labels, handles))

    # Reorder according to line values at the right edge
    labels_sorted = [df.columns[i] for i in order]
    handles_sorted = [label_to_handle[label] for label in labels_sorted]

    # Plot legend below the figure (4 items per row)
    fig.legend(
        handles_sorted, labels_sorted,
        loc='lower center',
        bbox_to_anchor=(0.52, -0.15),
        ncol=3,
        fontsize=24,
        frameon=False,
        columnspacing=0.8
    )


    fig.tight_layout(rect=[0, 0.13, 1, 1])  # leave space at the bottom for the legend
    fig.savefig(outfile, bbox_inches='tight')
    plt.show()

def plot_lines_on_ax(ax, pivot, title, label_to_color, highlight_top=5):
    df = smooth(pivot, window=3)

    totals = df.sum(axis=0).sort_values(ascending=False)
    top = set(totals.head(highlight_top).index)
    top.add('Missing Auth (Critical)')
    top.add('Access Control')
    top.add('NULL Deref')

    for col in df.columns:
    # for col in columns:
        lw = 2.5 if col in top else 1.5
        alp = 0.95 if col in top else 0.55
        ax.plot(df.index, df[col],
                label=col,
                color=label_to_color.get(col, '#888888'),
                linewidth=lw, alpha=alp)

    ax.set_title(title, fontsize=30)
    # ax.set_xlabel('Year', fontsize=22)
    ax.set_ylabel('Count', fontsize=30)
    ax.tick_params(labelsize=25)
    ax.grid(axis='y', linestyle='--', alpha=0.35)

    return totals


if not os.path.exists('./plots'):
    os.makedirs('./plots')


TOP_N = 20  # adjust as needed

q_iot_topN = f"""
SELECT  cwe.name,
        COUNT(*) AS cnt
FROM    cve_iot_classification AS iot
JOIN    cve_cve_cwes         AS map  ON map.cve_id = iot.cve_id
JOIN    cve_cwe              AS cwe  ON cwe.id      = map.cwe_id
WHERE   iot.is_iot = TRUE
GROUP BY cwe.name
ORDER BY cnt DESC
LIMIT {TOP_N};
"""

q_non_topN = q_iot_topN.replace(" = TRUE", " = FALSE")

iot_top_df = pd.read_sql(q_iot_topN, conn)
non_top_df = pd.read_sql(q_non_topN, conn)

top_cwes_iot = iot_top_df["name"].tolist()
top_cwes_non_iot = non_top_df["name"].tolist()

# Combined unique list for subsequent queries
top_cwes_all = list({*top_cwes_iot, *top_cwes_non_iot})



q_timeline = f"""
SELECT  cwe.name                 AS cwe_name,
        iot.is_iot               AS is_iot,
        make_date(split_part(cve.id, '-', 2)::int, 1, 1) AS year,
        COUNT(*)                 AS cnt
FROM    cve_iot_classification AS iot
JOIN    cve_cve                AS cve ON cve.id = iot.cve_id
JOIN    cve_cve_cwes           AS map ON map.cve_id = cve.id
JOIN    cve_cwe                AS cwe ON cwe.id  = map.cwe_id
WHERE   cwe.name = ANY(%s) and cve.status != 'R'
GROUP BY cwe_name, is_iot, year
ORDER BY year;
"""
timeline_df = pd.read_sql(q_timeline, conn, params=(top_cwes_all,))

# Ensure proper dtypes
timeline_df["year"] = pd.to_datetime(timeline_df["year"]).dt.year.astype("Int64")



overall = (timeline_df
           .groupby(['cwe_name', 'year'], as_index=False)
           .agg(cnt=('cnt', 'sum')))

year_totals = timeline_df.groupby('year', as_index=False)['cnt'].sum()
year_totals = year_totals.rename(columns={'cnt': 'year_total'})

family_year_totals = timeline_df.groupby(['is_iot', 'year'], as_index=False)['cnt'].sum()
family_year_totals = family_year_totals.rename(columns={'cnt': 'family_year_total'})

# Merge back into original
timeline_df = timeline_df.merge(family_year_totals, on=['is_iot', 'year'])
# Merge year totals back into timeline_df
# timeline_df = timeline_df.merge(year_totals, on='year')

# Normalize count per CWE by total CVEs that year
# timeline_df['cnt_norm'] = timeline_df['cnt'] / timeline_df['year_total']
timeline_df['cnt_norm'] = timeline_df['cnt'] / timeline_df['family_year_total']

iot_df     = timeline_df[timeline_df['is_iot']]
noniot_df  = timeline_df[~timeline_df['is_iot']]


iot_pivot = (timeline_df[timeline_df['is_iot']]
             .pivot_table(index='year', columns='cwe_name', values='cnt', aggfunc='sum')
             .fillna(0)
             .sort_index())

noniot_pivot = (timeline_df[~timeline_df['is_iot']]
                .pivot_table(index='year', columns='cwe_name', values='cnt', aggfunc='sum')
                .fillna(0)
                .sort_index())


top_iot_cwes = (timeline_df[timeline_df['is_iot']]
                .groupby('cwe_name')['cnt'].sum()
                .nlargest(20).index)

top_noniot_cwes = (timeline_df[~timeline_df['is_iot']]
                   .groupby('cwe_name')['cnt'].sum()
                   .nlargest(20).index)

iot_pivot = iot_pivot[top_iot_cwes.intersection(iot_pivot.columns)]
noniot_pivot = noniot_pivot[top_noniot_cwes.intersection(noniot_pivot.columns)]




cwe_short_labels = {
    "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')": "XSS",
    "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')": "SQLi",
    "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')": "OS Cmd Inj",
    "Improper Neutralization of Special Elements used in a Command ('Command Injection')": "Command Inj",
    "Improper Control of Generation of Code ('Code Injection')": "Code Inj",
    "Improper Input Validation": "Input Validation",
    "Out-of-bounds Write": "OOB Write",
    "Out-of-bounds Read": "OOB Read",
    "Use After Free": "Use-After-Free",
    "NULL Pointer Dereference": "NULL Deref",
    "Cross-Site Request Forgery (CSRF)": "CSRF",
    "Improper Restriction of Operations within the Bounds of a Memory Buffer": "Memory Bounds",
    "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')": "Classic BOF",
    "Stack-based Buffer Overflow": "Stack BOF",
    "Integer Overflow or Wraparound": "Int Overflow",
    "Exposure of Sensitive Information to an Unauthorized Actor": "Sensitive Info Leak",
    "Missing Authorization": "Missing Authorization",
    "Permissions, Privileges, and Access Controls": "Access Control",
    "Improper Access Control": "Improper Access",
    "Unrestricted Upload of File with Dangerous Type": "File Upload",
    "Improper Authentication": "Auth Failure",
    "Use of Hard-coded Credentials": "Hardcoded Creds",
    "Missing Authentication for Critical Function": "Missing Auth (Critical)",
    "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')": "Path Traversal",
    "Uncontrolled Resource Consumption": "Resource Consumption",
    "Insufficiently Protected Credentials": "Weak Creds",
}
from itertools import cycle
palette = [
    "#4E79A7","#F28E2B","#E15759","#76B7B2","#59A14F",
    "#EDC948","#B07AA1","#FF9DA7","#9C755F","#BAB0AC",
    "#1F77B4","#FF7F0E","#2CA02C","#D62728","#9467BD",
    "#8C564B","#E377C2","#7F7F7F","#BCBD22","#17BECF",
]
# 2) Rename columns once so both frames use the same short labels
iot_pivot = iot_pivot.rename(columns=lambda c: cwe_short_labels.get(c, c))

noniot_pivot = noniot_pivot.rename(columns=lambda c: cwe_short_labels.get(c, c))


bucket_map = {
    # Memory safety (buffer bounds parent + related)
    "OOB Write": "Memory safety",
    "OOB Read": "Memory safety",
    "Classic BOF": "Memory safety",
    "Stack BOF": "Memory safety",
    "Memory Bounds": "Memory safety",
    "Use-After-Free": "Memory safety",
    "Int Overflow": "Memory safety",
    "NULL Deref": "Memory safety",

    "Input Validation": "Input Validation (CWE-20)",

    # Injection
    "XSS": "XSS (CWE-79)",
    "SQLi": "SQLi (CWE-89)",
    "Path Traversal": "Path Traversal (CWE-22)",
    "CSRF": "CSRF (CWE-352)",

    "OS Cmd Inj": "OS Cmd Inj (CWE-78)",
    "Command Inj": "Command Inj (CWE-77)",
    "Code Inj": "Code Inj (CWE-94)",

    # Path/Filesystem
    "File Upload": "File Upload (CWE-434)",

    # AuthN/AuthZ & Access control
    "Auth Failure": "Authentication Failure (CWE-287)",
    "Missing Auth (Critical)": "No Authentication on Func (CWE-306)",
    "Improper Access": "Improper Access (CWE-284)",
    "Access Control": "Access Control (CWE-264)",  # deprecated but included per label
    "Hardcoded Creds": "Hardcoded Creds (CWE-798)",

    # Sensitive data
    "Sensitive Info Leak": "Sensitive Info Leak (CWE-200)",

    # Availability
    "Resource Consumption": "Resource Consumption (CWE-400)",
    "Missing Authorization": "Missing Authorization (CWE-862)",
}

bucket_map_groupB = {
    # Memory safety (buffer bounds parent + related)
    "OOB Write": "OOB Write (CWE-787)",
    "OOB Read": "OOB Read (CWE-125)",
    "Classic BOF": "Classic BOF (CWE-120)",
    "Stack BOF": "Stack BOF (CWE-121)",
    "Memory Bounds": "Memory Bounds (CWE-119)",
    "Use-After-Free": "Use-After-Free (CWE-416)",
    "Int Overflow": "Int Overflow (CWE-190)",
    "NULL Deref": "NULL Deref (CWE-476)"
}

# apply to your pivot
def bucketed(pivot, bucket_map):
    df = pivot.copy()
    df.columns = [bucket_map.get(c, c) for c in df.columns]
    return df.groupby(axis=1, level=0).sum()

iot_bucketed    = bucketed(iot_pivot, bucket_map)
noniot_bucketed = bucketed(noniot_pivot, bucket_map)
bucket_labels = list(dict.fromkeys(
    list(iot_bucketed.columns) + list(noniot_bucketed.columns)
))


def memory_safety_percentages(pivot: pd.DataFrame, bucket_map: dict) -> pd.DataFrame:
    # columns that roll up into "Memory safety"
    ms_members = [k for k, v in bucket_map.items() if v == "Memory safety" and k in pivot.columns]
    if not ms_members:
        # nothing to compute
        return pd.DataFrame(index=pivot.index)

    # counts for each memory-safety member
    ms_counts = pivot[ms_members].copy()

    # row-wise total of memory safety
    ms_total = ms_counts.sum(axis=1)

    # avoid divide-by-zero (rows with 0 total stay 0.0)
    with pd.option_context('mode.use_inf_as_na', True):
        ms_pct = ms_counts.div(ms_total.replace(0, pd.NA), axis=0) * 100
        ms_pct = ms_pct.fillna(0.0)

    # Optional: order columns nicely
    ms_pct = ms_pct.reindex(columns=ms_members)

    return ms_pct
bucket_palette = [
    "#4E79A7", "#E15759", "#59A14F", "#EDC948",
    "#B07AA1", "#76B7B2", "#F28E2B", "#9C755F",
    "#AF7AA1", "#86BCB6"  # extras if needed
][:len(bucket_labels)]

# bucket_to_color = {lab: col for lab, col in zip(bucket_labels, bucket_palette)}
bucket_to_color = {
    "Memory safety": "#4E79A7",
    "OOB Write (CWE-787)": "#4E79A7",
    "Input Validation (CWE-20)": "#948979",
    "XSS (CWE-79)": "#DDA853",
    "Path Traversal (CWE-22)": "#2CA07C",
    "Authentication Failure (CWE-287)": "brown",
    "Sensitive Info Leak (CWE-200)": "#CEB0a7",
    "Memory Bounds (CWE-119)": "#F28E2B",
    "Classic BOF (CWE-120)": "#FF9DA7",
    "OOB Read (CWE-125)": "#86BCB6",
    "OS Cmd Inj (CWE-78)": "#08CB00",
    "Hardcoded Creds (CWE-798)": "#BCBD22",
    "No Authentication on Func (CWE-306)": "#DD0303",
    "SQLi (CWE-89)": "#E377C2",
    "Stack BOF (CWE-121)": "#D62728",
    "Improper Access (CWE-284)": "blue",
    "Use-After-Free (CWE-416)": "#8C564B",
    "NULL Deref (CWE-476)": "#7F55B1",
    "Resource Consumption (CWE-400)": "#7F55B1",
    "Int Overflow (CWE-190)": "#59A14F",
    "CSRF (CWE-352)": "#17BECF",
    "Code Inj (CWE-94)": "#FDA403",
    "Access Control (CWE-264)": "#000000",  # deprecated; often maps to CWE-284
    "File Upload (CWE-434)": "#898121",
    "Missing Authorization (CWE-862)": "#F9E400",
}
# ----- plot IoT and non-IoT as line charts -----"

from itertools import cycle
palette = [
    "#4E79A7","#F28E2B","#E15759","#76B7B2","#59A14F",
    "#EDC948","#B07AA1","#FF9DA7","#9C755F","#BAB0AC",
    "#1F77B4","#FF7F0E","#2CA02C","#D62728","#9467BD",
    "#8C564B","#E377C2","#7F7F7F","#BCBD22","#17BECF",
]
# 2) Rename columns once so both frames use the same short labels
iot_pivot    = iot_pivot.rename(columns=lambda c: cwe_short_labels.get(c, c))

noniot_pivot = noniot_pivot.rename(columns=lambda c: cwe_short_labels.get(c, c))

# 3) Build a single color map covering ALL labels across both plots
all_labels = list(dict.fromkeys(list(iot_pivot.columns) + list(noniot_pivot.columns)))
color_cycle = cycle(palette)  # cycles if there are more labels than colors
label_to_color = {label: next(color_cycle) for label in all_labels}


groupA_labels = [
    # Memory safety (buffer bounds parent + related)
    "OOB Write", "OOB Read", "Classic BOF", "Stack BOF", "Memory Bounds", "Use-After-Free",
    # Numerics / pointer
    "Int Overflow", "NULL Deref",
    # Injection (web + non-web)
    "XSS", "SQLi", "Path Traversal", "CSRF", "OS Cmd Inj", "Command Inj", "Code Inj",
    # Path/Filesystem
    "File Upload",
    # AuthN/AuthZ & Access control
    "Auth Failure", "Improper Access", "Access Control", "Missing Auth (Critical)", "Hardcoded Creds",
    # Sensitive data
    "Sensitive Info Leak", "Resource Consumption", "Input Validation",
    # Availability
    "Missing Authorization"
]

groupB_labels = [
    "OOB Write", "OOB Read", "Classic BOF", "Stack BOF", "Memory Bounds",
    "Use-After-Free", "Int Overflow", "NULL Deref"
]

# Sanity: ensure no overlap
# assert set(groupA_labels).isdisjoint(set(groupB_labels)), "Group A/B label overlap!"

# --- 2) Build subset maps from your existing bucket_map ---

bucket_map_A = {k: v for k, v in bucket_map.items() if k in groupA_labels}
bucket_map_B = {k: v for k, v in bucket_map_groupB.items() if k in groupB_labels}

# --- 3) Helper to bucket *and* subset columns safely ---

def bucketed_subset(pivot, submap):
    # keep only columns present in both the pivot and the submap
    subset_cols = [c for c in pivot.columns if c in submap]
    if not subset_cols:
        # Return empty frame with same index if nothing matches
        return pivot.iloc[:, 0:0].copy()
    df = pivot[subset_cols].copy()
    # apply mapping and group by resulting bucket names
    df.columns = [submap.get(c, c) for c in df.columns]
    # pandas 2.x friendly axis usage
    return df.groupby(level=0, axis=1).sum()

# --- 4) Compute bucketed data for each group ---

iot_A     = bucketed_subset(iot_pivot,     bucket_map_A)
noniot_A  = bucketed_subset(noniot_pivot,  bucket_map_A)
iot_B     = bucketed_subset(iot_pivot,     bucket_map_B)
noniot_B  = bucketed_subset(noniot_pivot,  bucket_map_B)

# --- 5) Build colors per-plot (only for the buckets that appear in that plot) ---

def build_palette(labels):
    palette = [
     "#332288", "#88CCEE", "#44AA99", "#117733",
    "#999933", "#DDCC77", "#CC6677", "#882255",
    "#AA4499", "#661100", "#6699CC", "#AA4466",
    "#4477AA", "#66CCEE", "#228833", "#CCBB44",
    ][:len(labels)]
    return {lab: col for lab, col in zip(labels, palette)}

bucket_labels_A = list(iot_A.columns.union(noniot_A.columns))
bucket_labels_B = list(iot_B.columns.union(noniot_B.columns))

color_A = build_palette(bucket_labels_A)
color_B = build_palette(bucket_labels_B)

# --- Plot ---

ms_pct_iot = memory_safety_percentages(iot_pivot, bucket_map)
print(ms_pct_iot.round(2))

plot_lines(iot_A,
           'IoT CWE trends (Group A: memory/injection/filesystem)',
           './plots/iot_cwes_over_time.pdf',
           bucket_to_color, highlight_top=8)

plot_lines(noniot_A,
           'Non-IoT CWE trends (Group A: memory/injection/filesystem)',
           './plots/noniot_cwes_over_time.pdf',
           bucket_to_color, highlight_top=8)
# Group B
plot_lines(iot_B,
           'IoT CWE trends (Group B: auth/sensitive/availability)',
           './plots/iot_cwes_over_time_memory_safety.pdf',
           bucket_to_color, highlight_top=6)

plot_lines(noniot_B,
           'Non-IoT CWE trends (Group B: auth/sensitive/availability)',
           './plots/noniot_cwes_over_time_memory_safety.pdf',
           bucket_to_color, highlight_top=6)

