import psycopg2
import os
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib import transforms as mtransforms
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.colors import TwoSlopeNorm, Normalize
from config import setting

# --- DB config ---
DB_PARAMS = dict(
    dbname=setting.POSTGRES_DB,
    user=setting.POSTGRES_USER,
    password=setting.POSTGRES_PASSWORD,
    host=setting.POSTGRES_HOST,
    port=setting.POSTGRES_PORT
)

# --- CVSS vector parsing ---
BASE_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

LABEL_MAPS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}

AV_ORDER = ["Network", "Adjacent", "Local", "Physical"]

# Category orders for nicer, consistent plots
METRIC_ORDERS = {
    "AV_lbl": ["Network", "Adjacent", "Local", "Physical"],
    "AC_lbl": ["Low", "High"],
    "PR_lbl": ["None", "Low", "High"],
    "UI_lbl": ["None", "Required"],
    "S_lbl":  ["Unchanged", "Changed"],
    "C_lbl":  ["None", "Low", "High"],
    "I_lbl":  ["None", "Low", "High"],
    "A_lbl":  ["None", "Low", "High"],
}

UI_COLORS = {"None": "#4C78A8", "Required": "#F58518"}
SIMPLE_BLUE = "#4C78A8"
SIMPLE_ORANGE = "#F58518"


def get_cvss_data(is_iot=True):
    with psycopg2.connect(**DB_PARAMS) as conn:
        query = f"""
            WITH ranked_cvss AS (
                SELECT *,
                       ROW_NUMBER() OVER (
                           PARTITION BY cve_id
                           ORDER BY
                               CASE WHEN version = '3.1' THEN 1 ELSE 2 END,
                               CAST(version AS DECIMAL(3,1)) DESC
                       ) AS rn
                FROM cve_cvss
            ),
            cvss_with_severity AS (
                SELECT *,
                       CASE
                           WHEN base_score >= 9 THEN 'Critical'
                           WHEN base_score >= 7 THEN 'High'
                           WHEN base_score >= 4 THEN 'Medium'
                           ELSE 'Low'
                       END AS severity,
                CAST(split_part(ranked_cvss.cve_id, '-', 2) AS INT) AS year
                FROM ranked_cvss
                WHERE rn = 1
            )
            SELECT *
            FROM cvss_with_severity, cve_iot_classification
            WHERE cve_iot_classification.cve_id = cvss_with_severity.cve_id
              AND cve_iot_classification.is_iot = {str(is_iot).lower()}
        """
        return pd.read_sql(query, conn)


def parse_cvss_vector(vector):
    result = {k: None for k in BASE_KEYS}
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return result
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            if k in result:
                result[k] = v
    return result


def prepare_data(df):
    parsed = df["vector_string"].apply(parse_cvss_vector).apply(pd.Series)
    dfp = pd.concat([df, parsed], axis=1).dropna(subset=["AV"])
    for col, mapping in LABEL_MAPS.items():
        dfp[col + "_lbl"] = dfp[col].map(mapping).fillna(dfp[col])
    return dfp


def _counts(dfp, col, order):
    ct = dfp[col].value_counts().reindex(order, fill_value=0)
    return ct


def _percent(dfp, col, order):
    ct = _counts(dfp, col, order)
    tot = ct.sum() if ct.sum() else 1
    return (ct / tot) * 100


def plot_metric_delta_heatmap(dfp_iot, dfp_non, max_cells=4, show_na_labels=True):
    """
    Heatmap of (IoT% - non-IoT%) per CVSS metric.
    Each metric row has up to `max_cells` cells (pad with N/A gray).
    Cells show category name and percentage-point delta.
    Adds vertical group labels on the y-axis: Exploitability metrics (AV, AC, PR, UI) and Impact metrics (C, I, A).
    """
    metrics = ["AV_lbl","AC_lbl","PR_lbl","UI_lbl","S_lbl","C_lbl","I_lbl","A_lbl"]

    rows, label_rows, row_names = [], [], []

    for col in metrics:
        order_full = METRIC_ORDERS[col]
        order_capped = order_full[:max_cells]
        if len(order_capped) < max_cells:
            order_capped += [None] * (max_cells - len(order_capped))

        pct_iot = _percent(dfp_iot, col, order_full)
        pct_non = _percent(dfp_non, col, order_full)
        diff = pct_iot - pct_non

        row_vals, row_labels = [], []
        for cat in order_capped:
            if cat is None:
                row_vals.append(np.nan)
                row_labels.append("—")
            else:
                val = diff.loc[cat] if cat in diff.index else np.nan
                row_vals.append(float(val) if pd.notna(val) else np.nan)
                row_labels.append(str(cat))

        rows.append(row_vals)
        label_rows.append(row_labels)
        row_names.append(col.replace("_lbl",""))

    diff_mat = pd.DataFrame(rows, index=row_names,
                            columns=[f"v{i+1}" for i in range(max_cells)])
    labels_mat = pd.DataFrame(label_rows, index=row_names,
                              columns=[f"v{i+1}" for i in range(max_cells)])

    data = diff_mat.to_numpy(dtype=float)
    data_masked = np.ma.masked_invalid(data)

    finite_vals = data[np.isfinite(data)]
    if finite_vals.size == 0:
        norm = Normalize(vmin=-1.0, vmax=1.0)
    else:
        data_min, data_max = float(np.min(finite_vals)), float(np.max(finite_vals))
        if data_min == data_max:
            data_min -= 1e-6; data_max += 1e-6
        norm = TwoSlopeNorm(vmin=data_min, vcenter=0.0, vmax=data_max) if (data_min < 0 < data_max) \
               else Normalize(vmin=data_min, vmax=data_max)

    cmap = LinearSegmentedColormap.from_list(
        "custom_rb",
        ["#2166AC", "#F7F7F7", "#B2182B"],  # blue → neutral → red
        N=256
    )
    cmap.set_bad("#BEBEBE")  # gray for N/A cells
    cmap_name = 'coolwarm'
    cmap_name = ['#2c7bb6', '#f0f0f0', '#d7191c']
    na_color = '#BEBEBE'
    import matplotlib.cm as cm
    if isinstance(cmap_name, (list, tuple)):  # allow a custom 3+ color list
        cmap = LinearSegmentedColormap.from_list("custom_div", cmap_name, N=256)
    else:
        cmap = cm.get_cmap(cmap_name).copy()  # e.g., 'RdBu_r', 'BrBG', 'PuOr', 'coolwarm'
    cmap.set_bad(na_color)
    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(data_masked, aspect="auto", cmap=cmap, norm=norm, )

    ax.set_yticks(np.arange(len(diff_mat.index)))
    ax.set_yticklabels(diff_mat.index, fontsize=16)
    ax.set_xticks([])
    ax.set_xlabel("Values", fontsize=18)
    # ax.set_title("IoT% − Non-IoT% by CVSS Metric (red = IoT higher)")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Percentage point difference", fontsize=18)
    cbar.ax.tick_params(labelsize=16, width=1.2, length=6)

    # Contrast-aware text color
    def _text_color(val):
        if pd.isna(val):
            return "black"
        rgba = cmap(norm(val))
        lum = 0.299*rgba[0] + 0.587*rgba[1] + 0.114*rgba[2]
        return "black" if lum > 0.6 else "white"

    # annotate each cell with category and delta
    for i in range(diff_mat.shape[0]):
        for j in range(diff_mat.shape[1]):
            label = labels_mat.iat[i, j]
            val = diff_mat.iat[i, j]
            if pd.isna(val):
                txt = "" if show_na_labels and label == "—" else label
                ax.text(j, i, txt, ha="center", va="center", fontsize=16, color="black", linespacing=0.99)
            else:
                ax.text(j, i, f"{label}\n{val:+.1f}", ha="center", va="center",
                        fontsize=16, color=_text_color(val), linespacing=0.99,fontweight="bold")

    # ---- Vertical group labels on the y-axis ----
    # Map row names to indices
    row_pos = {name: idx for idx, name in enumerate(diff_mat.index)}
    exp_rows = [row_pos[k] for k in ["AV", "AC", "PR", "UI"] if k in row_pos]
    imp_rows = [row_pos[k] for k in ["C", "I", "A"] if k in row_pos]

    # blended transform: x in axes coords (so -0.06 is just left of y-axis), y in data coords (row index)
    trans = mtransforms.blended_transform_factory(ax.transAxes, ax.transData)
    # leave a bit of space on the left so vertical text isn't clipped
    fig.subplots_adjust(left=0.7)

    x_label = -0.075  # move further left/right if needed

    if exp_rows:
        exp_center = np.mean(exp_rows)
        ax.text(x_label, exp_center, "Exploitability metrics",
                transform=trans, rotation=90, rotation_mode='anchor',
                ha="center", va="center", fontsize=16, fontweight="bold",
                clip_on=False)

    if imp_rows:
        imp_center = np.mean(imp_rows)
        ax.text(x_label, imp_center, "Impact metrics",
                transform=trans, rotation=90, rotation_mode='anchor',
                ha="center", va="center", fontsize=16, fontweight="bold",
                clip_on=False)

    na_patch = Patch(facecolor="#BEBEBE", edgecolor="none", label="N/A (not applicable)")
    # ax.legend(handles=[na_patch], loc="upper right", frameon=True)

    fig.tight_layout()
    fig.savefig("./plots/cvss_metric_delta_heatmap.pdf", dpi=300)
    plt.close(fig)
    plt.show()
    return diff_mat


def cvss_heatmap(dfp, tag="iot"):
    pivot = dfp.pivot_table(index="year", columns="severity", aggfunc="size", fill_value=0)

    # Ensure correct severity order
    severity_order = ["Low", "Medium", "High", "Critical"]
    pivot = pivot.reindex(columns=severity_order, fill_value=0)
    pivot_normalized = pivot.div(pivot.sum(axis=1), axis=0) * 100
    plt.figure(figsize=(10, 6))
    pivot_normalized.index.name = None
    sns.heatmap(pivot_normalized, annot=True, fmt=".1f", cmap="YlOrRd", linewidths=0.5, annot_kws={"size": 18})
    plt.xlabel("Severity", fontsize=18)
    plt.yticks(fontsize=16,  rotation=45,)
    plt.xticks(fontsize=18)
    plt.tight_layout()
    cbar = plt.gca().collections[0].colorbar
    cbar.ax.tick_params(labelsize=18)
    plt.savefig(f"./plots/cvss_severity_by_year_{tag}.pdf")
    plt.show()


def run_comparative_analysis():
    if not os.path.exists('./plots'):
        os.makedirs('./plots')
    df_iot = get_cvss_data(True)
    df_non = get_cvss_data(False)
    dfp_iot = prepare_data(df_iot)
    dfp_noniot = prepare_data(df_non)
    cvss_heatmap(dfp_iot, "iot")
    cvss_heatmap(dfp_noniot, "nonIoT")
    diff_mat = plot_metric_delta_heatmap(dfp_iot, dfp_noniot)


run_comparative_analysis()