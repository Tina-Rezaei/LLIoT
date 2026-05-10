import json
import numpy as np
import glob as glob
import krippendorff
from pprint import pprint
from typing import Dict, List, Tuple, Iterable
from collections import Counter
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple


def unanimity_rate(labels_dict):
    # 1 if all m runs agree for the item, else 0
    flags = np.array([1 if len(set(v))==1 else 0 for v in labels_dict.values()], dtype=float)
    return float(flags.mean()), flags  # point estimate and 0/1 vector


def bootstrap_ci_mean(values, B=10_000, seed=42, pct=(2.5, 97.5)):
    n = len(values)
    rng = np.random.default_rng(seed)
    boot = np.empty(B, float)
    for b in range(B):
        idx = rng.integers(0, n, size=n)
        boot[b] = float(values[idx].mean())
    return np.percentile(boot, pct)


# --- helper ---
def mode_share_unanimity(votes):
    c = Counter(votes)
    return max(c.values()) / len(votes)


# --- summary stats ---
def summarize(arr):
    if len(arr)==0:
        return {"n":0, "mean":np.nan, "median":np.nan, "p25":np.nan, "p75":np.nan}
    return {
        "n": len(arr),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "p25": float(np.percentile(arr,25)),
        "p75": float(np.percentile(arr,75)),
    }


def _has_two_codes(data: np.ndarray) -> bool:
    """True iff there are at least two distinct observed codes in data."""
    obs = data[~np.isnan(data)]
    return len(np.unique(obs)) >= 2


def build_reliability_matrix(labels_dict: Dict[str, List[str]],
                             label_to_code: Dict[str, int] = None
                             ) -> Tuple[np.ndarray, List[str], Dict[str, int]]:
    items = list(labels_dict.keys())
    if label_to_code is None:
        label_set = sorted({lab for labs in labels_dict.values() for lab in labs})
        label_to_code = {lab: i for i, lab in enumerate(label_set)}
    max_raters = max(len(v) for v in labels_dict.values())
    data = np.full((max_raters, len(items)), np.nan, dtype=float)
    for col, item in enumerate(items):
        for row, lab in enumerate(labels_dict[item]):
            data[row, col] = float(label_to_code[lab])
    return data, items, label_to_code


def filter_items_with_min_obs(data: np.ndarray, items: List[str], min_obs: int = 2):
    keep_cols = [j for j in range(data.shape[1]) if np.sum(~np.isnan(data[:, j])) >= min_obs]
    if not keep_cols:
        return np.empty((data.shape[0], 0)), []
    data_f = data[:, keep_cols]
    items_f = [items[j] for j in keep_cols]
    return data_f, items_f


def kripp_alpha_nominal_safe(data: np.ndarray) -> float:
    """
    Safe wrapper: returns np.nan if alpha is undefined (e.g., only one code in domain).
    """
    if data.size == 0:
        return float("nan")
    if not _has_two_codes(data):
        return float("nan")
    try:
        return float(krippendorff.alpha(reliability_data=data, level_of_measurement='nominal'))
    except ValueError:
        # Library may still raise if the domain collapses for internal reasons
        return float("nan")

def bootstrap_alpha_ci(data: np.ndarray, B: int = 5000, seed: int = 42,
                       percentiles=(2.5, 97.5), max_draws_factor: int = 20
                      ) -> Tuple[float, float, float]:
    """
    Bootstrap CIs by resampling items (columns). Skips resamples with <2 codes or
    with all columns dropping to <2 ratings. If too few valid resamples, returns nan CIs.
    """
    rng = np.random.default_rng(seed)
    n_items = data.shape[1]
    a0 = kripp_alpha_nominal_safe(data)

    boot = []
    max_draws = max_draws_factor * B  # avoid infinite loop
    draws = 0
    while len(boot) < B and draws < max_draws:
        draws += 1
        idx = rng.integers(0, n_items, size=n_items)
        d = data[:, idx]
        # keep columns with at least 2 ratings in the resample
        cols_keep = [j for j in range(d.shape[1]) if np.sum(~np.isnan(d[:, j])) >= 2]
        if not cols_keep:
            continue
        d = d[:, cols_keep]
        if not _has_two_codes(d):
            continue
        a = kripp_alpha_nominal_safe(d)
        if not np.isnan(a):
            boot.append(a)

    if len(boot) < max(50, int(0.5 * B)):  # not enough valid resamples
        return a0, float("nan"), float("nan")

    lo, hi = np.percentile(np.array(boot, float), percentiles)
    return a0, float(lo), float(hi)


def unanimity_ratio(all_results):

    # 1) labels across m runs (example)
    labels_dict = all_results
    all_keys = list(all_results.keys())

    # 2) Stratum (ground truth) for each item: "IoT" vs "non-IoT"
    strata = {cve_id: "IoT" for cve_id in all_keys[0:500]}
    strata.update({cve_id: "non-IoT" for cve_id in all_keys[500:]})

    IoT_opposing = {key: value for key, value in list(all_results.items())[0:500] if len(set(value)) > 1}
    nonIoT_opposing = {key: value for key, value in list(all_results.items())[500:1000] if len(set(value)) > 1}

    # --- Example usage ---
    # labels_dict = { "CVE-...": ["IoT","IoT",...], ... }
    labels_dict = all_results
    IoT_strata = {key: value for key, value in list(all_results.items())[0:500]}
    nonIoT_strata = {key: value for key, value in list(all_results.items())[500:1000]}
    U, flags = unanimity_rate(labels_dict)
    ci_boot = bootstrap_ci_mean(flags, B=10_000)

    iot_U, iot_flags = unanimity_rate(IoT_strata)
    nonIoT_U, nonIoT_flags = unanimity_rate(nonIoT_strata)
    iot_ci_boot = bootstrap_ci_mean(iot_flags, B=10_000)
    nonIoT_ci_boot = bootstrap_ci_mean(nonIoT_flags, B=10_000)

    print(f"IoT unanimity rate: {iot_U:.3f}  (95% bootstrap CI: [{iot_ci_boot[0]:.3f}, {iot_ci_boot[1]:.3f}])")
    print(
        f"Non-IoT unanimity rate: {nonIoT_U:.3f}  (95% bootstrap CI: [{nonIoT_ci_boot[0]:.3f}, {nonIoT_ci_boot[1]:.3f}])")
    print(f"Unanimity rate: {U:.3f}  (95% bootstrap CI: [{ci_boot[0]:.3f}, {ci_boot[1]:.3f}])")


def plot_nonunanimous_samples(IoT_opposing, nonIoT_opposing):
    Ci_iot = [mode_share_unanimity(v) for v in IoT_opposing.values()]
    Ci_non_iot = [mode_share_unanimity(v) for v in nonIoT_opposing.values()]
    print("IoT (non-unanimous)   :", summarize(Ci_iot))
    print("Non-IoT (non-unanimous):", summarize(Ci_non_iot))
    # --- box plot (single chart, no subplots) ---
    data = []
    labels = []

    if len(Ci_iot) > 0:
        data.append(Ci_iot)
        print(Ci_iot)
        labels.append(f"IoT (n={len(Ci_iot)})")

    if len(Ci_non_iot) > 0:
        data.append(Ci_non_iot)
        labels.append(f"Non-IoT (n={len(Ci_non_iot)})")

    if not data:
        raise ValueError("No non-unanimous items to plot in either group.")

    plt.style.use("seaborn-v0_8-whitegrid")  # clean background

    # Create figure
    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    # Boxplot with custom styling
    bp = ax.boxplot(
        data,
        showfliers=True,
        widths=0.4,
        patch_artist=True,
        whis=[0, 100],  # whiskers go to min/max
        boxprops=dict(facecolor="lightgray", color="black"),
        whiskerprops=dict(color="black"),
        capprops=dict(color="black"),
        medianprops=dict(color="darkred"),
        flierprops=dict(marker="o", markersize=3, markerfacecolor="black", alpha=0.5),
    )

    # Axis formatting
    ax.set_xticks([1, 2])
    ax.set_xticklabels(labels, fontsize=14)
    ax.set_ylabel(r"$C_i$", fontsize=14)
    ax.set_ylim(0.4, 1.0)
    plt.yticks(fontsize=14)
    # Grid and spines
    ax.yaxis.grid(True, linestyle="--", alpha=0.6)

    # Tight layout for saving
    plt.tight_layout()
    plt.savefig("consistency_boxplot.pdf", dpi=600, bbox_inches="tight")
    plt.show()


def mode_share(labels_for_item: Iterable[str]) -> float:
    """
    Maximum-class agreement for one item:
        C_i = max_c n_{i,c} / m
    where m = number of runs for the item.
    """
    labels_for_item = list(labels_for_item)
    m = len(labels_for_item)
    if m == 0:
        raise ValueError("Empty label list for an item.")
    counts = Counter(labels_for_item)
    return max(counts.values()) / m

def bootstrap_mean_ci(values: np.ndarray, B: int = 10_000, seed: int = 42,
                      percentiles=(2.5, 97.5)) -> Tuple[float, float]:
    """
    Nonparametric bootstrap CI for the mean over items.
    Resamples items with replacement; computes mean each time.
    """
    n = len(values)
    if n == 0:
        raise ValueError("No items to bootstrap over.")
    rng = np.random.default_rng(seed)
    boot_means = np.empty(B, dtype=float)
    for b in range(B):
        idx = rng.integers(0, n, size=n)     # resample over items
        boot_means[b] = float(np.mean(values[idx]))
    lo, hi = np.percentile(boot_means, percentiles)
    return lo, hi

def compute_Ci(labels_dict: Dict[str, List[str]]) -> Dict[str, float]:
    """
    Compute C_i for every item in labels_dict.
    Returns dict: item -> C_i
    """
    return {item: mode_share(votes) for item, votes in labels_dict.items()}

def summarize_mean_with_ci(Ci_map: Dict[str, float], items: Iterable[str]) -> Tuple[float, float, float, int]:
    """
    Given a mapping item->C_i and a subset of items, compute:
      - mean \bar{C}
      - 95% bootstrap CI (10,000 resamples over items)
      - number of items used
    """
    sel = [Ci_map[i] for i in items if i in Ci_map]
    if len(sel) == 0:
        return (float("nan"), float("nan"), float("nan"), 0)
    arr = np.array(sel, dtype=float)
    cbar = float(np.mean(arr))
    lo, hi = bootstrap_mean_ci(arr, B=10_000, seed=42)
    return cbar, lo, hi, len(arr)


def mean_mode_share_overall_and_strata(
    labels_dict: Dict[str, List[str]],
    strata: Dict[str, str] = None,
    iot_name: str = "IoT",
    non_iot_name: str = "non-IoT"
):
    """
    Computes:
      - Overall \bar{C} with 95% CI
      - Per-stratum \bar{C} with 95% CI (IoT vs non-IoT), if 'strata' is provided.

    Args:
        labels_dict: {item_id: [label_run1, ..., label_run_m]}
        strata: {item_id: "IoT" or "non-IoT"}  (ground-truth or grouping)
        iot_name, non_iot_name: names used in 'strata' for each group

    Returns: dict of results
    """
    # Per-item C_i
    Ci = compute_Ci(labels_dict)

    # Overall
    all_items = list(labels_dict.keys())
    overall_cbar, overall_lo, overall_hi, n_all = summarize_mean_with_ci(Ci, all_items)

    results = {
        "overall": {
            "n_items": n_all,
            "C_bar": overall_cbar,
            "CI95_low": overall_lo,
            "CI95_high": overall_hi
        }
    }

    # Stratified (optional)
    if strata is not None:
        # Normalize stratum labels just in case (case-insensitive)
        norm = {}
        for k, v in strata.items():
            if isinstance(v, str):
                vv = v.strip().lower()
                if vv in {"iot"}:
                    norm[k] = iot_name
                elif vv in {"non-iot", "non_iot", "not iot", "non iot"}:
                    norm[k] = non_iot_name
                else:
                    norm[k] = v  # leave as is
            else:
                norm[k] = v

        iot_items     = [item for item, grp in norm.items() if grp == iot_name and item in labels_dict]
        non_iot_items = [item for item, grp in norm.items() if grp == non_iot_name and item in labels_dict]

        iot_cbar, iot_lo, iot_hi, n_iot = summarize_mean_with_ci(Ci, iot_items)
        nio_cbar, nio_lo, nio_hi, n_nio = summarize_mean_with_ci(Ci, non_iot_items)

        results["by_stratum"] = {
            iot_name:     {"n_items": n_iot,  "C_bar": iot_cbar, "CI95_low": iot_lo, "CI95_high": iot_hi},
            non_iot_name: {"n_items": n_nio,  "C_bar": nio_cbar, "CI95_low": nio_lo, "CI95_high": nio_hi},
        }

    return results



if __name__ == "__main__":

    file_names = glob.glob("batch_responses_file*.jsonl")
    all_results = {}
    for file_name in file_names:
        with open(file_name, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            line = json.loads(line)
            elements = all_results.get(line['custom_id'], [])
            content = json.loads(line['response']['body']['choices'][0]['message']['content'])
            elements.append(content["label"])
            all_results[line['custom_id']] = elements

    unanimity_ratio(all_results)

    all_agreement_percentages = []
    for cve in all_results:
        labels = all_results[cve]
        labels_count = Counter(labels)
        all_agreement_percentages.append(max([count / len(labels) for key, count in labels_count.items()]))

    # print(all_agreement_percentages[0:500])
    # print(len([score for score in all_agreement_percentages if score == 1.0]))

    items = [labels for labels in all_results.values()]
    iot_items = items[0:500]
    noniot_items = items[500:]

    all_keys = list(all_results.keys())

    # 2) Stratum (ground truth) for each item: "IoT" vs "non-IoT"
    strata = {cve_id: "IoT" for cve_id in all_keys[0:500]}
    strata.update({cve_id: "non-IoT" for cve_id in all_keys[500:]})

    IoT_opposing = {key: value for key, value in list(all_results.items())[0:500] if len(set(value)) > 1}
    nonIoT_opposing = {key: value for key, value in list(all_results.items())[500:1000] if len(set(value)) > 1}

    # =========================================================
    plot_nonunanimous_samples(IoT_opposing, nonIoT_opposing)

    # --- Build full matrix from your labels_dict ---
    labels_dict = all_results
    data, items, label_to_code = build_reliability_matrix(labels_dict)
    data, items = filter_items_with_min_obs(data, items, min_obs=2)

    results = mean_mode_share_overall_and_strata(all_results, strata=strata, iot_name="IoT", non_iot_name="non-IoT")
    print(results)
    # --- Overall ---
    alpha_overall, lo_overall, hi_overall = bootstrap_alpha_ci(data, B=5000)
    print(f"Overall Krippendorff's alpha (nominal): "
          f"{alpha_overall if not np.isnan(alpha_overall) else float('nan'):.3f} "
          f"(95% CI [{lo_overall if not np.isnan(lo_overall) else float('nan'):.3f}, "
          f"{hi_overall if not np.isnan(hi_overall) else float('nan'):.3f}]); "
          f"items={data.shape[1]}")

