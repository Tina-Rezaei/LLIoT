import json
import os
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import numpy as np


def add_value_labels(ax, spacing=5):
    """Add value labels on top of bars in a bar chart."""
    for rect in ax.patches:
        height = rect.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, spacing),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)

#===================load all reviews=========================

with open("reviews/expert_reviews.json", "r") as f:
    all_data = json.load(f)

#============================================================

full_agreement = 0
partial_agreement = 0
complete_disagreement = 0
two_iot = 0
consensus_iot = 0
two_non_iot = 0
consensus_non_iot = 0
two_unsure = 0
consensus_unsure = 0


# Aggregation logic
final_output = {}
COMPONENT_CATS = ["device", "communication", "application", "cloud backend", "unsure"]
comp_two_agree = {c: 0 for c in COMPONENT_CATS}
comp_full_consensus = {c: 0 for c in COMPONENT_CATS}
comp_complete_disagreement = 0

for cve_id, reviews in all_data.items():
    label_votes = {}
    component_votes = {}
    if len(reviews) < 3:
        # Skip CVEs with less than 3 reviews
        continue
    for reviewer, review in reviews.items():
        label_votes[reviewer] = review.get("manual_review_label")
        if review.get("manual_review_label") == "IoT specific":
            component_votes[reviewer] = review.get("affected_component")

    label_counter = Counter(label_votes.values())
    if len(label_counter) == 1:
        final_label = list(label_counter.keys())[0]
        full_agreement += 1
        if final_label == "IoT specific":
            consensus_iot += 1
        elif final_label == "Not IoT related":
            consensus_non_iot += 1
        if final_label == "Not sure":
            consensus_unsure += 1
    elif any(count == 2 for count in label_counter.values()):
        # Majority agreement
        final_label = next(label for label, count in label_counter.items() if count == 2)
        partial_agreement += 1
        if final_label == "IoT specific":
            two_iot += 1
        elif final_label == "Not IoT related":
            two_non_iot += 1
        elif final_label == "Not sure":
            two_unsure += 1
            print(cve_id)
    else:
        final_label = label_votes
        complete_disagreement += 1
        print(cve_id)


    if isinstance(final_label, str) and final_label == "IoT specific":
        component_votes = [
            r.get("affected_component")
            for r in reviews.values()
            if r.get("manual_review_label") == "IoT specific"
        ]
        component_votes = [c for c in component_votes if c]  # drop Nones
        if not component_votes:  # safety-check
            continue

        cc = Counter(component_votes)
        top_cat, top_count = cc.most_common(1)[0]

        if final_label == "IoT specific":
            if top_count == 3:  # 3/3 agree
                comp_full_consensus[top_cat] += 1
                final_component = top_cat
            elif top_count == 2:  # 2/3 agree
                comp_two_agree[top_cat] += 1
                final_component = top_cat
            else:  # 1–1–1 split
                comp_complete_disagreement += 1
                final_component = component_votes  # keep all votes
    else:
        final_component = None
    # Collect component votes *only* from reviewers who labelled it IoT


    result = {"manual_review_label": final_label}
    if final_label == "IoT specific" and final_component:
        result["affected_component"] = final_component
    final_output[cve_id] = result


# =======================================================================
# replace the tie-breaker decision for unsure and full disagreement votes
# =======================================================================


# Save output
with open("labels/final_labels.json", "w") as f:
    json.dump(final_output, f, indent=2)



# =======================================================================
# Analysis & Plots
# =======================================================================

# Bar labels
labels_main = ["IoT specific", "Not IoT", "Unsure"]
labels_all = labels_main + ["Full disagreement"]

# Stacked bar values
stack_data = {
    "Full consensus": np.array([consensus_iot, consensus_non_iot, consensus_unsure]),
    "Majority agreement": np.array([two_iot, two_non_iot, two_unsure])
}

# Create plot
fig, ax = plt.subplots(figsize=(12, 10))
x = np.arange(len(labels_all))

# Plot stacked bars (only for first 3 categories)
bottom = np.zeros(len(labels_main))
colors = ['#F44F56', '#427CAC']            # blue, green

for i, (label, values) in enumerate(stack_data.items()):
    ax.bar(x[:3], values, bottom=bottom, label=label, color=colors[i])
    bottom += values

    # Add text labels for each stack
    for j, val in enumerate(values):
        print(j)
        if j == 2 and i==1:
            y = bottom[j] - val / 2 + 9
        else:
            y = bottom[j] - val / 2 + 3
        ax.text(j, y, str(val), ha='center', va='center', fontsize=34, color='black', weight='bold')

# Add the separate bar for disagreement
disagreement_data = complete_disagreement
ax.bar(x[3], disagreement_data, color='#B6B09F', label="Full disagreement")
ax.text(x[3], disagreement_data / 2 + 2, str(disagreement_data), ha='center', va='center',
        fontsize=34, color='black', weight='bold')

# Final plot setup
# ax.set_title("IoT Label Summary by Reviewers", fontsize=16, weight='bold')
ax.set_ylabel("Number of CVEs", fontsize=32)
ax.set_xticks(x)
ax.set_xticklabels(labels_all, rotation=0, fontsize=28)
plt.setp(ax.get_xticklabels(), rotation=30, ha='right')  # Rotate x-axis labels
ax.tick_params(axis='y', labelsize=28)  # Enlarge y-axis tick labels
plt.ylim(0, max(bottom) + 70)
ax.legend(fontsize=32, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.savefig("plots/Manual_label_summary.pdf", dpi=300)
plt.show()



# --- Stacked bars (component categories) ---
labels_main = ["Device", "Communication", "Application", "Cloud backend", "Unsure"]
labels_all  = labels_main + ["Full disagreement"]
stack_data_comp = {
    "Full consensus": np.array([comp_full_consensus[c.lower()] for c in labels_main]),
    "Majority agreement":      np.array([comp_two_agree[c.lower()]      for c in labels_main]),
}
disagreement_comp = comp_complete_disagreement

fig, ax = plt.subplots(figsize=(12, 10))
x = np.arange(len(labels_all))
bottom = np.zeros(len(labels_main))

for i, (lbl, vals) in enumerate(stack_data_comp.items()):
    ax.bar(x[:5], vals, bottom=bottom, label=lbl, color=colors[i])
    bottom += vals
    # numeric labels
    for j, v in enumerate(vals):
        if v:
            y = bottom[j] - v / 2 + 0.4
            ax.text(j, y, str(v), ha='center', va='center',
                    fontsize=34, color='black', weight='bold')

# --- Separate bar: complete component disagreement ---
ax.bar(x[5], disagreement_comp, color='#B6B09F', label="Full disagreement")
if disagreement_comp:
    ax.text(x[5], disagreement_comp / 2, str(disagreement_comp),
            ha='center', va='center', fontsize=34,
            color='black', weight='bold')

# --- Cosmetics ---
# ax.set_title("IoT Component Label Summary by Reviewers", fontsize=16, weight='bold')
ax.set_ylabel("Number of CVEs", fontsize=32)
ax.set_xticks(x)
ax.set_xticklabels(labels_all,  fontsize=28)
plt.setp(ax.get_xticklabels(), rotation=30, ha='right')  # Rotate x-axis labels
ax.tick_params(axis='y', labelsize=28)  # Enlarge y-axis tick labels
ax.legend(fontsize=32, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.6)
plt.ylim(0, max(bottom) + 20)
plt.tight_layout()
plt.savefig("plots/manual_component_label_summary.pdf", dpi=300)
plt.show()


