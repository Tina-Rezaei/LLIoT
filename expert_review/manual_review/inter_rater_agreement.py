import json
import krippendorff
import numpy as np


def compute_alpha(ratings_per_cve):
    # Transpose to rater-by-item format
    ratings_matrix = list(map(list, zip(*ratings_per_cve)))

    # Compute Krippendorff’s Alpha
    alpha = krippendorff.alpha(reliability_data=ratings_matrix, level_of_measurement='nominal')
    print(f"Krippendorff's Alpha (nominal): {alpha:.4f}")


def classification_level_agreement(reviews):
    # Mapping labels to numeric values
    label_map = {
        "IoT specific": 0,
        "Not IoT related": 1,
        "Not sure": np.nan
    }

    # We will build columns first, then transpose later
    ratings_per_cve = []
    for cve_id, reviewers in reviews.items():
        if len(reviewers) < 3:
            continue
        labels = [review.get("manual_review_label") for review in reviewers.values()]
        # Skip if any label is missing or unrecognized
        if None in labels or any(label not in label_map for label in labels):
            continue

        numeric_labels = [label_map[label] for label in labels]
        ratings_per_cve.append(numeric_labels)

    compute_alpha(ratings_per_cve)


def layer_level_agreement(final_labels, reviews):
    # Fixed component-to-number mapping
    component_map = {
        "application": 0,
        "communication": 1,
        "device": 2,
        "cloud backend": 3,
        "unsure": np.nan,
    }

    ratings_per_cve = []
    for cve_id, cve_reviews in reviews.items():
        ratings = []
        if cve_id in final_labels.keys():
            if final_labels[cve_id]["manual_review_label"] == "IoT specific":
                for review in cve_reviews.values():
                    if review.get("manual_review_label") == "IoT specific":
                        component = review.get("affected_component")
                        if component in component_map:
                            ratings.append(component_map[component])

        if ratings:
            while len(ratings) < 3:
                ratings.append(np.nan)  # Replace None with np.nan
            ratings = sorted(ratings)
            ratings_per_cve.append(ratings)

    compute_alpha(ratings_per_cve)


if __name__ == "__main__":
    with open("reviews/expert_reviews.json", "r") as f:
        reviews = json.load(f)

    with open("labels/final_labels.json") as f:
        final_labels = json.load(f)

    layer_level_agreement(final_labels, reviews)
    classification_level_agreement(reviews)


