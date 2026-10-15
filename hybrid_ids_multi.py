
import os
import json
import glob
import re
import warnings

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DATA_DIR = r"MachineLearningCSV\MachineLearningCVE"
OUTPUT_DIR = "models_multi"

CHUNK_SIZE = 100_000
MAX_PER_CLASS = 15_000
TEST_SIZE = 0.30
RANDOM_STATE = 42

LABEL_COL = "Label"

# Identifiers are excluded to reduce memorization.
IDENTIFIER_COLS = {
    "flow id",
    "source ip",
    "destination ip",
    "source port",
    "destination port",
    "timestamp",
    "unnamed: 0",
}

os.makedirs(OUTPUT_DIR, exist_ok=True)


# --------------------------------------------------
# LABEL NORMALIZATION
# --------------------------------------------------

def normalize_label(value):
    """Convert CIC-IDS2017 labels into broader attack classes."""

    label = str(value).strip().lower()
    label = re.sub(r"\s+", " ", label)

    if label == "benign":
        return "BENIGN"

    if "portscan" in label:
        return "PortScan"

    if "ddos" in label or label.startswith("dos "):
        return "DoS_DDoS"

    if "patator" in label or "brute force" in label:
        return "BruteForce"

    if label == "bot":
        return "Bot"

    if "web attack" in label or "xss" in label:
        return "WebAttack"

    if "sql injection" in label:
        return "WebAttack"

    if "infiltration" in label:
        return "Infiltration"

    # Includes rare or otherwise ungrouped attack types.
    return "Other"


# --------------------------------------------------
# MEMORY-CONSCIOUS DATA LOADING
# --------------------------------------------------

def load_dataset():
    files = sorted(
        glob.glob(os.path.join(DATA_DIR, "*.csv"))
    )

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in: {os.path.abspath(DATA_DIR)}"
        )

    print(f"Found {len(files)} CSV files.")

    samples = {}
    feature_columns = None
    total_rows = 0

    for file in files:
        print(f"\nReading: {os.path.basename(file)}")

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):
            chunk.columns = chunk.columns.str.strip()

            label_col = next(
                (
                    c for c in chunk.columns
                    if c.strip().lower() == LABEL_COL.lower()
                ),
                None,
            )

            if label_col is None:
                raise ValueError(
                    f"Label column not found in {file}"
                )

            # Find numeric features, excluding identifiers.
            if feature_columns is None:
                excluded = IDENTIFIER_COLS | {
                    label_col.lower()
                }

                candidates = [
                    c for c in chunk.columns
                    if c.strip().lower() not in excluded
                ]

                feature_columns = [
                    c for c in candidates
                    if pd.api.types.is_numeric_dtype(chunk[c])
                ]

                if not feature_columns:
                    raise ValueError(
                        "No numeric features found in the dataset."
                    )

                print(
                    f"Detected {len(feature_columns)} numeric features."
                )

            # Normalize labels before balancing.
            labels = chunk[label_col].map(normalize_label)

            # Convert features to numeric and clean invalid values.
            X = chunk.reindex(columns=feature_columns).copy()

            for col in feature_columns:
                X[col] = pd.to_numeric(
                    X[col], errors="coerce"
                )

            X = X.replace([np.inf, -np.inf], np.nan)

            # Remove rows with entirely missing feature vectors.
            valid = X.notna().any(axis=1)
            X = X.loc[valid]
            labels = labels.loc[valid]

            # Keep a bounded, reproducible sample per class.
            for category in labels.unique():
                current_count = len(samples.get(category, []))
                remaining = MAX_PER_CLASS - current_count

                if remaining <= 0:
                    continue

                indices = labels.index[
                    labels == category
                ]

                if len(indices) > remaining:
                    indices = pd.Series(indices).sample(
                        n=remaining,
                        random_state=RANDOM_STATE,
                    ).tolist()

                selected_X = X.loc[indices].copy()
                selected_y = labels.loc[indices].copy()

                if category not in samples:
                    samples[category] = []

                samples[category].append(
                    (selected_X, selected_y)
                )

            total_rows += len(chunk)

        print(f"Rows scanned so far: {total_rows:,}")

    X_parts = []
    y_parts = []

    for category, batches in samples.items():
        for x_batch, y_batch in batches:
            X_parts.append(x_batch)
            y_parts.append(y_batch)

    if not X_parts:
        raise ValueError("No usable training rows were loaded.")

    X_all = pd.concat(X_parts, ignore_index=True)
    y_all = pd.concat(y_parts, ignore_index=True)

    # Remove any accidental duplicate rows.
    combined = X_all.copy()
    combined["_target_"] = y_all.values
    combined = combined.drop_duplicates().reset_index(drop=True)

    y_all = combined.pop("_target_")
    X_all = combined

    print("\nSelected dataset class counts:")
    print(y_all.value_counts().to_string())
    print(f"\nTotal sampled flows: {len(X_all):,}")

    return X_all, y_all


# --------------------------------------------------
# TRAIN AND EVALUATE
# --------------------------------------------------

def main():
    X, y = load_dataset()

    # Classes with only one sample cannot appear in both splits.
    counts = y.value_counts()
    eligible = counts[counts >= 2].index

    keep = y.isin(eligible)
    X = X.loc[keep].reset_index(drop=True)
    y = y.loc[keep].reset_index(drop=True)

    if y.nunique() < 2:
        raise ValueError(
            "At least two classes with two or more samples are required."
        )

    # Stratify where possible to preserve class proportions.
    class_counts = y.value_counts()
    stratify = y if class_counts.min() >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )

    # Fit imputation on training data only.
    imputer = SimpleImputer(strategy="median")

    X_train = imputer.fit_transform(X_train)
    X_test = imputer.transform(X_test)

    print(
        f"\nTraining on {len(y_train):,} flows "
        f"with {X_train.shape[1]} features..."
    )

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n========== MULTI-CLASS RESULTS ==========")
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(
        f"Precision: {precision_score(y_test, predictions, average='macro', zero_division=0):.4f}"
    )
    print(
        f"Recall:    {recall_score(y_test, predictions, average='macro', zero_division=0):.4f}"
    )
    print(
        f"F1 score:  {f1_score(y_test, predictions, average='macro', zero_division=0):.4f}"
    )

    report = classification_report(
        y_test,
        predictions,
        labels=model.classes_,
        target_names=model.classes_,
        output_dict=True,
        zero_division=0,
    )

    print("\nPer-class report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=model.classes_,
            target_names=model.classes_,
            zero_division=0,
        )
    )

    # Save model artifacts separately from the original model.
    joblib.dump(model, os.path.join(OUTPUT_DIR, "classifier.pkl"))
    joblib.dump(imputer, os.path.join(OUTPUT_DIR, "imputer.pkl"))
    joblib.dump(
        list(X.columns),
        os.path.join(OUTPUT_DIR, "feature_columns.pkl"),
    )
    joblib.dump(
        list(model.classes_),
        os.path.join(OUTPUT_DIR, "classes.pkl"),
    )

    metadata = {
        "dataset": "CIC-IDS2017",
        "model": "RandomForestClassifier",
        "features": list(X.columns),
        "classes": list(model.classes_),
        "rows_scanned": None,
        "sampled_rows": int(len(y)),
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "random_state": RANDOM_STATE,
        "metrics": {
            "accuracy": float(accuracy_score(y_test, predictions)),
            "macro_precision": float(
                precision_score(y_test, predictions, average="macro", zero_division=0)
            ),
            "macro_recall": float(
                recall_score(y_test, predictions, average="macro", zero_division=0)
            ),
            "macro_f1": float(
                f1_score(y_test, predictions, average="macro", zero_division=0)
            ),
        },
        "per_class_report": report,
    }

    with open(
        os.path.join(OUTPUT_DIR, "metadata.json"),
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(metadata, file, indent=2)

    # Save a confusion matrix image if matplotlib is installed.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        cm = confusion_matrix(
            y_test, predictions, labels=model.classes_
        )

        fig, ax = plt.subplots(
            figsize=(max(7, len(model.classes_)), 6)
        )
        ax.imshow(cm, interpolation="nearest")
        ax.set_xticks(
            range(len(model.classes_)),
            model.classes_,
            rotation=45,
            ha="right",
        )
        ax.set_yticks(
            range(len(model.classes_)), model.classes_
        )
        ax.set_xlabel("Predicted label")
        ax.set_ylabel("True label")
        ax.set_title("CIC-IDS2017 Confusion Matrix")
        fig.tight_layout()
        fig.savefig(
            os.path.join(OUTPUT_DIR, "confusion_matrix.png"),
            dpi=150,
        )
        plt.close(fig)

    except ImportError:
        print("Matplotlib not installed; skipping confusion matrix.")

    print(f"\nArtifacts saved to: {OUTPUT_DIR}")
    print("Training completed successfully.")


if __name__ == "__main__":
    main()
		