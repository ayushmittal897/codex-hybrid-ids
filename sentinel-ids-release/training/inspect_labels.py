import glob
import os
import pandas as pd

folder = r"MachineLearningCSV\MachineLearningCVE"
files = sorted(glob.glob(os.path.join(folder, "*.csv")))

print("CSV files found:", len(files))

for file in files:
    print("\n" + os.path.basename(file))
    try:
        columns = pd.read_csv(file, nrows=0).columns
        label_col = next(
            (c for c in columns if c.strip().lower() == "label"),
            None
        )

        if label_col is None:
            print("ERROR: Label column not found")
            continue

        labels = pd.read_csv(
            file, usecols=[label_col], low_memory=False
        ).iloc[:, 0].astype(str).str.strip()

        print(labels.value_counts().to_string())

    except Exception as exc:
        print("ERROR:", exc)
