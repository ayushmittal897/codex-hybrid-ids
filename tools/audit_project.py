"""Read-only source/data audit; writes reports only. Never deserializes models."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'evidence'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = []
    for path in sorted(ROOT.rglob('*')):
        rel = path.relative_to(ROOT)
        if not path.is_file() or any(x in rel.parts for x in ('.git', 'node_modules', '.venv', '__pycache__', 'evidence')):
            continue
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        inventory.append({'path': rel.as_posix(), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest()})
    (OUT / 'file_inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    files = []
    total_labels = Counter()
    for path in sorted((ROOT / 'MachineLearningCSV').rglob('*.csv')):
        labels = Counter()
        missing = Counter()
        infinite = Counter()
        invalid = Counter()
        rows = 0
        bad_rows = 0
        columns = None
        for frame in pd.read_csv(path, chunksize=50000, low_memory=False):
            frame.columns = frame.columns.str.strip()
            columns = list(frame.columns)
            labels.update(frame['Label'].fillna('<missing>').astype(str).str.strip().value_counts().to_dict())
            numeric = frame.drop(columns=['Label'])
            converted = numeric.apply(pd.to_numeric, errors='coerce')
            missing.update({k:int(v) for k,v in numeric.isna().sum().items() if v})
            invalid.update({k:int(v) for k,v in (converted.isna() & numeric.notna()).sum().items() if v})
            inf = np.isinf(converted)
            infinite.update({k:int(v) for k,v in inf.sum().items() if v})
            bad_rows += int((converted.isna() | inf).any(axis=1).sum())
            rows += len(frame)
        item = {'file':path.relative_to(ROOT).as_posix(), 'rows':rows, 'columns':columns,
                'labels':dict(labels), 'missing_cells_by_column':dict(missing),
                'non_numeric_cells_by_column':dict(invalid), 'infinite_cells_by_column':dict(infinite),
                'rows_with_invalid_numeric_values':bad_rows}
        files.append(item)
        total_labels.update(labels)
        print(path.name, rows, json.dumps(dict(labels), ensure_ascii=True), flush=True)
    report = {'scope':'All rows and columns scanned; duplicate/conflicting-label counts not computed.',
              'total_rows':sum(x['rows'] for x in files), 'label_counts':dict(total_labels), 'files':files}
    (OUT / 'dataset_audit.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Total rows:', report['total_rows'], flush=True)


if __name__ == '__main__':
    main()
