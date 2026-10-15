"""
Hybrid IDS: flow features -> rule engine + ML classifier -> hybrid risk score -> alerts.

Covers Levels 1, 5 and 6 of the project plan (ML foundation, rule engine, hybrid
engine) in one file. Split it into src/ml, src/rules and src/detection later.

Usage:
    # Train + evaluate (ML only vs Rules only vs Hybrid) on CIC-IDS2017 CSVs
    python hybrid_ids.py train --data dataset/raw/ --model rf
    python hybrid_ids.py train --data dataset/raw/ --model xgb

    # Quick pipeline check without the dataset
    python hybrid_ids.py train --synthetic

    # Run hybrid detection on a CSV of flows and write alerts
    python hybrid_ids.py predict --data flows.csv --out alerts.csv

Requires: pandas numpy scikit-learn joblib matplotlib (xgboost optional)
"""
import argparse
import glob
import json
import os
from dataclasses import dataclass, asdict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Columns that identify a flow rather than describe its behaviour. Dropped from the
# model's features so it cannot memorise IPs/ports/timestamps (shortcut learning).
IDENTIFIER_COLS = ["Flow ID", "Source IP", "Destination IP", "Source Port",
                   "Destination Port", "Timestamp", "Unnamed: 0", "Fwd Header Length.1"]


# ============================ Configuration ================================
@dataclass
class Config:
    benign_label: str = "BENIGN"
    # Rule thresholds (tune experimentally, don't present as optimal)
    scan_unique_ports: int = 20        # distinct dst ports from one src IP
    syn_flood_rate: float = 1000.0     # packets/s with SYN and no reply
    high_packet_rate: float = 5000.0   # packets/s
    # Hybrid weights: risk = w_ml * ml_score + w_rule * rule_score
    w_ml: float = 0.6
    w_rule: float = 0.4
    sev_high: float = 0.8
    sev_medium: float = 0.5
    sev_low: float = 0.3


# ============================== Data =======================================
def load_flows(path: str) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(path, "*.csv"))) if os.path.isdir(path) else [path]
    if not files:
        raise FileNotFoundError(f"No CSV files found at {path}")
    df = pd.concat((pd.read_csv(f, low_memory=False) for f in files), ignore_index=True)
    df.columns = df.columns.str.strip()
    return df


def clean(df: pd.DataFrame, label_col: str = None) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan)
    if label_col:
        df = df.dropna(subset=df.columns.difference([label_col]), how="any")
        df = df.drop_duplicates()
    return df.reset_index(drop=True)


def synthetic_flows(n=20000, seed=42) -> pd.DataFrame:
    """CICIDS-style columns so the whole pipeline can be tested offline."""
    rng = np.random.default_rng(seed)
    labels = rng.choice(["BENIGN", "DoS", "PortScan", "DDoS"], size=n, p=[0.7, 0.1, 0.12, 0.08])
    df = pd.DataFrame({
        "Flow Duration": rng.exponential(1e5, n),
        "Total Fwd Packets": rng.poisson(8, n) + 1,
        "Total Backward Packets": rng.poisson(6, n),
        "Fwd Packet Length Mean": rng.normal(60, 20, n).clip(0),
        "Bwd Packet Length Mean": rng.normal(80, 30, n).clip(0),
        "Flow Bytes/s": rng.exponential(2000, n),
        "Flow Packets/s": rng.exponential(200, n),
        "SYN Flag Count": rng.integers(0, 2, n),
        "ACK Flag Count": rng.integers(0, 2, n),
        "RST Flag Count": rng.integers(0, 2, n),
        "Source IP": [f"10.0.0.{i}" for i in rng.integers(1, 40, n)],
        "Destination Port": rng.integers(1, 1024, n),
        "Label": labels,
    })
    dos = labels == "DoS"
    df.loc[dos, "Flow Packets/s"] += 8000
    df.loc[dos, "SYN Flag Count"] = 1
    df.loc[dos, "Total Backward Packets"] = 0
    scan = labels == "PortScan"
    df.loc[scan, "Total Fwd Packets"] = 1
    df.loc[scan, "Total Backward Packets"] = 0
    df.loc[scan, "RST Flag Count"] = 1
    df.loc[scan, "Source IP"] = "10.0.0.99"
    ddos = labels == "DDoS"
    df.loc[ddos, "Flow Packets/s"] += 12000
    df.loc[ddos, "Flow Bytes/s"] += 50000
    return df


# ============================ Rule engine ==================================
def _col(df, name):
    return df[name].to_numpy(dtype=float) if name in df.columns else np.zeros(len(df))


def rule_engine(df: pd.DataFrame, cfg: Config):
    """Returns (rule_score in [0,1], name of strongest rule) for each flow."""
    n = len(df)
    rules = {}

    rate = _col(df, "Flow Packets/s")
    syn, bwd = _col(df, "SYN Flag Count"), _col(df, "Total Backward Packets")
    fwd, rst = _col(df, "Total Fwd Packets"), _col(df, "RST Flag Count")

    # Rule 1: port scan. Cross-flow if IP/port columns exist, else per-flow heuristic.
    if {"Source IP", "Destination Port"}.issubset(df.columns):
        ports = df.groupby("Source IP")["Destination Port"].transform("nunique").to_numpy()
        rules["PORT_SCAN"] = np.where(ports >= cfg.scan_unique_ports, 1.0, 0.0)
    else:
        rules["PORT_SCAN"] = np.where((fwd <= 2) & (bwd <= 1) & ((rst >= 1) | (bwd == 0)), 0.5, 0.0)

    # Rule 2: SYN flood (SYNs at high rate with no responses)
    rules["SYN_FLOOD"] = np.where((syn >= 1) & (bwd == 0) & (rate > cfg.syn_flood_rate), 1.0, 0.0)

    # Rule 3: abnormally high packet rate
    rules["HIGH_PACKET_RATE"] = np.where(rate > cfg.high_packet_rate, 0.6, 0.0)

    names = list(rules)
    stack = np.vstack([rules[k] for k in names])      # (rules, flows)
    score = stack.max(axis=0) if n else np.zeros(0)
    top = np.array(names)[stack.argmax(axis=0)] if n else np.array([])
    top = np.where(score > 0, top, "")
    return score, top


# ============================ Hybrid engine ================================
def severity_from(risk: np.ndarray, cfg: Config):
    return np.select([risk >= cfg.sev_high, risk >= cfg.sev_medium, risk >= cfg.sev_low],
                     ["HIGH", "MEDIUM", "LOW"], default="NONE")


def hybrid_detect(df_raw, X_scaled, model, le, cfg: Config) -> pd.DataFrame:
    proba = model.predict_proba(X_scaled)
    pred_idx = proba.argmax(axis=1)
    pred = le.inverse_transform(pred_idx)
    confidence = proba.max(axis=1)
    benign_idx = list(le.classes_).index(cfg.benign_label) if cfg.benign_label in le.classes_ else None
    ml_score = 1 - proba[:, benign_idx] if benign_idx is not None else confidence

    r_score, r_name = rule_engine(df_raw, cfg)
    risk = cfg.w_ml * ml_score + cfg.w_rule * r_score
    # A confident rule hit overrides a benign ML verdict instead of being ignored
    attack = np.where((pred == cfg.benign_label) & (r_score >= 0.5),
                      "SUSPICIOUS:" + pd.Series(r_name).astype(str).values, pred)

    out = pd.DataFrame({
        "prediction": attack,
        "ml_prediction": pred,
        "ml_confidence": confidence.round(4),
        "ml_score": ml_score.round(4),
        "rule_score": r_score.round(4),
        "rule_triggered": r_name,
        "risk_score": risk.round(4),
        "severity": severity_from(risk, cfg),
    })
    for c in ["Source IP", "Destination IP", "Source Port", "Destination Port", "Timestamp"]:
        if c in df_raw.columns:
            out.insert(0, c, df_raw[c].values)
    return out


# ============================== Metrics ====================================
def binary_metrics(y_true_attack, y_pred_attack) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true_attack, y_pred_attack, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true_attack, y_pred_attack),
        "precision": precision_score(y_true_attack, y_pred_attack, zero_division=0),
        "recall": recall_score(y_true_attack, y_pred_attack, zero_division=0),
        "f1": f1_score(y_true_attack, y_pred_attack, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
    }


def plot_confusion(cm, classes, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, ax = plt.subplots(figsize=(max(6, len(classes)), max(5, len(classes) * 0.8)))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


# =============================== Train =====================================
def build_model(kind, n_classes, seed):
    if kind == "xgb":
        try:
            from xgboost import XGBClassifier
        except ImportError:
            raise SystemExit("xgboost not installed: pip install xgboost")
        return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1,
                             subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
                             objective="multi:softprob" if n_classes > 2 else "binary:logistic",
                             random_state=seed)
    return RandomForestClassifier(n_estimators=200, n_jobs=-1, class_weight="balanced_subsample",
                                  random_state=seed)


def train(args):
    cfg = Config()
    raw = synthetic_flows(seed=args.seed) if args.synthetic else load_flows(args.data)
    raw = clean(raw, args.label_col)
    raw[args.label_col] = raw[args.label_col].astype(str).str.strip()
    print(f"Flows after cleaning: {len(raw)}")
    print(raw[args.label_col].value_counts().to_string(), "\n")

    feature_cols = [c for c in raw.select_dtypes(include=[np.number]).columns
                    if c not in IDENTIFIER_COLS and c != args.label_col]
    le = LabelEncoder()
    y = le.fit_transform(raw[args.label_col])
    benign_idx = list(le.classes_).index(cfg.benign_label)

    # Split FIRST, then fit the scaler on the training portion only (no leakage)
    idx = np.arange(len(raw))
    can_stratify = np.bincount(y).min() >= 2
    tr_idx, te_idx = train_test_split(idx, test_size=args.test_size, random_state=args.seed,
                                      stratify=y if can_stratify else None)
    scaler = StandardScaler().fit(raw.loc[tr_idx, feature_cols])
    X_tr = scaler.transform(raw.loc[tr_idx, feature_cols])
    X_te = scaler.transform(raw.loc[te_idx, feature_cols])
    y_tr, y_te = y[tr_idx], y[te_idx]

    model = build_model(args.model, len(le.classes_), args.seed)
    print(f"Training {args.model.upper()} on {len(tr_idx)} flows, {len(feature_cols)} features...")
    model.fit(X_tr, y_tr)

    # --- Multi-class evaluation of the ML model
    y_pred = model.predict(X_te)
    print("\n=== ML multi-class report (test set) ===")
    print(classification_report(y_te, y_pred, target_names=le.classes_, digits=4, zero_division=0))
    cm = confusion_matrix(y_te, y_pred, labels=range(len(le.classes_)))
    os.makedirs(args.out_dir, exist_ok=True)
    plot_confusion(cm, list(le.classes_), os.path.join(args.out_dir, "confusion_matrix.png"))

    # --- ML only vs Rules only vs Hybrid (binary: benign vs attack)
    test_raw = raw.loc[te_idx].reset_index(drop=True)
    det = hybrid_detect(test_raw, X_te, model, le, cfg)
    y_true_bin = (y_te != benign_idx).astype(int)
    comparison = {
        "ml_only": binary_metrics(y_true_bin, (y_pred != benign_idx).astype(int)),
        "rules_only": binary_metrics(y_true_bin, (det["rule_score"].values >= cfg.sev_medium).astype(int)),
        "hybrid": binary_metrics(y_true_bin, (det["risk_score"].values >= cfg.sev_medium).astype(int)),
    }
    print("=== Binary comparison (benign vs attack) ===")
    print(pd.DataFrame(comparison).T.round(4).to_string(), "\n")

    # --- Feature importance (for the explainability section)
    top_features = []
    if hasattr(model, "feature_importances_"):
        imp = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
        top_features = imp.head(10).round(4).to_dict()
        print("Top features:\n", imp.head(10).round(4).to_string(), "\n")

    # --- Save everything inference needs
    joblib.dump(model, os.path.join(args.out_dir, "network_classifier.pkl"))
    joblib.dump(scaler, os.path.join(args.out_dir, "scaler.pkl"))
    joblib.dump(feature_cols, os.path.join(args.out_dir, "feature_columns.pkl"))
    joblib.dump(le, os.path.join(args.out_dir, "label_encoder.pkl"))
    meta = {
        "model": {"rf": "RandomForest", "xgb": "XGBoost"}[args.model],
        "version": "1.0",
        "dataset": "synthetic" if args.synthetic else args.data,
        "classes": list(le.classes_),
        "n_features": len(feature_cols),
        "train_flows": int(len(tr_idx)),
        "test_flows": int(len(te_idx)),
        "config": asdict(cfg),
        "test_metrics_binary": comparison,
        "top_features": top_features,
    }
    with open(os.path.join(args.out_dir, "model_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2, default=float)
    print(f"Artifacts saved to {args.out_dir}/")


# ============================== Predict ====================================
def predict(args):
    d = args.model_dir
    model = joblib.load(os.path.join(d, "network_classifier.pkl"))
    scaler = joblib.load(os.path.join(d, "scaler.pkl"))
    feature_cols = joblib.load(os.path.join(d, "feature_columns.pkl"))
    le = joblib.load(os.path.join(d, "label_encoder.pkl"))
    with open(os.path.join(d, "model_metadata.json")) as f:
        cfg = Config(**json.load(f)["config"])

    raw = clean(load_flows(args.data))
    missing = [c for c in feature_cols if c not in raw.columns]
    if missing:
        raise SystemExit(f"Input is missing {len(missing)} expected features, e.g. {missing[:5]}. "
                         "Live/PCAP extraction must follow the training feature schema exactly.")
    X = scaler.transform(raw[feature_cols].fillna(0))   # same columns, same order as training
    alerts = hybrid_detect(raw, X, model, le, cfg)
    alerts.to_csv(args.out, index=False)
    print(alerts["severity"].value_counts().to_string())
    print(alerts["prediction"].value_counts().to_string())
    print(f"\nAlerts written to {args.out}")


# =============================== CLI =======================================
def main():
    p = argparse.ArgumentParser(description="Hybrid IDS (ML + rules)")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="train, evaluate and save the model")
    t.add_argument("--data", help="CSV file or directory of CSVs (CIC-IDS2017)")
    t.add_argument("--synthetic", action="store_true", help="use generated demo data")
    t.add_argument("--label-col", default="Label")
    t.add_argument("--model", choices=["rf", "xgb"], default="rf")
    t.add_argument("--test-size", type=float, default=0.3)
    t.add_argument("--out-dir", default="models")
    t.add_argument("--seed", type=int, default=42)
    t.set_defaults(func=train)

    r = sub.add_parser("predict", help="run hybrid detection on a CSV of flows")
    r.add_argument("--data", required=True)
    r.add_argument("--model-dir", default="models")
    r.add_argument("--out", default="alerts.csv")
    r.set_defaults(func=predict)

    args = p.parse_args()
    if args.cmd == "train" and not (args.data or args.synthetic):
        p.error("train needs --data or --synthetic")
    args.func(args)


if __name__ == "__main__":
    main()
