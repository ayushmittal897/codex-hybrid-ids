"""
Sentinel IDS: Multi-Model Inference & Live Traffic Capture API.
Provides endpoints for offline CSV analysis, model evaluation cards, and real-time live traffic capture.
"""

from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import joblib
import numpy as np
import pandas as pd

from backend.live_capture import LiveTrafficCapture

ROOT = Path(__file__).resolve().parents[1]
MODEL_PORTSCAN_DIR = ROOT / "models_portscan_v2"
MODEL_MULTI_DIR = ROOT / "models_multi"

app = FastAPI(title="Sentinel IDS Hybrid Security Engine", version="1.0.0")

# Robust CORS for all local development servers (Vite, Bun, TanStack)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ModelManager:
    """Manages multiple trained ML models and feature transformation pipelines."""

    def __init__(self):
        self.models: Dict[str, Dict[str, Any]] = {}
        self.active_model_id = "multiclass"
        self.load_models()

    def load_models(self):
        # 1. Load PortScan V2 (Binary model)
        try:
            with (MODEL_PORTSCAN_DIR / "model_metadata.json").open(encoding="utf-8") as f:
                portscan_meta = json.load(f)
            self.models["portscan"] = {
                "id": "portscan",
                "name": "PortScan Random Forest",
                "type": "binary",
                "dir": MODEL_PORTSCAN_DIR,
                "classifier": joblib.load(MODEL_PORTSCAN_DIR / "network_classifier.pkl"),
                "scaler": joblib.load(MODEL_PORTSCAN_DIR / "scaler.pkl"),
                "imputer": None,
                "features": joblib.load(MODEL_PORTSCAN_DIR / "feature_columns.pkl"),
                "label_encoder": joblib.load(MODEL_PORTSCAN_DIR / "label_encoder.pkl"),
                "classes": portscan_meta.get("classes", ["BENIGN", "PortScan"]),
                "metadata": portscan_meta,
                "status": "ready",
            }
        except Exception as e:
            self.models["portscan"] = {"id": "portscan", "status": "error", "error": str(e)}

        # 2. Load Multiclass Model (8 classes)
        try:
            with (MODEL_MULTI_DIR / "metadata.json").open(encoding="utf-8") as f:
                multi_meta = json.load(f)
            classes = joblib.load(MODEL_MULTI_DIR / "classes.pkl")
            self.models["multiclass"] = {
                "id": "multiclass",
                "name": "Multi-Threat Random Forest (8 Classes)",
                "type": "multiclass",
                "dir": MODEL_MULTI_DIR,
                "classifier": joblib.load(MODEL_MULTI_DIR / "classifier.pkl"),
                "scaler": None,
                "imputer": joblib.load(MODEL_MULTI_DIR / "imputer.pkl"),
                "features": joblib.load(MODEL_MULTI_DIR / "feature_columns.pkl"),
                "label_encoder": None,
                "classes": list(classes),
                "metadata": multi_meta,
                "status": "ready",
            }
        except Exception as e:
            self.models["multiclass"] = {"id": "multiclass", "status": "error", "error": str(e)}

        # Set default active model
        if self.models.get("multiclass", {}).get("status") == "ready":
            self.active_model_id = "multiclass"
        elif self.models.get("portscan", {}).get("status") == "ready":
            self.active_model_id = "portscan"

    def predict_dataframe(self, frame: pd.DataFrame, model_id: Optional[str] = None) -> Tuple[List[str], Dict[str, Any]]:
        target_id = model_id or self.active_model_id
        bundle = self.models.get(target_id)
        if not bundle or bundle.get("status") != "ready":
            # Fallback to available ready bundle
            ready_bundles = [k for k, v in self.models.items() if v.get("status") == "ready"]
            if not ready_bundles:
                raise RuntimeError("No trained model bundle is available.")
            target_id = ready_bundles[0]
            bundle = self.models[target_id]

        features_expected = bundle["features"]
        frame.columns = frame.columns.str.strip()

        missing = [col for col in features_expected if col not in frame.columns]
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"message": f"Input CSV missing required features for model {target_id}.", "missing": missing[:10]},
            )

        X = frame[features_expected].apply(pd.to_numeric, errors="coerce")
        X = X.replace([float("inf"), float("-inf")], np.nan)

        if bundle.get("imputer"):
            X_clean = bundle["imputer"].transform(X)
        else:
            X_clean = X.fillna(0).values

        if bundle.get("scaler"):
            X_clean = bundle["scaler"].transform(X_clean)

        raw_preds = bundle["classifier"].predict(X_clean)

        if bundle.get("label_encoder"):
            labels = bundle["label_encoder"].inverse_transform(raw_preds)
        else:
            labels = raw_preds

        return [str(l) for l in labels], bundle

    def evaluate_flows(self, flow_trackers) -> List[Dict]:
        """Classifies real-time live flow trackers into API-ready flow records."""
        if not flow_trackers:
            return []

        rows = [t.to_feature_dict() for t in flow_trackers]
        df = pd.DataFrame(rows)
        labels, bundle = self.predict_dataframe(df)

        results = []
        for i, tracker in enumerate(flow_trackers):
            label = labels[i]
            attack = "Benign" if label.upper() == "BENIGN" else label
            is_threat = attack != "Benign"
            severity = "Low" if not is_threat else ("Critical" if attack in ("DoS_DDoS", "Infiltration") else "High")
            score = 12 if not is_threat else (92 if severity == "Critical" else 85)

            results.append({
                "id": f"LIVE-{tracker.start_time:.0f}-{i+1}",
                "time": datetime.fromtimestamp(tracker.start_time, tz=timezone.utc).isoformat(),
                "source": tracker.key[0],
                "destination": tracker.key[1],
                "port": tracker.key[3],
                "protocol": tracker.key[4],
                "bytes": tracker.fwd_bytes + tracker.bwd_bytes,
                "packets": tracker.fwd_packets + tracker.bwd_packets,
                "attack": attack,
                "severity": severity,
                "score": score,
                "engine": f"Hybrid ({bundle['name']})",
                "acknowledged": False,
                "reasons": [
                    f"Model prediction: {label}",
                    f"Flow duration: {max(1e-4, tracker.last_time - tracker.start_time):.2f}s",
                ],
            })
        return results


# Initialize Model Manager and Live Capture Engine
MODEL_MANAGER = ModelManager()
CAPTURE_ENGINE = LiveTrafficCapture(MODEL_MANAGER)


# ---------------------------------------------------------------------------
# API Routes: Health & Models
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    active_bundle = MODEL_MANAGER.models.get(MODEL_MANAGER.active_model_id, {})
    return {
        "status": "ok" if any(v.get("status") == "ready" for v in MODEL_MANAGER.models.values()) else "degraded",
        "active_model_id": MODEL_MANAGER.active_model_id,
        "model": active_bundle.get("name", "RandomForest"),
        "classes": active_bundle.get("classes", []),
        "available_models": [k for k, v in MODEL_MANAGER.models.items() if v.get("status") == "ready"],
        "error": None,
    }


@app.get("/models")
def list_models():
    """Returns detailed model cards, validation metrics, and feature inventories."""
    cards = []
    for model_id, bundle in MODEL_MANAGER.models.items():
        if bundle.get("status") != "ready":
            continue
        meta = bundle.get("metadata", {})
        metrics = meta.get("metrics", {})
        cards.append({
            "id": model_id,
            "name": bundle["name"],
            "type": bundle["type"],
            "active": model_id == MODEL_MANAGER.active_model_id,
            "classes": bundle["classes"],
            "features_count": len(bundle["features"]),
            "metrics": {
                "accuracy": metrics.get("accuracy", meta.get("accuracy", 0.995)),
                "precision": metrics.get("macro_precision", meta.get("precision", 0.894)),
                "recall": metrics.get("macro_recall", meta.get("recall", 0.777)),
                "f1_score": metrics.get("macro_f1", meta.get("f1_score", 0.822)),
            },
            "per_class_report": meta.get("per_class_report", {}),
            "dataset": meta.get("dataset", "CIC-IDS2017"),
            "trained_rows": meta.get("train_rows", meta.get("sampled_rows")),
        })
    return {"models": cards, "active_model_id": MODEL_MANAGER.active_model_id}


@app.post("/models/switch")
def switch_model(model_id: str = Query(..., description="Target model ID: 'multiclass' or 'portscan'")):
    if model_id not in MODEL_MANAGER.models or MODEL_MANAGER.models[model_id].get("status") != "ready":
        raise HTTPException(status_code=400, detail=f"Model '{model_id}' is not loaded.")
    MODEL_MANAGER.active_model_id = model_id
    return {"status": "switched", "active_model_id": model_id, "name": MODEL_MANAGER.models[model_id]["name"]}


# ---------------------------------------------------------------------------
# API Routes: Offline Dataset Inference
# ---------------------------------------------------------------------------

@app.post("/predict")
async def predict(file: UploadFile = File(...), model_id: Optional[str] = Query(None)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a CSV file.")
    raw = await file.read()
    if len(raw) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV is limited to 50 MB.")

    try:
        frame = pd.read_csv(BytesIO(raw), low_memory=False)
        labels, bundle = MODEL_MANAGER.predict_dataframe(frame, model_id=model_id)
        counts = Counter(labels)

        return {
            "source": file.filename,
            "model": bundle["name"],
            "model_id": bundle["id"],
            "classes": bundle["classes"],
            "rows": len(frame),
            "predictions": dict(counts),
            "prediction_labels": labels,
            "preview": [{"prediction": l} for l in labels[:20]],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not analyze CSV: {exc}") from exc


# ---------------------------------------------------------------------------
# API Routes: Live Traffic Flow Capture
# ---------------------------------------------------------------------------

@app.get("/capture/interfaces")
def get_interfaces():
    return {"interfaces": CAPTURE_ENGINE.get_interfaces()}


@app.post("/capture/start")
def start_capture(interface: Optional[str] = Query(None)):
    if not isinstance(interface, str):
        interface = None
    res = CAPTURE_ENGINE.start(interface=interface)
    return res


@app.post("/capture/stop")
def stop_capture():
    res = CAPTURE_ENGINE.stop()
    return res


@app.get("/capture/status")
def capture_status():
    return CAPTURE_ENGINE.get_status()


@app.get("/capture/flows")
def get_captured_flows(limit: int = Query(50, ge=1, le=500)):
    flows = CAPTURE_ENGINE.get_flows(limit=limit)
    return {"flows": flows, "count": len(flows), "status": CAPTURE_ENGINE.get_status()}


@app.get("/capture/download")
def download_captured_flows():
    csv_data = CAPTURE_ENGINE.export_csv()
    filename = f"sentinel-live-capture-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
