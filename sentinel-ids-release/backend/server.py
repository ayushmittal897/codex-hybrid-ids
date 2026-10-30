"""Local, read-only ML inference API for the approved legacy PortScan bundle."""
from collections import Counter
from io import BytesIO
from pathlib import Path
import json

import joblib
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from backend.live_capture import capture, interfaces


class CaptureRequest(BaseModel):
    interface_index: int

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models_portscan_v2"

app = FastAPI(title="Sentinel IDS Inference API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8081",
        "http://127.0.0.1:8081",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def load_bundle():
    required = [
        "network_classifier.pkl",
        "scaler.pkl",
        "feature_columns.pkl",
        "label_encoder.pkl",
        "model_metadata.json",
    ]
    missing = [name for name in required if not (MODEL_DIR / name).exists()]
    if missing:
        raise RuntimeError(f"Model bundle is incomplete: {', '.join(missing)}")
    with (MODEL_DIR / "model_metadata.json").open(encoding="utf-8") as stream:
        metadata = json.load(stream)
    return (
        joblib.load(MODEL_DIR / "network_classifier.pkl"),
        joblib.load(MODEL_DIR / "scaler.pkl"),
        joblib.load(MODEL_DIR / "feature_columns.pkl"),
        joblib.load(MODEL_DIR / "label_encoder.pkl"),
        metadata,
    )


try:
    MODEL, SCALER, FEATURE_COLUMNS, LABEL_ENCODER, METADATA = load_bundle()
    LOAD_ERROR = None
except Exception as exc:  # Exposed through health; do not hide startup problems.
    MODEL = SCALER = FEATURE_COLUMNS = LABEL_ENCODER = METADATA = None
    LOAD_ERROR = str(exc)


@app.get("/health")
def health():
    return {
        "status": "ok" if LOAD_ERROR is None else "degraded",
        "model_dir": str(MODEL_DIR),
        "model": METADATA.get("model") if METADATA else None,
        "classes": METADATA.get("classes") if METADATA else None,
        "error": LOAD_ERROR,
    }


@app.get("/capture/interfaces")
def capture_interfaces():
    return interfaces()


@app.get("/capture/status")
def capture_status():
    return capture.snapshot()


@app.post("/capture/start")
def capture_start(request: CaptureRequest):
    try:
        capture.start(request.interface_index)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail="Unknown capture interface") from exc
    return capture.snapshot()


@app.post("/capture/stop")
def capture_stop():
    capture.stop_event.set()
    return capture.snapshot()


@app.post("/predict")
async def predict(file: UploadFile = File(...)):
    if LOAD_ERROR:
        raise HTTPException(status_code=503, detail=LOAD_ERROR)
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a CSV file.")
    raw = await file.read()
    if len(raw) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV is limited to 50 MB.")
    try:
        frame = pd.read_csv(BytesIO(raw), low_memory=False)
        frame.columns = frame.columns.str.strip()
        missing = [column for column in FEATURE_COLUMNS if column not in frame.columns]
        if missing:
            raise HTTPException(
                status_code=422,
                detail={"message": "Input is missing model features.", "missing": missing[:10]},
            )
        features = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
        features = features.replace([float("inf"), float("-inf")], pd.NA).fillna(0)
        transformed = SCALER.transform(features)
        predictions = MODEL.predict(transformed)
        labels = LABEL_ENCODER.inverse_transform(predictions)
        confidences = MODEL.predict_proba(transformed).max(axis=1)
        counts = Counter(str(label) for label in labels)
        return {
            "source": file.filename,
            "model": METADATA.get("model"),
            "classes": METADATA.get("classes"),
            "rows": len(frame),
            "predictions": dict(counts),
            "prediction_labels": [str(label) for label in labels],
            "prediction_confidences": [round(float(value), 6) for value in confidences],
            "preview": [{"prediction": str(label)} for label in labels[:20]],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not analyze CSV: {exc}") from exc
