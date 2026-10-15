import asyncio
import time
from fastapi import UploadFile
from backend.server import (
    app,
    health,
    list_models,
    switch_model,
    predict,
    start_capture,
    stop_capture,
    capture_status,
    get_captured_flows,
    download_captured_flows,
)

def test_health():
    h = health()
    assert h["status"] == "ok"
    assert "multiclass" in h["available_models"]

def test_models():
    m = list_models()
    assert len(m["models"]) >= 2
    active_models = [c for c in m["models"] if c["active"]]
    assert len(active_models) == 1

def test_live_capture():
    start = start_capture(None)
    assert start["status"] in ("started", "already_running")
    time.sleep(1.5)
    st = capture_status()
    assert st["running"] is True
    flows = get_captured_flows(10)
    assert "flows" in flows
    csv_bytes = download_captured_flows().body
    assert len(csv_bytes) > 0
    stop = stop_capture()
    assert stop["status"] == "stopped"

if __name__ == "__main__":
    test_health()
    test_models()
    test_live_capture()
    print("All backend tests passed!")
