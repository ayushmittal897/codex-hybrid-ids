# Sentinel IDS — Current Implementation Stage

Sentinel IDS is a local hybrid intrusion-detection prototype. It accepts CSV network-flow features, applies transparent threshold rules, and can send the same CSV to a bundled Random Forest PortScan model. The interface presents only data loaded during the current browser session; it does not create simulated alerts or traffic.

## What is included

- `frontend/` — React dashboard for offline CSV analysis and model inference.
- `backend/` — FastAPI service for inference and optional local packet-capture metadata.
- `models_portscan_v2/` — the approved Random Forest model bundle, trained for `BENIGN` and `PortScan` classes.
- `requirements.txt` — Python runtime dependencies.
- `run-local.ps1` — starts the local API and dashboard after dependencies are installed.

## Scope and safety

This is an **offline flow-analysis prototype**. The model is validated only on the supplied CICIDS PortScan split and should not be treated as a production security control. Predictions and rules are indicators for an analyst to investigate. Packet capture is local to the computer and requires Npcap on Windows; it captures metadata only and does not block traffic.

## Quick start on Windows

Open PowerShell in this folder and run these two commands:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; cd frontend; npm install; cd ..
```

```powershell
.\run-local.ps1
```

Open the dashboard address printed by Vite (normally `http://localhost:8080`) and use **Dataset analysis** to upload a CSV. To use the model, keep the API terminal open and select **Run connected ML model**.

## Manual start

Use two PowerShell windows from this folder:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.server:app --host 127.0.0.1 --port 8000
```

```powershell
cd frontend
npm run dev
```

Check the API at `http://127.0.0.1:8000/health` and API documentation at `http://127.0.0.1:8000/docs`.

## CSV requirements

The rule-analysis page accepts either standard CICIDS names such as `Flow Packets/s`, `SYN Flag Count`, `Source IP`, and `Destination IP`, or the simplified fields `packet_rate` and `syn_count`. The Random Forest endpoint requires all 76 feature columns listed in `models_portscan_v2/feature_columns.pkl`; a CICIDS flow CSV is compatible.

## Verification

Run these checks after dependencies are installed:

```powershell
cd frontend
npm run lint
npm run test
npx tsc --noEmit
npm run build
```

```powershell
cd ..
.\.venv\Scripts\python.exe -m compileall -q backend
```

## Repository policy

Training datasets, captures, alerts, virtual environments, Node modules, and generated build output are intentionally ignored. The small approved model bundle is included so the demonstration runs without downloading a dataset.
