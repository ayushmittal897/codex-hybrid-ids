"""
CLI utility to capture and download live network traffic flows from Sentinel IDS.
Usage:
    python tools/download_live_traffic.py --duration 10 --out live_flows.csv
"""

import argparse
import sys
import time
import urllib.request
import json

BASE_URL = "http://127.0.0.1:8000"


def main():
    parser = argparse.ArgumentParser(description="Sentinel IDS Live Traffic Flow Downloader")
    parser.add_argument("--duration", type=int, default=5, help="Duration to run live capture (seconds)")
    parser.add_argument("--interface", type=str, default=None, help="Network interface to sniff on")
    parser.add_argument("--out", type=str, default="downloaded_live_flows.csv", help="Output CSV path")
    args = parser.parse_args()

    print(f"[*] Connecting to Sentinel IDS API at {BASE_URL}...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"[+] Connected! Active model: {data.get('model')} (status={data.get('status')})")
    except Exception as e:
        print(f"[!] Could not connect to {BASE_URL}: {e}")
        print("    Please ensure the backend is running:")
        print("    .\\.venv\\Scripts\\python -m uvicorn backend.server:app --port 8000")
        sys.exit(1)

    print(f"[*] Starting live traffic capture (Duration: {args.duration}s)...")
    start_url = f"{BASE_URL}/capture/start"
    if args.interface:
        start_url += f"?interface={urllib.parse.quote(args.interface)}"
    
    req = urllib.request.Request(start_url, data=b"", method="POST")
    with urllib.request.urlopen(req) as resp:
        print(f"    Capture status: {json.loads(resp.read().decode())}")

    for sec in range(args.duration):
        time.sleep(1)
        req = urllib.request.Request(f"{BASE_URL}/capture/status")
        with urllib.request.urlopen(req) as resp:
            st = json.loads(resp.read().decode())
            print(f"    [{sec+1}/{args.duration}s] Packets: {st['packets_captured']} | Flows: {st['flows_evaluated']} | Threats: {st['threats_detected']}")

    print("[*] Stopping live traffic capture...")
    req = urllib.request.Request(f"{BASE_URL}/capture/stop", data=b"", method="POST")
    with urllib.request.urlopen(req) as resp:
        print(f"    Final summary: {json.loads(resp.read().decode())}")

    print(f"[*] Downloading captured flows CSV to {args.out}...")
    req = urllib.request.Request(f"{BASE_URL}/capture/download")
    with urllib.request.urlopen(req) as resp, open(args.out, "wb") as f:
        content = resp.read()
        f.write(content)
        print(f"[+] Download complete! Saved {len(content)} bytes to {args.out}")


if __name__ == "__main__":
    main()
