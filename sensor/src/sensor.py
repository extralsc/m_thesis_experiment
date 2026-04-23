"""
IoT Water Level Sensor Simulator
Loads pre-processed sensor.npy (from setup_environment.py) and streams
rows to the Edge IoT Gateway to simulate a water level IoT sensor.
"""

import os
import csv
import time
import requests
import numpy as np
from datetime import datetime

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://edge-gateway:5000/predict")
SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", "1.0"))
DATA_PATH = os.environ.get("DATA_PATH", "/app/data/processed/sensor.npy")
LOG_PATH = f"/app/results/{os.environ.get('MODEL_NAME', 'model')}_sensor_log.csv"


def load_data(path):
    print(f"[Sensor] Loading {path}...")
    X = np.load(path)
    print(f"[Sensor] Ready — {len(X)} rows, {X.shape[1]} features")
    return X


def init_log():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "status", "label", "is_attack", "latency_ms"])


def log_result(status, label, is_attack, latency_ms):
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(), status, label,
            "yes" if is_attack else "no", f"{latency_ms:.2f}"
        ])


def wait_for_gateway(url, timeout=60):
    health_url = url.rsplit("/", 1)[0] + "/health"
    print(f"[Sensor] Waiting for gateway...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(health_url, timeout=2)
            if r.status_code == 200:
                print("[Sensor] Gateway ready!")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(2)
    print("[Sensor] WARNING: Gateway not responding, starting anyway...")
    return False


def main():
    init_log()
    X = load_data(DATA_PATH)
    wait_for_gateway(GATEWAY_URL)

    idx = 0
    sent = 0
    false_positives = 0

    print(f"[Sensor] Streaming water level sensor traffic every {SEND_INTERVAL}s")

    while True:
        features = X[idx % len(X)].tolist()
        idx += 1

        try:
            r = requests.post(GATEWAY_URL, json={"features": features, "source": "water-sensor"}, timeout=5)
            result = r.json()
            sent += 1

            label = result.get("label", "?")
            is_attack = result.get("is_attack", False)
            latency = result.get("latency_ms", 0)

            if is_attack:
                false_positives += 1

            fpr = (false_positives / sent) * 100
            print(
                f"[WaterSensor] #{sent} -> {label:22} "
                f"({'FALSE POSITIVE' if is_attack else 'correct':14}) "
                f"| FPR={fpr:.1f}% | {latency:.1f}ms"
            )
            log_result("ok", label, is_attack, latency)

        except requests.RequestException as e:
            print(f"[Sensor] Error: {e}")
            log_result("error", "?", False, 0)

        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    main()
