"""
Attacker Simulator
Loads real attack CSVs from Edge-IIoTset, preprocesses them identically
to the training notebook, and streams rows to the Edge IoT Gateway.
Each attack type is mapped to its STRIDE category.
"""

import os
import csv
import time
import requests
import numpy as np
from datetime import datetime

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://edge-gateway:5000/predict")
SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", "0.5"))
LOG_PATH = f"/app/results/{os.environ.get('MODEL_NAME', 'model')}_attacker_log.csv"

# Attack CSV files and their STRIDE category
ATTACK_TYPES = {
    "Backdoor":      ("Backdoor.npy",      "Elevation of Privilege"),
    "DDoS_HTTP":     ("DDoS_HTTP.npy",     "Denial of Service"),
    "MITM":          ("MITM.npy",          "Tampering"),
    "Port_Scanning": ("Port_Scanning.npy", "Information Disclosure"),
    "SQL_injection": ("SQL_injection.npy", "Tampering"),
    "XSS":           ("XSS.npy",           "Tampering"),
}


def load_all_attacks(data_dir):
    attacks = []
    processed_dir = os.path.join(data_dir, "processed")

    for attack_type, (filename, stride) in ATTACK_TYPES.items():
        path = os.path.join(processed_dir, filename)
        if not os.path.exists(path):
            print(f"[Attacker] WARNING: {filename} not found, skipping")
            continue
        X = np.load(path)
        attacks.append((attack_type, stride, X))
        print(f"[Attacker] Loaded {attack_type:16} — {len(X)} rows")

    return attacks


def init_log():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "attack_type", "stride_category",
                "status", "predicted_label", "detected", "latency_ms"
            ])


def log_result(attack_type, stride, status, predicted_label, detected, latency_ms):
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(), attack_type, stride,
            status, predicted_label, "yes" if detected else "no",
            f"{latency_ms:.2f}"
        ])


def wait_for_gateway(url, timeout=60):
    health_url = url.rsplit("/", 1)[0] + "/health"
    print(f"[Attacker] Waiting for gateway...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(health_url, timeout=2)
            if r.status_code == 200:
                print("[Attacker] Gateway ready!")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(2)
    print("[Attacker] WARNING: Gateway not responding, starting anyway...")
    return False


def main():
    init_log()
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    attacks = load_all_attacks(data_dir)

    if not attacks:
        print("[Attacker] No attack files found, exiting.")
        return

    wait_for_gateway(GATEWAY_URL)

    print(f"[Attacker] Loaded {len(attacks)} attack types, sending every {SEND_INTERVAL}s")

    # Interleave rows from all attack types
    indices = [0] * len(attacks)
    sent = 0
    detected = 0
    per_type = {}
    attack_ptr = 0

    while True:
        attack_type, stride, X = attacks[attack_ptr % len(attacks)]
        row_idx = indices[attack_ptr % len(attacks)]
        features = X[row_idx % len(X)].tolist()
        indices[attack_ptr % len(attacks)] += 1
        attack_ptr += 1

        try:
            r = requests.post(GATEWAY_URL, json={"features": features, "source": "attacker"}, timeout=5)
            result = r.json()
            sent += 1

            is_detected = result.get("is_attack", False)
            predicted_label = result.get("label", "?")
            latency = result.get("latency_ms", 0)

            if is_detected:
                detected += 1
            if attack_type not in per_type:
                per_type[attack_type] = {"sent": 0, "detected": 0}
            per_type[attack_type]["sent"] += 1
            if is_detected:
                per_type[attack_type]["detected"] += 1

            det_rate = (detected / sent) * 100
            print(
                f"[Attacker] #{sent} [{attack_type:16}|{stride:25}] "
                f"-> {predicted_label:22} | det={det_rate:.1f}% | {latency:.1f}ms"
            )
            log_result(attack_type, stride, "ok", predicted_label, is_detected, latency)

        except requests.RequestException as e:
            print(f"[Attacker] Error: {e}")
            log_result(attack_type, stride, "error", "?", False, 0)

        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    main()
