"""
One-time environment setup script.
Run this ONCE before docker-compose up.

What it does:
  1. Loads and preprocesses Water_Level.csv  → data/processed/sensor.npy
  2. Loads and preprocesses each attack CSV  → data/processed/<attack>.npy
  3. Verifies models and scaler are present

Usage:
  pip install pandas scikit-learn joblib numpy
  python setup_environment.py
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

DATA_DIR    = "data"
MODELS_DIR  = "models"
OUT_DIR     = "data/processed"

DROP_COLS = [
    'frame.time', 'ip.src_host', 'ip.dst_host', 'arp.src.proto_ipv4',
    'arp.dst.proto_ipv4', 'http.file_data', 'http.request.full_uri',
    'icmp.transmit_timestamp', 'http.request.uri.query', 'tcp.options',
    'tcp.payload', 'tcp.srcport', 'tcp.dstport', 'udp.port', 'mqtt.msg'
]

ATTACK_FILES = [
    "Backdoor_attack.csv",
    "DDoS_HTTP_Flood_attack.csv",
    "MITM_attack.csv",
    "Port_Scanning_attack.csv",
    "SQL_injection_attack.csv",
    "XSS_attack.csv",
]


def preprocess(csv_path, scaler):
    df = pd.read_csv(csv_path, low_memory=False)
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])
    df = df.dropna().drop_duplicates()
    for c in df.select_dtypes(include='object').columns:
        if c != 'Attack_type':
            df[c] = LabelEncoder().fit_transform(df[c].astype(str))
    X_raw = df.drop(columns=['Attack_type', 'Attack_label'], errors='ignore').values
    return scaler.transform(X_raw)


def check_models():
    required = [
        "models/scaler.pkl",
        "models/Random_Forest.pkl",
        "models/Decision_Tree.pkl",
        "models/Logistic_Regression.pkl",
        "models/Naive_Bayes.pkl",
        "models/ANN.keras",
        "models/CNN.keras",
    ]
    missing = [f for f in required if not os.path.exists(f)]
    if missing:
        print("ERROR — missing files:")
        for f in missing:
            print(f"  {f}")
        exit(1)
    print("[OK] All model files present")


def main():
    print("=== IoT IDS Environment Setup ===\n")

    # 1. Check models
    check_models()

    # 2. Load scaler
    scaler = joblib.load("models/scaler.pkl")
    print("[OK] Scaler loaded\n")

    os.makedirs(OUT_DIR, exist_ok=True)

    # 3. Preprocess sensor data (Water Level)
    sensor_out = os.path.join(OUT_DIR, "sensor.npy")
    if os.path.exists(sensor_out):
        print(f"[SKIP] {sensor_out} already exists")
    else:
        path = os.path.join(DATA_DIR, "Water_Level.csv")
        print(f"Processing sensor data: {path}  (this may take a minute)...")
        X = preprocess(path, scaler)
        np.save(sensor_out, X)
        print(f"[OK] Saved {len(X)} sensor rows -> {sensor_out}")

    print()

    # 4. Preprocess each attack file
    for filename in ATTACK_FILES:
        name = filename.replace("_attack.csv", "").replace("_Flood", "")
        out_path = os.path.join(OUT_DIR, f"{name}.npy")

        if os.path.exists(out_path):
            print(f"[SKIP] {out_path} already exists")
            continue

        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            print(f"[SKIP] {filename} not found in data/")
            continue

        print(f"Processing {filename}...")
        X = preprocess(path, scaler)
        np.save(out_path, X)
        print(f"[OK] Saved {len(X)} rows -> {out_path}")

    print("\n=== Setup complete. Ready to run: ===")
    print("  MODEL_NAME=Random_Forest docker-compose up --build")
    print("  bash run_experiments.sh")
    print()
    print("Processed files:")
    for f in sorted(os.listdir(OUT_DIR)):
        path = os.path.join(OUT_DIR, f)
        mb = os.path.getsize(path) / (1024 * 1024)
        arr = np.load(path)
        print(f"  {f:30s}  {arr.shape[0]:>7} rows  {mb:.1f} MB")


if __name__ == "__main__":
    main()
