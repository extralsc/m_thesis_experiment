"""
Edge IoT Gateway - Intrusion Detection System
Simulates a Raspberry Pi-class edge device running ML-based IDS.
Receives sensor/network data via HTTP, classifies as normal/attack,
and logs performance metrics (latency, CPU, memory).

Supports both scikit-learn (.pkl) and Keras (.keras) models.
Trained on Edge-IIoTset dataset: 46 features, 15 attack classes.
"""

import os
import csv
import time
import psutil
import numpy as np
from datetime import datetime
from flask import Flask, request

app = Flask(__name__)

# --- Configuration ---
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/Random_Forest.pkl")
LOG_PATH = os.environ.get("LOG_PATH", "/app/results/edge_metrics.csv")

# --- Load model (supports .pkl and .keras) ---
print(f"[Edge Gateway] Loading model from {MODEL_PATH}")
model = None
model_type = None

try:
    if MODEL_PATH.endswith(".keras"):
        from tensorflow.keras.models import load_model as keras_load
        model = keras_load(MODEL_PATH)
        model_type = "keras"
        print("[Edge Gateway] Keras model loaded")
    else:
        import joblib
        model = joblib.load(MODEL_PATH)
        model_type = "sklearn"
        print("[Edge Gateway] sklearn model loaded")
except Exception as e:
    print(f"[Edge Gateway] WARNING: Could not load model ({e}), running in dummy mode")

# --- Metrics logging ---
LOG_FIELDS = [
    "timestamp", "source", "prediction", "label", "confidence",
    "latency_ms", "cpu_percent", "memory_mb", "total_requests"
]
request_count = 0

CLASS_NAMES = [
    "Backdoor", "DDoS_HTTP", "DDoS_ICMP", "DDoS_TCP", "DDoS_UDP",
    "Fingerprinting", "MITM", "Normal", "Password", "Port_Scanning",
    "Ransomware", "SQL_injection", "Uploading", "Vulnerability_scanner", "XSS"
]
NORMAL_CLASS_IDX = CLASS_NAMES.index("Normal") if "Normal" in CLASS_NAMES else -1


def init_log():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(LOG_FIELDS)


def log_metrics(source, prediction, label, confidence, latency_ms):
    global request_count
    request_count += 1
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / (1024 * 1024)
    cpu = psutil.cpu_percent(interval=None)
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(), source, prediction, label,
            f"{confidence:.4f}", f"{latency_ms:.2f}",
            f"{cpu:.1f}", f"{mem_mb:.2f}", request_count,
        ])


# --- API routes ---

@app.route("/health", methods=["GET"])
def health():
    return {"status": "running", "model_loaded": model is not None,
            "model_type": model_type, "total_requests": request_count}


@app.route("/predict", methods=["POST"])
def predict():
    """
    Expects JSON: {"features": [f1..f46], "source": "sensor"|"attacker"}
    Returns: {"prediction": int, "label": str, "confidence": float, "latency_ms": float}
    """
    data = request.get_json(force=True)
    features = data.get("features", [])
    source = data.get("source", "unknown")

    if not features:
        return {"error": "No features provided"}, 400

    features_array = np.array(features, dtype=np.float32).reshape(1, -1)

    start = time.perf_counter()

    if model is None:
        prediction = int(np.random.choice(range(len(CLASS_NAMES))))
        confidence = 1.0 / len(CLASS_NAMES)
    elif model_type == "keras":
        # CNN expects shape (1, n_features, 1)
        x = features_array.reshape(1, features_array.shape[1], 1) if "CNN" in MODEL_PATH else features_array
        proba = model.predict(x, batch_size=1, verbose=0)[0]
        prediction = int(np.argmax(proba))
        confidence = float(proba[prediction])
    else:
        prediction = int(model.predict(features_array)[0])
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_array)[0]
            confidence = float(max(proba))
        else:
            confidence = 1.0

    latency_ms = (time.perf_counter() - start) * 1000

    label = CLASS_NAMES[prediction] if prediction < len(CLASS_NAMES) else str(prediction)
    is_attack = (prediction != NORMAL_CLASS_IDX)

    log_metrics(source, prediction, label, confidence, latency_ms)

    status = "ATTACK" if is_attack else "NORMAL"
    print(
        f"[{source:>8}] {status:6} ({label:22}) | conf={confidence:.3f} "
        f"| latency={latency_ms:.2f}ms | n={request_count}"
    )

    return {
        "prediction": prediction,
        "label": label,
        "is_attack": is_attack,
        "confidence": confidence,
        "latency_ms": round(latency_ms, 2),
    }


@app.route("/metrics", methods=["GET"])
def metrics():
    process = psutil.Process(os.getpid())
    mem = process.memory_info()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_rss_mb": round(mem.rss / (1024 * 1024), 2),
        "memory_vms_mb": round(mem.vms / (1024 * 1024), 2),
        "total_requests": request_count,
    }


if __name__ == "__main__":
    init_log()
    print("[Edge Gateway] Starting on port 5000...")
    app.run(host="0.0.0.0", port=5000, threaded=True)
