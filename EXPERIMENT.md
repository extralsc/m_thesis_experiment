# IoT Intrusion Detection System — Docker Experiment

## Overview

This experiment deploys 6 pre-trained ML models on a resource-constrained edge device (simulating a Raspberry Pi 4) and measures how each model performs under real hardware limits. Models were trained in Google Colab on the **Edge-IIoTset** dataset. The Docker experiment replays real dataset rows against those models to measure detection quality, latency, CPU, and memory under constraint.

### Experiment Pipeline

```
Edge-IIoTset Dataset (Kaggle)
      |
      |  [Google Colab — THESIS.ipynb]
      |
      +-- Data preparation (152k rows, 46 features, 15 classes)
      |
      +-- Train 6 models (RF, DT, LR, NB, ANN, CNN)
      |
      +-- Evaluate on test split (accuracy, F1, FPR, FNR, latency, size)
      |
      v
  saved_models/ (downloaded as thesis_results.zip)
      |
      |  [Docker — this project]
      |
      +-- Deploy each model on Pi-constrained container (1 CPU, 512MB)
      |
      +-- Replay real normal + attack traffic from dataset
      |
      +-- Measure: inference latency, CPU %, RSS memory, detection rate
      |
      v
  results/<model>_metrics.csv  →  map to STRIDE + NIS2
```

---

## Architecture

```
+-------------------------------------------------------------+
|                     Docker Network: iot-net                 |
|                                                             |
|  +----------------+  HTTP POST /predict  +---------------+ |
|  |  IoT Sensor    | -------------------> |  Edge Gateway | |
|  |  (sensor.py)   |                      |  (gateway.py) | |
|  |                |                      |               | |
|  | Replays normal |  HTTP POST /predict  | Loads 1 model | |
|  | rows from      | <------------------- | Flask API :5000| |
|  | normal_traffic |                      | 1 CPU / 512MB | |
|  | .csv @ 1s      |                      | RAM (Pi limit)| |
|  +----------------+                      |               | |
|                                          | Writes metrics| |
|  +----------------+  HTTP POST /predict  | to results/   | |
|  |  Attacker      | -------------------> |               | |
|  | (attacker.py)  |                      +---------------+ |
|  |                |                                        |
|  | Replays attack |    Shared volumes:                     |
|  | rows + STRIDE  |    - models/  (read-only)              |
|  | labels @ 0.5s  |    - data/    (read-only)              |
|  +----------------+    - results/ (all containers write)   |
+-------------------------------------------------------------+
```

---

## Project Structure

```
thesis/docker/
├── docker-compose.yml            # 3 containers, iot-net network, Pi resource limits
├── run_experiments.sh            # Runs all 6 models sequentially, saves separate results
├── edge/                         # Container 1: Edge IoT Gateway
│   ├── Dockerfile
│   ├── requirements.txt          # flask, scikit-learn, tensorflow-cpu, psutil
│   └── src/gateway.py            # Flask API + model loader + metrics logger
├── sensor/                       # Container 2: IoT Sensor
│   ├── Dockerfile
│   └── src/sensor.py             # Replays normal_traffic.csv, tracks false positives
├── attacker/                     # Container 3: Attacker
│   ├── Dockerfile
│   └── src/attacker.py           # Replays attack_traffic.csv with STRIDE labels
├── models/                       # Trained models (copy from thesis_results.zip)
│   ├── Random_Forest.pkl
│   ├── Decision_Tree.pkl
│   ├── Logistic_Regression.pkl
│   ├── Naive_Bayes.pkl
│   ├── ANN.keras
│   └── CNN.keras
├── data/                         # Dataset rows exported from Colab
│   ├── normal_traffic.csv        # Normal rows, 46 features, no label column
│   ├── attack_traffic.csv        # Attack rows, 46 features, no label column
│   ├── attack_labels.csv         # Attack type per row (matches attack_traffic.csv)
│   ├── export_for_docker.py      # Run this in Colab to generate the 3 CSVs above
│   └── THESIS.ipynb              # Full training notebook (run in Google Colab)
└── results/                      # Experiment output — one CSV set per model run
```

---

## Dataset

| Property | Value |
|----------|-------|
| Name | Edge-IIoTset |
| Source | Kaggle: `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot` |
| File used | `ML-EdgeIIoT-dataset.csv` |
| Raw rows | 157,800 |
| After cleaning | 152,196 |
| Features | 46 (after dropping leakage columns and encoding) |
| Classes | 15 (1 normal + 14 attack types) |

**Attack classes:**

| Class | STRIDE Category |
|-------|----------------|
| Normal | — |
| Backdoor | Elevation of Privilege |
| DDoS_HTTP | Denial of Service |
| DDoS_ICMP | Denial of Service |
| DDoS_TCP | Denial of Service |
| DDoS_UDP | Denial of Service |
| Fingerprinting | Information Disclosure |
| MITM | Tampering |
| Password | Spoofing |
| Port_Scanning | Information Disclosure |
| Ransomware | Tampering |
| SQL_injection | Tampering |
| Uploading | Elevation of Privilege |
| Vulnerability_scanner | Information Disclosure |
| XSS | Tampering |

---

## Models

Six models trained in Colab, saved to `saved_models/` and bundled as `thesis_results.zip`:

| Model | File | Type | Deployment Tier (from Colab results) |
|-------|------|------|--------------------------------------|
| Random Forest | `Random_Forest.pkl` | sklearn | Cloud (209 MB) |
| Decision Tree | `Decision_Tree.pkl` | sklearn | Cloud (2.7 MB) |
| Logistic Regression | `Logistic_Regression.pkl` | sklearn | Sensor (6.5 KB) |
| Naive Bayes | `Naive_Bayes.pkl` | sklearn | Sensor (11.9 KB) |
| ANN | `ANN.keras` | TensorFlow | Gateway (208 KB) |
| CNN | `CNN.keras` | TensorFlow | Gateway (390 KB) |

**Key results from Colab (on full hardware, no constraints):**

| Model | Accuracy | Macro-F1 | FPR | Inference µs/sample |
|-------|----------|----------|-----|---------------------|
| Random Forest | 0.9396 | 0.9247 | 0.0043 | 9.97 |
| Decision Tree | 0.9335 | 0.9157 | 0.0047 | 0.22 |
| Logistic Regression | 0.7660 | 0.7242 | 0.0166 | 1.15 |
| Naive Bayes | 0.6701 | 0.5373 | 0.0236 | 5.11 |
| ANN | 0.8104 | 0.7717 | 0.0135 | 22.36 |
| CNN | 0.6903 | 0.6258 | 0.0219 | 29.83 |

The Docker experiment repeats inference under 1 CPU / 512 MB RAM to show how these numbers change on a Pi.

---

## Setup

### Step 1 — Get models from Colab

In your Colab notebook, cell 13 runs:
```python
!zip -r thesis_results.zip saved_models
files.download("thesis_results.zip")
```
The zip downloads automatically. Extract it into the Docker project:
```bash
unzip thesis_results.zip -d /home/dev/thesis/docker/models/
```

### Step 2 — Export data rows from Colab

Run `data/export_for_docker.py` inside Colab (paste it as a new cell after the data preparation cell). Download the 3 output files and place them in `data/`:

```
data/normal_traffic.csv
data/attack_traffic.csv
data/attack_labels.csv
```

### Step 3 — Run the experiment

**All 6 models automatically:**
```bash
cd /home/dev/thesis/docker
bash run_experiments.sh           # 2 minutes per model (default)
bash run_experiments.sh 300       # 5 minutes per model
```

**One model manually:**
```bash
# sklearn model
MODEL_NAME=Random_Forest docker-compose up --build
docker-compose logs -f
docker-compose down

# Keras model
MODEL_NAME=ANN MODEL_PATH=/app/models/ANN.keras docker-compose up --build
```

**Check gateway while running:**
```bash
curl http://localhost:5000/health    # status, model loaded, request count
curl http://localhost:5000/metrics   # live CPU %, RSS MB, VMS MB
```

---

## Container Details

### Edge Gateway

| Property | Value |
|----------|-------|
| CPU limit | 1 core |
| RAM limit | 512 MB |
| Port | 5000 |
| Model support | `.pkl` (sklearn) and `.keras` (TensorFlow) |
| Dummy mode | Runs with random predictions if model file is missing |

**API:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/predict` | POST | Classify a 46-feature vector |
| `/health` | GET | Model status and request count |
| `/metrics` | GET | Live CPU %, RSS memory MB, VMS memory MB |

**`/predict` request:**
```json
{ "features": [f1, f2, ..., f46], "source": "sensor" }
```

**`/predict` response:**
```json
{ "prediction": 7, "label": "Normal", "is_attack": false, "confidence": 0.97, "latency_ms": 4.2 }
```

### IoT Sensor

Reads `data/normal_traffic.csv` row-by-row, POSTs each row to `/predict` at 1-second intervals. Prints a live false positive rate (how often the model wrongly flags normal traffic as an attack).

### Attacker

Reads `data/attack_traffic.csv` and `data/attack_labels.csv` in parallel, POSTs each row at 0.5-second intervals. Maps each attack type to its STRIDE category. Prints per-type detection rate live.

---

## Results

After running, `results/` contains one set of files per model:

| File | Key columns | What it answers |
|------|-------------|-----------------|
| `<model>_metrics.csv` | `latency_ms`, `cpu_percent`, `memory_mb`, `confidence`, `source` | How fast and resource-hungry is this model on a Pi? |
| `<model>_attacker_log.csv` | `attack_type`, `stride_category`, `detected`, `latency_ms` | Which STRIDE threats does this model catch? |
| `<model>_sensor_log.csv` | `label`, `is_attack`, `latency_ms` | How often does it false-alarm on legitimate traffic? |

### Memory metrics explained

| Metric | What it is | Why it matters |
|--------|-----------|----------------|
| `memory_rss_mb` | Resident Set Size — physical RAM currently used | Real memory pressure on the Pi |
| `memory_vms_mb` | Virtual Memory Size — total address space reserved | Includes shared libs, may exceed RSS |
| `cpu_percent` | CPU usage at inference time | Shows if model saturates the single Pi core |

RSS is the primary metric for Raspberry Pi constraint analysis. VMS is reported for completeness.

---

## Configuration Reference

All behaviour is controlled by environment variables in `docker-compose.yml`:

| Container | Variable | Default | Purpose |
|-----------|----------|---------|---------|
| edge-gateway | `MODEL_PATH` | `Random_Forest.pkl` | Which model file to load |
| edge-gateway | `LOG_PATH` | `<model>_metrics.csv` | Where to write metrics |
| iot-sensor | `SEND_INTERVAL` | `1.0` | Seconds between requests |
| iot-sensor | `DATA_PATH` | `normal_traffic.csv` | Normal traffic source |
| attacker | `SEND_INTERVAL` | `0.5` | Seconds between attacks |
| attacker | `DATA_PATH` | `attack_traffic.csv` | Attack traffic source |

To simulate a Raspberry Pi 3 instead of Pi 4, change in `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      cpus: "1.0"
      memory: 256M   # Pi 3 has 512MB total, leave headroom for OS
```

---

## NIS2 Mapping

| NIS2 Article | Requirement | Experiment Metric |
|-------------|-------------|-------------------|
| Art. 21 — Risk analysis | Identify threats | STRIDE category detection rate per attack type |
| Art. 21 — Incident detection | Detect attacks | `detected` column in `attacker_log.csv` |
| Art. 21 — Business continuity | Stay operational under load | Latency and CPU under concurrent sensor + attacker |
| Art. 21 — Supply chain security | Trustworthy components | Model provenance (Edge-IIoTset, open dataset) |
| Art. 23 — Reporting timelines | Fast response | `latency_ms` — time from packet to classification |
