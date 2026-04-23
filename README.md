# IoT Intrusion Detection System — Docker Experiment

Master's thesis experiment evaluating ML-based Intrusion Detection Systems (IDS) deployed on a resource-constrained edge device (Raspberry Pi 4-class), using real IoT network traffic from the Edge-IIoTset dataset. Results are mapped to STRIDE threat categories and NIS2 compliance requirements.

---

## Research Question

> *Can ML-based intrusion detection run effectively on a Raspberry Pi-class edge device to protect IoT infrastructure, and which model best satisfies NIS2 compliance requirements under real hardware constraints?*

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Docker Network (iot-net)                   │
│                                                             │
│  ┌──────────────────┐   HTTP POST /predict  ┌────────────┐ │
│  │  Water Sensor    │ ───────────────────>  │            │ │
│  │  (iot-sensor)    │                       │    Edge    │ │
│  │                  │                       │  Gateway   │ │
│  │  Streams real    │   HTTP POST /predict  │            │ │
│  │  water level     │ <───────────────────  │  ML model  │ │
│  │  IoT traffic     │                       │  + IDS     │ │
│  └──────────────────┘                       │            │ │
│                                             │  1 CPU     │ │
│  ┌──────────────────┐   HTTP POST /predict  │  512MB RAM │ │
│  │  Attacker        │ ───────────────────>  │  (Pi 4)    │ │
│  │  (attacker)      │                       │            │ │
│  │                  │                       └────────────┘ │
│  │  Sends 6 STRIDE  │                                      │
│  │  attack types    │         results/ (shared volume)     │
│  └──────────────────┘                                      │
└─────────────────────────────────────────────────────────────┘
```

**Three containers communicate over a Docker bridge network:**

| Container | Role | Resource limits |
|-----------|------|----------------|
| `edge-gateway` | Runs ML model, classifies incoming traffic as NORMAL or ATTACK, logs metrics | 1 CPU, 512MB RAM |
| `iot-sensor` | Simulates a water level IoT sensor sending normal telemetry | None (external device) |
| `attacker` | Sends real attack traffic patterns (6 STRIDE types) | None (external attacker) |

---

## Dataset

**Edge-IIoTset** — IEEE Access 2022 (Ferrag et al.) — a peer-reviewed IoT/IIoT cybersecurity dataset captured from a physical testbed with real IoT devices.

| Property | Value |
|----------|-------|
| Source | Kaggle: `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot` |
| Normal traffic | `Water_Level.csv` — real MQTT traffic from a water level sensor |
| Attack traffic | 6 individual attack CSVs (see below) |
| Features | 46 network flow features per sample |

**Attack types used and STRIDE mapping:**

| Attack File | Attack Type | STRIDE Category |
|-------------|-------------|-----------------|
| `Backdoor_attack.csv` | Backdoor | Elevation of Privilege |
| `DDoS_HTTP_Flood_attack.csv` | DDoS HTTP Flood | Denial of Service |
| `MITM_attack.csv` | Man-in-the-Middle | Tampering |
| `Port_Scanning_attack.csv` | Port Scanning | Information Disclosure |
| `SQL_injection_attack.csv` | SQL Injection | Tampering |
| `XSS_attack.csv` | Cross-Site Scripting | Tampering |

---

## Models Evaluated

All 6 models were trained in Google Colab (`data/THESIS.ipynb`) on the full Edge-IIoTset ML dataset (152,196 samples, 46 features, 15 classes):

| Model | File | Colab Accuracy | Colab Macro-F1 |
|-------|------|---------------|----------------|
| Random Forest | `Random_Forest.pkl` | 93.96% | 0.9247 |
| Decision Tree | `Decision_Tree.pkl` | 93.35% | 0.9157 |
| Logistic Regression | `Logistic_Regression.pkl` | 76.60% | 0.7242 |
| Naive Bayes | `Naive_Bayes.pkl` | 67.01% | 0.5373 |
| ANN | `ANN.keras` | 81.04% | 0.7717 |
| CNN | `CNN.keras` | 69.03% | 0.6258 |

The Docker experiment re-evaluates these models under Raspberry Pi 4 constraints (1 CPU, 512MB RAM) to measure real deployment performance.

---

## Prerequisites

- Docker and Docker Compose installed
- Python 3.10+ with `pandas`, `scikit-learn`, `joblib`, `numpy`

---

## Setup After Cloning

The repo does not include model files (213MB) or the dataset (1.6GB) — too large for GitHub.
Download them separately before running anything.

### Step 1 — Get the trained models

Download `thesis_results.zip` from Google Drive:
**[INSERT GOOGLE DRIVE LINK HERE]**

```bash
# Extract into the models/ folder
unzip thesis_results.zip -d models/
```

You should now have `models/Random_Forest.pkl`, `models/ANN.keras`, `models/scaler.pkl`, etc.

Alternatively: run `data/THESIS.ipynb` in Google Colab yourself to retrain all models from scratch.

### Step 2 — Get the dataset from Kaggle

Download from: `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot`

Place these files in `data/raw/`:
```
data/raw/Water_Level.csv
data/raw/Backdoor_attack.csv
data/raw/DDoS_HTTP_Flood_attack.csv
data/raw/MITM_attack.csv
data/raw/Port_Scanning_attack.csv
data/raw/SQL_injection_attack.csv
data/raw/XSS_attack.csv
```

### Step 3 — Preprocess the dataset (one-time)

```bash
pip install pandas scikit-learn joblib numpy
python setup_environment.py
```

This creates `data/processed/*.npy` — fast binary files the containers load at runtime.

### Step 4 — Verify required files are present

```
models/
├── scaler.pkl              (exported from Colab training notebook)
├── Random_Forest.pkl
├── Decision_Tree.pkl
├── Logistic_Regression.pkl
├── Naive_Bayes.pkl
├── ANN.keras
└── CNN.keras

data/
├── Water_Level.csv         (downloaded from Kaggle)
├── Backdoor_attack.csv
├── DDoS_HTTP_Flood_attack.csv
├── MITM_attack.csv
├── Port_Scanning_attack.csv
├── SQL_injection_attack.csv
└── XSS_attack.csv
```

> **How to get models:** Run `data/THESIS.ipynb` in Google Colab, then download `thesis_results.zip` and extract into `models/`. The `scaler.pkl` is saved during the data preparation step.
>
> **How to get data:** Download from Kaggle using the dataset ID `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot`.

### Step 3 — Preprocess data (one-time only)

This step converts the raw CSVs into fast-loading NumPy arrays that the containers use at runtime. Only needs to run once.

```bash
pip install pandas scikit-learn joblib numpy
python setup_environment.py
```

Expected output:
```
[OK] All model files present
[OK] Scaler loaded
Processing sensor data: data/Water_Level.csv...
[OK] Saved 1778027 sensor rows -> data/processed/sensor.npy
Processing Backdoor_attack.csv...
[OK] Saved 24026 rows -> data/processed/Backdoor.npy
...
=== Setup complete ===
```

---

## Running the Experiment

### Run one model

```bash
MODEL_NAME=Random_Forest docker-compose up --build
```

Replace `Random_Forest` with any of: `Decision_Tree`, `Logistic_Regression`, `Naive_Bayes`, `ANN`, `CNN`

For Keras models (ANN, CNN):
```bash
MODEL_NAME=ANN MODEL_PATH=/app/models/ANN.keras docker-compose up --build
```

### Run all 6 models — baseline first, then constrained

**Step 1 — Baseline (no resource limits):** establishes the performance ceiling

```bash
bash run_experiments.sh --baseline 120    # 2 minutes per model
```

Results go to `results/baseline/<model>_*.csv`

**Step 2 — Constrained (Raspberry Pi 4 simulation):** 1 CPU, 512MB RAM, 50ms network delay

```bash
bash run_experiments.sh 120              # 2 minutes per model
bash run_experiments.sh 300             # 5 minutes per model (more stable)
```

Results go to `results/<model>_*.csv`

**Step 3 — Analyze and generate thesis figures:**

```bash
pip install pandas matplotlib scipy scikit-learn
python analyze_results.py
```

Outputs: `results/summary_table.csv` + 3 plots in `results/plots/` + thesis placement guide in console.

### Monitor live

```bash
docker-compose logs -f                    # all containers
docker-compose logs -f edge-gateway       # IDS classifications only
docker-compose logs -f attacker           # attack detection rates only
docker-compose logs -f iot-sensor         # false positive rate only
```

### Check gateway status

```bash
curl http://localhost:5000/health     # model status, request count
curl http://localhost:5000/metrics    # live CPU%, RSS memory, VMS memory
```

### Stop

```bash
docker-compose down
```

---

## Results

After each run, `results/` contains three CSV files named after the model:

### `<model>_metrics.csv` — Edge gateway performance
| Column | Description |
|--------|-------------|
| `timestamp` | UTC time of request |
| `source` | `water-sensor` or `attacker` |
| `prediction` | Predicted class index |
| `label` | Predicted class name (e.g. `DDoS_HTTP`, `Normal`) |
| `confidence` | Model confidence score (0–1) |
| `latency_ms` | Inference time in milliseconds |
| `cpu_percent` | CPU usage at time of inference |
| `memory_mb` | RSS memory usage in MB |

### `<model>_attacker_log.csv` — Attack detection
| Column | Description |
|--------|-------------|
| `attack_type` | Attack name (e.g. `DDoS_HTTP`) |
| `stride_category` | STRIDE category (e.g. `Denial of Service`) |
| `predicted_label` | What the model predicted |
| `detected` | `yes` if correctly identified as attack, `no` if missed |
| `latency_ms` | Inference time |

### `<model>_sensor_log.csv` — False positive rate
| Column | Description |
|--------|-------------|
| `label` | What the model predicted for normal traffic |
| `is_attack` | `yes` = false positive (normal traffic wrongly flagged) |
| `latency_ms` | Inference time |

---

## What the Experiment Measures

| Metric | Why it matters for NIS2 |
|--------|------------------------|
| Detection rate per attack type | NIS2 Art. 21 — incident detection capability |
| False positive rate | Operational reliability — too many false alarms = ignored alerts |
| Inference latency (ms) | NIS2 Art. 23 — response time requirements |
| CPU % under load | Can the Pi handle simultaneous sensor + attack traffic? |
| Memory usage (MB) | Does the model fit within Pi's 512MB limit? |

**The key thesis finding:** Colab measured models on powerful cloud hardware. This experiment measures the same models under Raspberry Pi constraints. The gap between the two reveals which models are *actually deployable* for NIS2-compliant IoT monitoring.

---

## Project Structure

```
thesis/docker/
├── README.md                    # this file
├── EXPERIMENT.md                # detailed experiment documentation
├── CLAUDE.md                    # notes for Claude Code AI assistant
├── docker-compose.yml           # constrained run (1 CPU, 512MB, 50ms delay)
├── docker-compose.baseline.yml  # baseline run (no resource limits)
├── run_experiments.sh           # run all 6 models (--baseline flag for unconstrained)
├── setup_environment.py         # one-time data preprocessing
├── analyze_results.py           # compute metrics + generate thesis figures
│
├── docs/                        # documentation
│   ├── EXPERIMENT_EXPLAINED.md  # plain-English guide for supervisors
│   ├── HOW_TO_RUN.md            # step-by-step researcher guide
│   └── IMPROVEMENTS_NEEDED.md   # examinator/supervisor feedback action plan
│
├── edge/                        # Edge IoT Gateway container
│   ├── Dockerfile
│   ├── entrypoint.sh            # applies tc netem delay before starting gateway
│   ├── requirements.txt
│   └── src/gateway.py           # Flask API + ML inference + metrics logging
│
├── sensor/                      # IoT Water Sensor container
│   ├── Dockerfile
│   ├── requirements.txt
│   └── src/sensor.py            # streams normal water level traffic
│
├── attacker/                    # Attacker container
│   ├── Dockerfile
│   ├── requirements.txt
│   └── src/attacker.py          # streams 6 STRIDE attack types
│
├── models/                      # trained ML models (from Colab)
│   ├── scaler.pkl
│   ├── Random_Forest.pkl
│   ├── Decision_Tree.pkl
│   ├── Logistic_Regression.pkl
│   ├── Naive_Bayes.pkl
│   ├── ANN.keras
│   ├── CNN.keras
│   └── train_model.py           # synthetic model trainer (fallback only)
│
├── data/                        # raw dataset files (from Kaggle/Colab)
│   ├── THESIS.ipynb             # full training notebook (run in Google Colab)
│   ├── Water_Level.csv          # normal IoT sensor traffic
│   ├── Backdoor_attack.csv
│   ├── DDoS_HTTP_Flood_attack.csv
│   ├── MITM_attack.csv
│   ├── Port_Scanning_attack.csv
│   ├── SQL_injection_attack.csv
│   ├── XSS_attack.csv
│   ├── export_for_docker.py     # (alternative) export preprocessed rows from Colab
│   ├── generate_sample.py       # synthetic data generator (fallback only)
│   └── processed/               # preprocessed .npy files (created by setup_environment.py)
│       ├── sensor.npy
│       ├── Backdoor.npy
│       ├── DDoS_HTTP.npy
│       ├── MITM.npy
│       ├── Port_Scanning.npy
│       ├── SQL_injection.npy
│       └── XSS.npy
│
└── results/                     # experiment output (auto-created)
    ├── Random_Forest_metrics.csv
    ├── Random_Forest_attacker_log.csv
    ├── Random_Forest_sensor_log.csv
    └── ...
```

---

## Methodology Note

This experiment follows standard practice in ML-based IDS research. Pre-captured network flow features from a peer-reviewed dataset (Edge-IIoTset, IEEE Access 2022) are replayed to the ML classifier — the same methodology used in all major published IDS papers (CICIDS2017, NSL-KDD, UNSW-NB15, TON-IoT benchmarks). The Docker environment enforces real Raspberry Pi 4 hardware constraints (1 CPU core, 512MB RAM) to measure actual deployment feasibility, which is the novel contribution beyond the Colab training results.

> **Limitation:** As is standard in this field, evaluation uses pre-captured traffic features rather than live network attacks. This ensures reproducibility and allows direct comparison with published benchmarks, but may not capture novel real-world traffic distributions.
