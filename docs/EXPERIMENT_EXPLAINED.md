# Experiment Explained — Plain-English Guide for Supervisors

This document explains every file in the experiment, what it does, and why it exists. No Docker knowledge is assumed.

---

## What Is This Experiment?

The experiment answers one question: **"How well do ML-based intrusion detection models perform when deployed on a cheap, resource-limited IoT edge device?"**

To answer it, we built a simulated environment where:
- A "water level sensor" sends normal traffic to an edge gateway (a small computer checking for attacks)
- An "attacker" sends known attack traffic to that same gateway
- The gateway runs each of our 6 trained ML models and measures how well it detects attacks — and how much CPU and memory it uses under tight hardware limits

Everything runs in Docker containers on your laptop to simulate the real Raspberry Pi 4 hardware we target.

---

## The Big Picture

```
Google Colab (training phase — done)
    ↓
6 trained models saved as files (Random_Forest.pkl, ANN.keras, etc.)
    ↓
Docker experiment (measurement phase — this project)
    ↓
Results CSVs → analyze_results.py → Tables + Graphs → Thesis
```

Three containers run simultaneously and talk to each other over a simulated network:

```
[iot-sensor container]  →  HTTP request every 1s  →  [edge-gateway container]
[attacker container]    →  HTTP request every 0.5s →  [edge-gateway container]
```

The edge-gateway loads one ML model, classifies each incoming request as "normal" or "attack", and records the result with timing and resource measurements.

---

## File-by-File Explanation

### Top-Level Files

#### `docker-compose.yml`
**What it is:** The main configuration file that defines all 3 containers, how they connect, and what hardware limits to apply.

**Why it exists:** Instead of running 3 separate commands to start 3 separate containers, this one file describes the whole system. Docker reads it and starts everything together.

**Key setting:** The edge-gateway gets `1 CPU core` and `512 MB RAM` — the hardware spec of a Raspberry Pi 4 Model B. It also applies `50ms network delay` (using the Linux `tc netem` tool) to simulate a Pi connected to a local IoT network. This combination is what makes it a "constrained" run.

#### `docker-compose.baseline.yml`
**What it is:** Same as docker-compose.yml but with NO hardware limits and NO network delay.

**Why it exists:** Supervisor Fatiha requires a baseline (unconstrained) run first. Without a baseline, we cannot answer: "how much does the Pi constraint degrade performance?" The baseline is the ceiling; the constrained run shows how far we fall below it.

#### `run_experiments.sh`
**What it is:** A shell script that runs all 6 models one after another automatically.

**Why it exists:** Without this script, you would have to manually start Docker, wait 2 minutes, stop it, change the model name, and repeat — 6 times. This script does it all. It also saves the results with the correct model name so they don't overwrite each other.

**How to use it:**
```bash
bash run_experiments.sh --baseline 120   # run all 6 without constraints (2 min each)
bash run_experiments.sh 120              # run all 6 with Pi constraints (2 min each)
```

#### `analyze_results.py`
**What it is:** A Python script that reads all the results CSV files and produces:
1. A summary table with all metrics per model
2. Three publication-ready graphs (bar charts and scatter plot)
3. A thesis placement guide (telling you where each number/graph goes in the thesis)

**Why it exists:** The raw results are spread across 18 CSV files (3 per model × 6 models). This script brings them all together and computes the statistics the thesis requires: Macro-F1, Balanced Accuracy, mean ± std latency, CPU and RAM usage, and NIS2 compliance mapping.

#### `setup_environment.py`
**What it is:** A one-time preprocessing script that converts the raw CSV dataset files into fast binary format (`.npy` files).

**Why it exists:** The Edge-IIoTset dataset CSVs are large (hundreds of MB). Parsing them from scratch every time a container starts would take too long and waste memory. This script runs once, converts the data to fast NumPy binary format, and saves it to `data/processed/`. Containers then load the `.npy` files in milliseconds.

**When to run it:** Once, before the first Docker experiment run, after downloading the dataset.

---

### `edge/` — Container 1: The Edge Gateway

This is the most important container. It simulates a Raspberry Pi 4 running ML-based IDS software.

#### `edge/Dockerfile`
**What it is:** Instructions for building the gateway container image — which Python packages to install, which files to copy in.

**Why it exists:** Docker needs to know how to build the container. This file installs Flask (the web server), scikit-learn and TensorFlow (for ML model loading), psutil (for CPU/memory measurement), and iproute2 (for network delay simulation).

#### `edge/entrypoint.sh`
**What it is:** The startup script that runs when the container starts (in constrained mode only).

**Why it exists:** Before starting the gateway, we apply a 50ms network delay using the Linux `tc netem` tool. This simulates the typical round-trip time of a Raspberry Pi connected to a LAN IoT network (backed by Diab et al. 2024 and IoTSim-Edge). Without this, we'd only be testing CPU/RAM constraints, not the full deployment scenario.

#### `edge/src/gateway.py`
**What it is:** The Flask web server that runs the ML model and records results.

**Why it exists:** The gateway needs to receive traffic (via HTTP POST requests), run it through the ML model, and return a classification. Flask provides the web server framework. The gateway also measures and logs: inference latency (how long the model took), CPU usage, and RAM usage — these are the thesis metrics.

**Endpoints:**
- `POST /predict` — send 46 features, get back class label (Normal or attack type)
- `GET /health` — check if gateway is ready
- `GET /metrics` — get current CPU % and RAM usage

---

### `sensor/` — Container 2: The IoT Water Level Sensor

#### `sensor/src/sensor.py`
**What it is:** A Python script that replays normal IoT traffic.

**Why it exists:** We need legitimate, non-attack traffic to measure false positive rate (how often the IDS wrongly flags normal traffic as an attack). The data comes from `Water_Level.csv` in the Edge-IIoTset dataset — real MQTT readings from a physical water level sensor in the testbed where the dataset was collected.

The sensor sends one row of data every second to the gateway's `/predict` endpoint and tracks: did the model correctly say "Normal"? If it says "attack" when it should say "Normal", that's a false positive.

---

### `attacker/` — Container 3: The Attacker

#### `attacker/src/attacker.py`
**What it is:** A Python script that replays known attack traffic.

**Why it exists:** We need to test whether the IDS can detect real attacks. The data comes from the same Edge-IIoTset dataset — the rows labeled as specific attack types (Backdoor, DDoS_HTTP, MITM, Port_Scanning, SQL_injection, XSS).

Each attack type is mapped to a STRIDE threat category (the standard threat modeling framework):
- Backdoor → Elevation of Privilege
- DDoS_HTTP → Denial of Service
- MITM → Tampering
- Port_Scanning → Information Disclosure
- SQL_injection → Tampering
- XSS → Tampering

The attacker sends one row every 0.5 seconds and tracks: did the model detect it as an attack? This gives us the detection rate per STRIDE category, which maps directly to NIS2 Article 21 requirements.

---

### `models/` — Trained Models

Contains the 6 ML models trained in Google Colab. These are the files the gateway loads at startup.

| File | Size | Algorithm | Notes |
|------|------|-----------|-------|
| `Random_Forest.pkl` | 209 MB | Random Forest (100 trees) | Best accuracy in Colab (93.96%) |
| `Decision_Tree.pkl` | 2.7 MB | Decision Tree | Fast, small |
| `Logistic_Regression.pkl` | 6.5 KB | Logistic Regression | Very small, interpretable |
| `Naive_Bayes.pkl` | 12 KB | Naive Bayes | Probabilistic, very fast |
| `ANN.keras` | 208 KB | Artificial Neural Network | Deep learning, medium size |
| `CNN.keras` | 391 KB | Convolutional Neural Network | Deep learning, medium size |
| `scaler.pkl` | 1.7 KB | StandardScaler | Preprocessing — must match training |

The `scaler.pkl` is critical: it applies the same numerical scaling that was used during training. Without it, feature values would be on different scales and the model would give wrong predictions.

---

### `data/` — Dataset Files

#### `data/processed/` — Preprocessed data (created by `setup_environment.py`)
- `sensor.npy` — 1.78 million normal traffic rows, 46 features each
- `Backdoor.npy`, `DDoS_HTTP.npy`, `MITM.npy`, `Port_Scanning.npy`, `SQL_injection.npy`, `XSS.npy` — attack traffic rows

These are NumPy binary files: fast to load, compact, and exactly what the containers need.

#### `data/THESIS.ipynb`
The full Google Colab training notebook. Contains data download, preprocessing, model training, and evaluation. This is the source of the `models/` files.

---

### `results/` — Experiment Output

Created automatically when experiments run. One set of 3 CSV files per model:

| File | What it records | Key columns |
|------|-----------------|-------------|
| `<model>_metrics.csv` | Every prediction the gateway made | `latency_ms`, `cpu_percent`, `memory_mb`, `source` (sensor/attacker) |
| `<model>_attacker_log.csv` | Attack traffic sent by the attacker | `attack_type`, `stride_category`, `detected` (yes/no), `latency_ms` |
| `<model>_sensor_log.csv` | Normal traffic sent by the sensor | `is_attack` (yes/no = false positive flag), `latency_ms` |

After running the baseline, results also appear in `results/baseline/` with the same structure.

---

### `docs/` — Documentation

| File | Purpose |
|------|---------|
| `EXPERIMENT_EXPLAINED.md` | This file — plain-English guide for supervisors |
| `HOW_TO_RUN.md` | Step-by-step instructions for running the experiment |
| `IMPROVEMENTS_NEEDED.md` | All examinator and supervisor feedback with from→to improvement plan |

---

## Why Docker? Why Not Just Run Python Scripts?

Docker gives us three things that matter for this thesis:

1. **Reproducible resource limits** — We can tell Docker "this container gets exactly 1 CPU and 512MB RAM". On a real Raspberry Pi, the OS and other processes also consume resources, so our limits model a conservative Pi deployment. Every researcher who runs this gets the same constraints.

2. **Network isolation** — The three containers communicate over a simulated network (`iot-net`). We can add network delay (50ms) to this network to simulate the Pi being on a physical LAN, which is something you cannot easily control when running scripts directly.

3. **Clean environment** — Each container starts fresh with only the packages it needs. No conflicts with the host system's Python packages. The experiment runs identically on any machine.

---

## The Two-Tier Architecture (Important for Thesis)

There are two distinct hardware tiers in this experiment:

| Tier | Hardware | RAM | Role | In this experiment |
|------|----------|-----|------|--------------------|
| Sensor microcontroller | Arduino Nano 33 BLE, ESP32, etc. | 256KB–512KB | Reads physical measurement (water level) and sends it over MQTT | Simulated by `sensor.py` — not a real Arduino |
| Edge gateway | Raspberry Pi 4 Model B | 512MB–4GB | Receives sensor readings, runs ML model, classifies as normal/attack | Simulated by `edge-gateway` container with 1 CPU + 512MB limit |

The ML intrusion detection runs **on the gateway, not on the sensor**. The 32KB RAM figure sometimes mentioned for microcontrollers is the sensor tier — completely different hardware. Our target is the Pi 4 gateway.
