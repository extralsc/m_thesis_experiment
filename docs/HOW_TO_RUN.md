# How to Run the Experiment — Complete Researcher Guide

This guide takes you from a fresh machine to thesis-ready results and figures. Follow the phases in order.

---

## What You Need

- **Docker Desktop** installed and running (free: https://www.docker.com/products/docker-desktop/)
- **Python 3.9+** on your host machine (for `setup_environment.py` and `analyze_results.py`)
- The project folder (this repo)
- The trained model files from Google Colab (`thesis_results.zip`)
- The Edge-IIoTset dataset from Kaggle

Estimated total time: ~90 minutes (mostly waiting for experiments to run)

---

## Phase 1 — One-Time Setup

Do this once. Skip it if you have already done it.

### Step 1: Get the trained models from Google Colab

1. Open your Colab notebook (`data/THESIS.ipynb`)
2. Run all cells — the final cell creates `thesis_results.zip`
3. Download `thesis_results.zip` to your computer
4. Extract it into the `models/` folder:

```bash
unzip thesis_results.zip -d models/
```

You should now have:
```
models/
  Random_Forest.pkl     (209 MB)
  Decision_Tree.pkl
  Logistic_Regression.pkl
  Naive_Bayes.pkl
  ANN.keras
  CNN.keras
  scaler.pkl
```

> **If `scaler.pkl` is missing:** In your Colab notebook, add this after the `StandardScaler` cell:
> ```python
> import joblib, os
> os.makedirs('saved_models', exist_ok=True)
> joblib.dump(scaler, 'saved_models/scaler.pkl')
> ```
> Then re-run and re-download.

### Step 2: Download the dataset from Kaggle

1. Go to Kaggle and download `mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot`
2. You need the folder `ML-EdgeIIoT-dataset-selected-features-for-ML/` which contains CSV files per attack type plus `Water_Level.csv`
3. Place the CSVs in `data/raw/`:

```
data/raw/
  Water_Level.csv
  Backdoor_attack.csv
  DDoS-HTTP_attack.csv
  MITM_attack.csv
  Port_Scanning_attack.csv
  SQL_Injection_attack.csv
  XSS_attack.csv
```

### Step 3: Install preprocessing dependencies

```bash
pip install pandas scikit-learn joblib numpy
```

### Step 4: Preprocess the data

```bash
python setup_environment.py
```

This script reads the CSVs, applies the same scaling used during training (using `scaler.pkl`), and saves fast binary files to `data/processed/`. Takes about 5–10 minutes.

When done, you will see:
```
data/processed/
  sensor.npy          (normal traffic — 1.78M rows)
  Backdoor.npy
  DDoS_HTTP.npy
  MITM.npy
  Port_Scanning.npy
  SQL_injection.npy
  XSS.npy
```

> **Why this step?** The raw CSVs are hundreds of MB. Converting them once to binary `.npy` files means the Docker containers start in seconds instead of minutes.

---

## Phase 2 — Run the Baseline (Unconstrained)

Run all 6 models **without** any resource limits. This establishes the performance ceiling.

```bash
bash run_experiments.sh --baseline 120
```

- `--baseline` — uses the unconstrained profile (no CPU/RAM/network limits)
- `120` — seconds per model (2 minutes). Use `300` for more stable results.

This takes ~15 minutes total (6 models × 2 minutes + startup time).

**Where results go:** `results/baseline/<model>_metrics.csv`, `_attacker_log.csv`, `_sensor_log.csv`

**What to expect:** Low latency (often < 5ms for sklearn models), high CPU available, RAM varies by model.

---

## Phase 3 — Run the Constrained Experiment (Pi 4 Simulation)

Run all 6 models **with** resource limits that simulate a Raspberry Pi 4 edge gateway.

```bash
bash run_experiments.sh 120
```

Constraints applied:
- **1 CPU core** — Pi 4 runs on 1.8 GHz Cortex-A72 (4 cores, but we limit to 1 to be conservative and reproducible)
- **512 MB RAM** — lower bound of Pi 4 Model B (available: 1/2/4/8 GB, but 512MB is worst-case for a production deployment)
- **50ms ± 10ms network delay** — typical round-trip time of a Pi on a local LAN (backed by Diab et al. 2024, IoTSim-Edge)

**Where results go:** `results/<model>_metrics.csv`, `_attacker_log.csv`, `_sensor_log.csv`

**What to expect:** Higher latency (especially for large models like Random Forest), higher CPU%, same or higher RAM usage.

> **Important:** Run the baseline BEFORE the constrained experiment. Without a baseline, there is no reference point to show how much the constraints degrade performance.

---

## Phase 4 — Analyze Results and Generate Thesis Figures

Install analysis dependencies (once):

```bash
pip install pandas matplotlib scipy scikit-learn
```

Run the analysis script:

```bash
python analyze_results.py
```

The script will:

1. **Print a summary table** — one row per model with all metrics:
   - Overall detection rate
   - Macro-F1 score
   - Balanced Accuracy
   - False positive rate
   - Mean ± std latency (ms)
   - Mean ± std CPU usage (%)
   - Mean ± std RAM usage (MB)
   - Baseline vs constrained latency delta (if baseline exists)

2. **Save a CSV summary** → `results/summary_table.csv`

3. **Generate 3 publication-ready plots** → `results/plots/`

4. **Print a NIS2 compliance table** — per attack type with NIS2 article mapping

5. **Print a thesis placement guide** — tells you exactly which number/plot goes in which thesis section

---

## Phase 5 — Adding Results to the Thesis

### The summary table → Thesis Table in Results section

Copy `results/summary_table.csv` into your thesis results table. The table has one row per model and covers all metrics the supervisors and examinators require: F1, Balanced Accuracy, latency (with standard deviation), CPU, RAM.

**Where in thesis:** Section 4 (Results), Table X: "Model Performance Under Constrained and Unconstrained Deployment"

### Figure 1 — Detection Rates by Attack Type

File: `results/plots/fig1_detection_rates.png`

A grouped bar chart showing how well each model detects each of the 6 attack types. This directly answers **RQ1** (which models detect IoT attacks?) and **RQ2** (which remain viable under constraints?).

**Where in thesis:** Section 4.2 (Detection Performance per Attack Type)

**Caption template:**
> "Figure X: Per-attack-type detection rate for all six models under Raspberry Pi 4 hardware constraints. Error bars represent standard deviation across the experiment run."

### Figure 2 — Latency vs. Detection Quality (F1)

File: `results/plots/fig2_latency_vs_f1.png`

A scatter plot with mean inference latency on the x-axis and Macro-F1 on the y-axis. Each model is one point. If baseline results exist, constrained and baseline points are shown together, revealing the trade-off.

**Where in thesis:** Section 4.3 (Resource Constraint Impact)

**Caption template:**
> "Figure X: Trade-off between inference latency and detection quality (Macro-F1) for constrained (Raspberry Pi 4 limits) and unconstrained baseline deployments."

### Figure 3 — Resource Usage per Model

File: `results/plots/fig3_resource_usage.png`

A grouped bar chart showing mean CPU% and mean RAM (MB) per model. Demonstrates which models are feasible on a Pi (RAM < 512MB, CPU < 100%) and which exceed the constraints.

**Where in thesis:** Section 4.3 (Resource Constraint Impact)

**Caption template:**
> "Figure X: Mean CPU usage and RAM consumption per model under constrained deployment. The horizontal dashed lines indicate the Raspberry Pi 4 hardware limits (512MB RAM, 100% single-core CPU)."

### The NIS2 compliance table → Thesis Discussion section

The analysis script prints a NIS2 table:

| Attack Type | STRIDE | NIS2 Article | Detection Rate | Compliant? |
|-------------|--------|-------------|---------------|------------|
| DDoS_HTTP | Denial of Service | Art. 21(2)(b) | X% | Yes/No |
| MITM | Tampering | Art. 21(2)(e) | X% | Yes/No |
| ... | | | | |

**Where in thesis:** Section 5 (Discussion), subsection "NIS2 Compliance Assessment"

**How to determine compliant:** A detection rate ≥ 80% is the threshold used in this thesis (consistent with Ferrag et al. 2022). Below 80% = does not meet the NIS2 requirement for that threat category.

### Statistical analysis → Thesis Results section

The summary table already includes mean ± std for latency, CPU, and RAM. Add this sentence to your results methodology:

> "Each metric is reported as mean ± standard deviation across all predictions made during the experiment run. A 95% confidence interval is computed using the t-distribution to reflect result reliability."

The confidence intervals are also printed by `analyze_results.py`.

---

## Troubleshooting

**Docker cannot start / permission denied:**
Make sure Docker Desktop is running and you are in the `docker` group:
```bash
sudo usermod -aG docker $USER
# then log out and back in
```

**Gateway takes too long to start (Random Forest):**
The 209MB Random Forest model takes 30–60 seconds to load under memory constraints. The sensor and attacker will wait automatically (they poll `/health`). Be patient.

**`tc` permission error in logs:**
The network delay tool requires `NET_ADMIN` capability. This is already set in `docker-compose.yml`. If you see errors, make sure you are using the provided `docker-compose.yml` and not a custom one.

**`data/processed/` is empty:**
Run `python setup_environment.py` first (Phase 1, Step 4).

**Out of disk space:**
The `data/processed/sensor.npy` file is ~600MB. Make sure you have at least 2GB free.

---

## Verification Checklist

Before submitting to supervisors, verify:

- [ ] `results/baseline/` contains 18 CSV files (3 per model × 6 models)
- [ ] `results/` contains 18 CSV files (constrained results)
- [ ] `python analyze_results.py` runs without errors
- [ ] `results/summary_table.csv` exists and has 6 rows (one per model)
- [ ] `results/plots/` contains 3 PNG files
- [ ] The summary table shows clearly different latency between baseline and constrained runs
- [ ] All 6 attack types appear in the NIS2 compliance table
