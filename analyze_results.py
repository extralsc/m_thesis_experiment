"""
Analyze Docker experiment results and generate thesis-ready outputs.

Reads all results CSV files for the 6 models, computes:
  - Detection rate per attack type (from attacker_log)
  - False positive rate (from sensor_log)
  - Macro-F1 and Balanced Accuracy
  - Mean +/- std and 95% CI for latency, CPU%, RAM
  - Baseline vs constrained comparison (if results/baseline/ exists)

Outputs:
  - results/summary_table.csv     — one row per model, all metrics
  - results/plots/fig1_detection_rates.png
  - results/plots/fig2_latency_vs_f1.png
  - results/plots/fig3_resource_usage.png
  - Console: NIS2 compliance table + thesis placement guide

Usage:
  pip install pandas matplotlib scipy scikit-learn
  python analyze_results.py
"""

import os
import sys
import math
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False
    print("[WARNING] matplotlib not installed — plots will be skipped.")
    print("          Run: pip install matplotlib")

try:
    from scipy import stats as scipy_stats
    SCIPY_OK = True
except ImportError:
    SCIPY_OK = False

try:
    from sklearn.metrics import f1_score, balanced_accuracy_score
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
    print("[WARNING] scikit-learn not installed — F1/Balanced Accuracy will be estimated.")
    print("          Run: pip install scikit-learn")


# ─── Configuration ────────────────────────────────────────────────────────────

RESULTS_DIR = "results"
BASELINE_DIR = os.path.join(RESULTS_DIR, "baseline")
PLOTS_DIR = os.path.join(RESULTS_DIR, "plots")

MODELS = [
    "Random_Forest",
    "Decision_Tree",
    "Logistic_Regression",
    "Naive_Bayes",
    "ANN",
    "CNN",
]

ATTACK_TYPES = [
    "Backdoor",
    "DDoS_HTTP",
    "MITM",
    "Port_Scanning",
    "SQL_injection",
    "XSS",
]

# NIS2 mapping per attack type
NIS2_MAP = {
    "Backdoor":      ("Elevation of Privilege", "Art. 21(2)(b)", "Incident handling"),
    "DDoS_HTTP":     ("Denial of Service",      "Art. 21(2)(b)", "Incident handling"),
    "MITM":          ("Tampering",              "Art. 21(2)(e)", "Supply chain security"),
    "Port_Scanning": ("Information Disclosure", "Art. 21(2)(e)", "Network security"),
    "SQL_injection": ("Tampering",              "Art. 21(2)(h)", "Basic cyber hygiene"),
    "XSS":           ("Tampering",              "Art. 21(2)(h)", "Basic cyber hygiene"),
}

# Detection rate threshold for NIS2 compliance
NIS2_THRESHOLD = 0.80

MODEL_LABELS = {
    "Random_Forest":      "RF",
    "Decision_Tree":      "DT",
    "Logistic_Regression": "LR",
    "Naive_Bayes":        "NB",
    "ANN":                "ANN",
    "CNN":                "CNN",
}


# ─── Data loading ─────────────────────────────────────────────────────────────

def load_model_results(model, results_dir):
    """Load all three CSV files for one model. Returns dict of DataFrames."""
    data = {}
    for suffix in ("attacker_log", "sensor_log", "metrics"):
        path = os.path.join(results_dir, f"{model}_{suffix}.csv")
        if os.path.exists(path):
            try:
                data[suffix] = pd.read_csv(path)
            except Exception as e:
                print(f"[WARNING] Could not read {path}: {e}")
    return data


# ─── Metric computation ───────────────────────────────────────────────────────

def ci95(values):
    """Return 95% confidence interval half-width using t-distribution."""
    n = len(values)
    if n < 2:
        return 0.0
    if SCIPY_OK:
        return scipy_stats.sem(values) * scipy_stats.t.ppf(0.975, df=n - 1)
    return 1.96 * np.std(values, ddof=1) / math.sqrt(n)


def compute_metrics(model, results_dir):
    """Compute all metrics for one model from its CSV files."""
    data = load_model_results(model, results_dir)
    result = {"model": model}

    # ── Attacker log → detection rates, F1, Balanced Accuracy ──────────────
    if "attacker_log" in data:
        alog = data["attacker_log"]
        alog["detected"] = alog["detected"].str.strip().str.lower()

        # Per-attack-type detection rate
        attack_rates = {}
        for attack in ATTACK_TYPES:
            rows = alog[alog["attack_type"] == attack]
            if len(rows) > 0:
                rate = (rows["detected"] == "yes").sum() / len(rows)
                attack_rates[attack] = round(float(rate), 4)
            else:
                attack_rates[attack] = None

        result["attack_rates"] = attack_rates
        result["overall_detection"] = round(float((alog["detected"] == "yes").mean()), 4)

        # Latency from attacker log
        if "latency_ms" in alog.columns:
            lats = alog["latency_ms"].dropna().values
            result["attacker_latency_mean"] = round(float(np.mean(lats)), 2)
            result["attacker_latency_std"] = round(float(np.std(lats, ddof=1)), 2)

        # Macro-F1 and Balanced Accuracy (treating as 6-class + Normal problem)
        if SKLEARN_OK and "predicted_label" in alog.columns:
            y_true = alog["attack_type"].values
            y_pred = alog["predicted_label"].values
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result["macro_f1"] = round(
                    float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4
                )
                result["balanced_acc"] = round(
                    float(balanced_accuracy_score(y_true, y_pred)), 4
                )
        else:
            # Estimate: mean detection rate as proxy for balanced accuracy
            valid_rates = [v for v in attack_rates.values() if v is not None]
            result["macro_f1"] = round(float(np.mean(valid_rates)), 4) if valid_rates else None
            result["balanced_acc"] = result["macro_f1"]
    else:
        result["attack_rates"] = {a: None for a in ATTACK_TYPES}
        result["overall_detection"] = None

    # ── Sensor log → false positive rate ────────────────────────────────────
    if "sensor_log" in data:
        slog = data["sensor_log"]
        slog["is_attack"] = slog["is_attack"].str.strip().str.lower()
        n = len(slog)
        fps = (slog["is_attack"] == "yes").sum()
        result["fpr"] = round(float(fps / n), 4) if n > 0 else None
        result["n_sensor_rows"] = n

        # False positive CI
        if n > 0:
            p = result["fpr"]
            result["fpr_ci95"] = round(1.96 * math.sqrt(p * (1 - p) / n), 4)
    else:
        result["fpr"] = None

    # ── Metrics CSV → latency, CPU, RAM ─────────────────────────────────────
    if "metrics" in data:
        mdf = data["metrics"]
        if "latency_ms" in mdf.columns:
            lats = mdf["latency_ms"].dropna().values
            result["latency_mean"] = round(float(np.mean(lats)), 2)
            result["latency_std"] = round(float(np.std(lats, ddof=1)), 2)
            result["latency_ci95"] = round(float(ci95(lats)), 2)
        if "cpu_percent" in mdf.columns:
            cpus = mdf["cpu_percent"].dropna().values
            result["cpu_mean"] = round(float(np.mean(cpus)), 1)
            result["cpu_std"] = round(float(np.std(cpus, ddof=1)), 1)
        if "memory_mb" in mdf.columns:
            rams = mdf["memory_mb"].dropna().values
            result["ram_mean"] = round(float(np.mean(rams)), 1)
            result["ram_std"] = round(float(np.std(rams, ddof=1)), 1)
        result["n_total_requests"] = len(mdf)

    return result


# ─── Summary table ────────────────────────────────────────────────────────────

def build_summary(constrained, baseline=None):
    rows = []
    for model in MODELS:
        c = constrained.get(model, {})
        b = baseline.get(model, {}) if baseline else {}

        row = {
            "Model": model,
            "Overall Detection (%)": f"{c.get('overall_detection', 0)*100:.1f}" if c.get("overall_detection") is not None else "—",
            "Macro-F1": f"{c.get('macro_f1', 0):.4f}" if c.get("macro_f1") is not None else "—",
            "Balanced Acc": f"{c.get('balanced_acc', 0):.4f}" if c.get("balanced_acc") is not None else "—",
            "FPR (%)": f"{c.get('fpr', 0)*100:.2f}" if c.get("fpr") is not None else "—",
            "Latency mean±std (ms)": (
                f"{c.get('latency_mean', 0):.1f}±{c.get('latency_std', 0):.1f}"
                if c.get("latency_mean") is not None else "—"
            ),
            "CPU mean±std (%)": (
                f"{c.get('cpu_mean', 0):.1f}±{c.get('cpu_std', 0):.1f}"
                if c.get("cpu_mean") is not None else "—"
            ),
            "RAM mean±std (MB)": (
                f"{c.get('ram_mean', 0):.1f}±{c.get('ram_std', 0):.1f}"
                if c.get("ram_mean") is not None else "—"
            ),
        }

        if b:
            blatency = b.get("latency_mean")
            clatency = c.get("latency_mean")
            if blatency and clatency:
                delta = clatency - blatency
                row["Baseline Latency (ms)"] = f"{blatency:.1f}"
                row["Latency Delta (ms)"] = f"+{delta:.1f}" if delta >= 0 else f"{delta:.1f}"
            row["Baseline RAM (MB)"] = f"{b.get('ram_mean', 0):.1f}" if b.get("ram_mean") else "—"

        rows.append(row)

    return pd.DataFrame(rows)


# ─── NIS2 compliance table ────────────────────────────────────────────────────

def print_nis2_table(constrained):
    print("\n" + "=" * 80)
    print("NIS2 COMPLIANCE TABLE")
    print("=" * 80)
    header = f"{'Attack Type':<18} {'STRIDE':<25} {'NIS2 Article':<15} {'Best Detection':<16} {'Best Model':<10} {'Compliant'}"
    print(header)
    print("-" * 80)

    for attack in ATTACK_TYPES:
        stride, article, _ = NIS2_MAP[attack]
        rates = {}
        for model in MODELS:
            c = constrained.get(model, {})
            rate = c.get("attack_rates", {}).get(attack)
            if rate is not None:
                rates[model] = rate

        if rates:
            best_model = max(rates, key=rates.get)
            best_rate = rates[best_model]
            compliant = "YES" if best_rate >= NIS2_THRESHOLD else "NO (< 80%)"
            print(
                f"{attack:<18} {stride:<25} {article:<15} "
                f"{best_rate*100:>5.1f}% ({MODEL_LABELS[best_model]:<4})  {compliant}"
            )
        else:
            print(f"{attack:<18} {stride:<25} {article:<15} {'N/A':<16} {'—':<10} —")

    print("-" * 80)
    print(f"Compliance threshold: ≥ {int(NIS2_THRESHOLD*100)}% detection rate (consistent with Ferrag et al. 2022)")
    print("→ Place this table in Section 5 (Discussion / NIS2 Compliance Assessment)\n")


# ─── Plots ────────────────────────────────────────────────────────────────────

def ieee_style():
    """Apply IEEE-style plot settings."""
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": 150,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })


def plot_detection_rates(constrained, out_path):
    """Fig 1: Grouped bar chart — detection rate per attack type per model."""
    ieee_style()

    available_models = [m for m in MODELS if m in constrained]
    n_attacks = len(ATTACK_TYPES)
    n_models = len(available_models)
    bar_width = 0.8 / n_models
    x = np.arange(n_attacks)
    colors = plt.cm.tab10(np.linspace(0, 0.9, n_models))

    fig, ax = plt.subplots(figsize=(10, 5))

    for i, model in enumerate(available_models):
        rates = []
        for attack in ATTACK_TYPES:
            r = constrained[model].get("attack_rates", {}).get(attack)
            rates.append((r or 0) * 100)
        offset = (i - n_models / 2 + 0.5) * bar_width
        bars = ax.bar(x + offset, rates, bar_width, label=MODEL_LABELS[model],
                      color=colors[i], edgecolor="white", linewidth=0.5)

    # 80% NIS2 compliance line
    ax.axhline(80, color="red", linestyle="--", linewidth=1.0, label="80% NIS2 threshold")

    ax.set_xticks(x)
    ax.set_xticklabels(ATTACK_TYPES, rotation=20, ha="right")
    ax.set_ylabel("Detection Rate (%)")
    ax.set_ylim(0, 110)
    ax.set_title("Detection Rate per Attack Type — Constrained Deployment (Raspberry Pi 4)")
    ax.legend(loc="upper right", ncol=3, framealpha=0.9)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%d%%"))

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_latency_vs_f1(constrained, baseline, out_path):
    """Fig 2: Scatter plot — Macro-F1 vs mean latency, constrained vs baseline."""
    ieee_style()
    fig, ax = plt.subplots(figsize=(7, 5))
    colors = plt.cm.tab10(np.linspace(0, 0.9, len(MODELS)))

    for i, model in enumerate(MODELS):
        c = constrained.get(model, {})
        b = baseline.get(model, {}) if baseline else {}

        c_lat = c.get("latency_mean")
        c_f1 = c.get("macro_f1")
        b_lat = b.get("latency_mean") if b else None
        b_f1 = b.get("macro_f1") if b else None

        label = MODEL_LABELS[model]
        color = colors[i]

        if c_lat and c_f1:
            ax.scatter(c_lat, c_f1, color=color, marker="o", s=80, zorder=3,
                       label=f"{label} (constrained)")
            ax.annotate(label, (c_lat, c_f1), textcoords="offset points",
                        xytext=(5, 3), fontsize=8, color=color)

        if b_lat and b_f1:
            ax.scatter(b_lat, b_f1, color=color, marker="s", s=60, alpha=0.6, zorder=3,
                       label=f"{label} (baseline)")
            if c_lat and c_f1:
                ax.annotate("", xy=(c_lat, c_f1), xytext=(b_lat, b_f1),
                            arrowprops=dict(arrowstyle="->", color=color, alpha=0.4, lw=1.0))

    ax.set_xlabel("Mean Inference Latency (ms)")
    ax.set_ylabel("Macro-F1 Score")
    ax.set_title("Detection Quality vs. Inference Latency\n(● constrained  ■ baseline)")
    ax.set_ylim(0, 1.05)

    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker="o", color="gray", label="Constrained (Pi 4)", linestyle="None", markersize=8),
        Line2D([0], [0], marker="s", color="gray", label="Baseline (no limits)", linestyle="None", markersize=8, alpha=0.6),
    ]
    ax.legend(handles=legend_elements, loc="lower right", framealpha=0.9)

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_resource_usage(constrained, baseline, out_path):
    """Fig 3: Grouped bar chart — mean CPU% and RAM per model."""
    ieee_style()
    available_models = [m for m in MODELS if m in constrained]
    labels = [MODEL_LABELS[m] for m in available_models]
    x = np.arange(len(available_models))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    # CPU usage
    c_cpu = [constrained[m].get("cpu_mean", 0) for m in available_models]
    c_cpu_std = [constrained[m].get("cpu_std", 0) for m in available_models]

    if baseline:
        b_cpu = [baseline.get(m, {}).get("cpu_mean", 0) for m in available_models]
        b_cpu_std = [baseline.get(m, {}).get("cpu_std", 0) for m in available_models]
        ax1.bar(x - 0.2, b_cpu, 0.38, label="Baseline", color="#9ecae1",
                yerr=b_cpu_std, capsize=3, error_kw={"linewidth": 0.8})
        ax1.bar(x + 0.2, c_cpu, 0.38, label="Constrained", color="#3182bd",
                yerr=c_cpu_std, capsize=3, error_kw={"linewidth": 0.8})
    else:
        ax1.bar(x, c_cpu, 0.6, label="Constrained", color="#3182bd",
                yerr=c_cpu_std, capsize=3, error_kw={"linewidth": 0.8})

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("Mean CPU Usage (%)")
    ax1.set_title("CPU Usage per Model")
    ax1.axhline(100, color="red", linestyle="--", linewidth=0.8, label="Pi 4 limit (1 core)")
    ax1.legend(framealpha=0.9)

    # RAM usage
    c_ram = [constrained[m].get("ram_mean", 0) for m in available_models]
    c_ram_std = [constrained[m].get("ram_std", 0) for m in available_models]

    if baseline:
        b_ram = [baseline.get(m, {}).get("ram_mean", 0) for m in available_models]
        b_ram_std = [baseline.get(m, {}).get("ram_std", 0) for m in available_models]
        ax2.bar(x - 0.2, b_ram, 0.38, label="Baseline", color="#a1d99b",
                yerr=b_ram_std, capsize=3, error_kw={"linewidth": 0.8})
        ax2.bar(x + 0.2, c_ram, 0.38, label="Constrained", color="#31a354",
                yerr=c_ram_std, capsize=3, error_kw={"linewidth": 0.8})
    else:
        ax2.bar(x, c_ram, 0.6, label="Constrained", color="#31a354",
                yerr=c_ram_std, capsize=3, error_kw={"linewidth": 0.8})

    ax2.set_xticks(x)
    ax2.set_xticklabels(labels)
    ax2.set_ylabel("Mean RAM Usage (MB)")
    ax2.set_title("RAM Usage per Model")
    ax2.axhline(512, color="red", linestyle="--", linewidth=0.8, label="Pi 4 limit (512MB)")
    ax2.legend(framealpha=0.9)

    fig.suptitle("Resource Usage — Constrained vs. Baseline Deployment", fontsize=12)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


# ─── Thesis placement guide ───────────────────────────────────────────────────

def print_thesis_guide(has_baseline):
    print("\n" + "=" * 80)
    print("THESIS PLACEMENT GUIDE")
    print("=" * 80)
    print("""
Table (Results section):
  Copy: results/summary_table.csv
  → Thesis location: Section 4, Table X: "Model Performance Under Deployment"
  → Columns to use: Model | Macro-F1 | Balanced Acc | FPR | Latency mean±std |
                    CPU mean±std | RAM mean±std""")
    if has_baseline:
        print("                    | Baseline Latency | Latency Delta")
    print("""
Figure 1 — Detection Rates by Attack Type:
  File: results/plots/fig1_detection_rates.png
  → Thesis location: Section 4.2 (Detection Performance per Attack Type)
  → Caption: "Detection rate per attack type for all six models under
    Raspberry Pi 4 hardware constraints. Red dashed line = 80% NIS2 threshold."
  → Answers: RQ1 (which models detect IoT attacks?)

Figure 2 — Latency vs. Detection Quality:
  File: results/plots/fig2_latency_vs_f1.png
  → Thesis location: Section 4.3 (Resource Constraint Impact)
  → Caption: "Trade-off between inference latency and Macro-F1 for constrained
    and baseline deployments. Arrows show degradation from baseline to constrained."
  → Answers: RQ2 (which models remain viable under Pi 4 constraints?)

Figure 3 — Resource Usage per Model:
  File: results/plots/fig3_resource_usage.png
  → Thesis location: Section 4.3 (Resource Constraint Impact)
  → Caption: "Mean CPU and RAM usage per model. Dashed red lines = Pi 4 limits
    (100% single-core CPU, 512MB RAM). Error bars = standard deviation."
  → Answers: RQ2 (feasibility under hardware limits)

NIS2 Table (above):
  → Thesis location: Section 5 (Discussion / NIS2 Compliance Assessment)
  → Caption: "NIS2 Article 21 compliance assessment based on constrained
    deployment detection rates. Threshold: ≥ 80%."
  → Answers: RQ3 (do results satisfy NIS2 requirements?)

Statistical justification sentence (add to methodology):
  "Results are reported as mean ± standard deviation across all predictions
   recorded during the experiment run. A 95% confidence interval is computed
   using the t-distribution (scipy.stats.t) to characterise result reliability,
   consistent with the approach used by Diab et al. (2024) and Ferrag et al. (2022)."
""")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("IDS Experiment Results Analysis")
    print("=" * 60)

    # Check for results
    if not os.path.isdir(RESULTS_DIR):
        print(f"[ERROR] Results directory '{RESULTS_DIR}' not found.")
        print("        Run: bash run_experiments.sh 120")
        sys.exit(1)

    has_baseline = os.path.isdir(BASELINE_DIR) and any(
        f.endswith("_metrics.csv") for f in os.listdir(BASELINE_DIR)
    )

    # Load constrained results
    constrained = {}
    for model in MODELS:
        metrics_path = os.path.join(RESULTS_DIR, f"{model}_metrics.csv")
        if not os.path.exists(metrics_path):
            print(f"[SKIP] No constrained results for {model}")
            continue
        print(f"[LOAD] Constrained: {model}")
        constrained[model] = compute_metrics(model, RESULTS_DIR)

    # Load baseline results
    baseline = {}
    if has_baseline:
        print(f"\n[INFO] Baseline results found in {BASELINE_DIR}")
        for model in MODELS:
            metrics_path = os.path.join(BASELINE_DIR, f"{model}_metrics.csv")
            if not os.path.exists(metrics_path):
                continue
            print(f"[LOAD] Baseline: {model}")
            baseline[model] = compute_metrics(model, BASELINE_DIR)
    else:
        print("\n[INFO] No baseline results found. Run: bash run_experiments.sh --baseline 120")

    if not constrained:
        print("[ERROR] No constrained results loaded. Cannot produce analysis.")
        sys.exit(1)

    # Summary table
    df = build_summary(constrained, baseline if has_baseline else None)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary_path = os.path.join(RESULTS_DIR, "summary_table.csv")
    df.to_csv(summary_path, index=False)

    print("\n" + "=" * 80)
    print("SUMMARY TABLE — All Models")
    print("=" * 80)
    print(df.to_string(index=False))
    print(f"\nSaved: {summary_path}")

    # Per-attack detection detail
    print("\n" + "=" * 80)
    print("DETECTION RATES PER ATTACK TYPE (%)")
    print("=" * 80)
    header = f"{'Model':<22}" + "".join(f"{a[:12]:<14}" for a in ATTACK_TYPES)
    print(header)
    print("-" * (22 + 14 * len(ATTACK_TYPES)))
    for model in MODELS:
        if model not in constrained:
            continue
        rates = constrained[model].get("attack_rates", {})
        row = f"{model:<22}"
        for attack in ATTACK_TYPES:
            r = rates.get(attack)
            row += f"{r*100:>6.1f}%       " if r is not None else f"{'N/A':<14}"
        print(row)

    # Latency confidence intervals
    print("\n" + "=" * 80)
    print("LATENCY 95% CONFIDENCE INTERVALS (ms)")
    print("=" * 80)
    for model in MODELS:
        if model not in constrained:
            continue
        c = constrained[model]
        mean = c.get("latency_mean", "—")
        ci = c.get("latency_ci95", "—")
        print(f"  {model:<25}  {mean} ± {ci} ms (95% CI)")

    # NIS2 table
    print_nis2_table(constrained)

    # Plots
    if MATPLOTLIB_OK:
        os.makedirs(PLOTS_DIR, exist_ok=True)
        print("\nGenerating plots...")

        plot_detection_rates(
            constrained,
            os.path.join(PLOTS_DIR, "fig1_detection_rates.png")
        )
        plot_latency_vs_f1(
            constrained,
            baseline if has_baseline else {},
            os.path.join(PLOTS_DIR, "fig2_latency_vs_f1.png")
        )
        plot_resource_usage(
            constrained,
            baseline if has_baseline else {},
            os.path.join(PLOTS_DIR, "fig3_resource_usage.png")
        )
    else:
        print("\n[SKIP] Plots skipped — install matplotlib: pip install matplotlib")

    # Thesis guide
    print_thesis_guide(has_baseline)


if __name__ == "__main__":
    main()
