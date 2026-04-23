#!/bin/bash
# Run the IDS experiment for each trained model sequentially.
# Results saved to results/<model>_*.csv (constrained) or results/baseline/<model>_*.csv (baseline).
#
# Usage:
#   bash run_experiments.sh [duration_seconds]            # constrained run (Pi 4 limits)
#   bash run_experiments.sh --baseline [duration_seconds] # baseline run (no limits)

set -e

BASELINE=false
DURATION=120

# Parse arguments
for arg in "$@"; do
    if [ "$arg" = "--baseline" ]; then
        BASELINE=true
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        DURATION="$arg"
    fi
done

MODELS=(
    "Random_Forest:pkl"
    "Decision_Tree:pkl"
    "Logistic_Regression:pkl"
    "Naive_Bayes:pkl"
    "ANN:keras"
    "CNN:keras"
)

mkdir -p results

if [ "$BASELINE" = true ]; then
    COMPOSE_FILE="docker-compose.baseline.yml"
    RESULTS_LABEL="BASELINE (unconstrained)"
    mkdir -p results/baseline
else
    COMPOSE_FILE="docker-compose.yml"
    RESULTS_LABEL="CONSTRAINED (Pi 4: 1 CPU, 512MB RAM, 50ms network delay)"
fi

echo ""
echo "========================================"
echo " Mode: $RESULTS_LABEL"
echo " Duration per model: ${DURATION}s"
echo " Compose file: $COMPOSE_FILE"
echo "========================================"

for ENTRY in "${MODELS[@]}"; do
    MODEL="${ENTRY%%:*}"
    EXT="${ENTRY##*:}"
    MODEL_FILE="models/${MODEL}.${EXT}"

    if [ ! -f "$MODEL_FILE" ]; then
        echo "[SKIP] $MODEL_FILE not found, skipping."
        continue
    fi

    echo ""
    echo "========================================"
    echo " Experiment: $MODEL  (${DURATION}s)"
    echo "========================================"

    echo "Building and starting containers (this may take a few minutes on first run)..."
    MODEL_NAME=$MODEL \
    MODEL_PATH="/app/models/${MODEL}.${EXT}" \
    docker-compose -f "$COMPOSE_FILE" up --build -d

    echo "Waiting for gateway to be ready..."
    for i in $(seq 1 60); do
        if curl -sf http://localhost:5000/health > /dev/null 2>&1; then
            echo "Gateway ready. Collecting data for ${DURATION}s..."
            break
        fi
        sleep 3
        echo "  waiting... (${i}/60)"
    done

    sleep "$DURATION"

    docker-compose -f "$COMPOSE_FILE" down

    # Move baseline results into results/baseline/
    if [ "$BASELINE" = true ]; then
        for suffix in metrics attacker_log sensor_log; do
            SRC="results/${MODEL}_${suffix}.csv"
            DST="results/baseline/${MODEL}_${suffix}.csv"
            if [ -f "$SRC" ]; then
                mv "$SRC" "$DST"
                echo "Saved: $DST"
            fi
        done
    else
        echo "Saved: results/${MODEL}_*.csv"
    fi
done

echo ""
echo "All experiments complete."
if [ "$BASELINE" = true ]; then
    ls -lh results/baseline/ 2>/dev/null || echo "(no baseline results)"
else
    ls -lh results/*.csv 2>/dev/null || echo "(no constrained results)"
fi
