# Automated Detection of Noisy Neighbors in Multi-Tenant SaaS Platforms

**An AIOps Pipeline for Fast and Accurate Detection and Attribution of Resource Anomalies**

## 📋 Overview

This project develops an **AIOps pipeline** for detecting and attributing "noisy neighbors"—tenants that consume disproportionate resources in multi-tenant SaaS platforms. The pipeline combines **system metrics (CPU)** with **application logs (per-tenant request counts)** to quickly identify which tenant is causing performance degradation.

### ✨ Key Results

- **Detection Performance**: 100% precision, 49.1% recall (F1: 65.8%)
- **Attribution Accuracy**: **66.7%** (4/6 attack windows correct)
  - With persistent attack tracking: **7.3× better than random** (9.1%)
  - **4.7× better than correlation-based** (14.3%)
  - **Exceeds 50% operational target** ✅
- **Processing Speed**: <2 seconds per dataset (2000 samples)
- **Architecture**: Simple, interpretable heuristics (no complex ML models)

### Key Features

- **Two-step detection pipeline**: Anomaly detection (Isolation Forest) → Multi-signal attribution
- **Novel innovation**: Persistent attack tracking across temporal windows
- **Multiple baselines**: Metrics-only, Logs-only, Correlation-based approaches
- **Reproducible dataset**: EDGAR-calibrated workload generation
- **Production-ready**: Containerized, low-latency, explainable decisions
- **Comprehensive evaluation**: Precision, Recall, F1-Score, Attribution Accuracy

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Multi-Tenant SaaS Platform              │
└─────────────────────────────────────────────────────────────┘
              ↓
    ┌─────────────────────┐
    │   Flask App         │  (Instrumented with tenant IDs)
    │  (5 readers         │  → Collects telemetry
    │   5 processors      │  → Enforces rate limiting
    │   1 attacker)       │
    └─────────────────────┘
              ↓
    ┌─────────────────────┐
    │   Telemetry CSV     │  (Timestamp, CPU, per-tenant counts, RL hits)
    │   + Replay Plan     │  (Ground truth: attacker start/end times)
    └─────────────────────┘
              ↓
    ┌─────────────────────┐
    │   Analysis Pipeline │  (Aggregation → Detection → Attribution)
    └─────────────────────┘
              ↓
    ┌─────────────────────┐
    │   Labeled Output    │  (Per-window: CPU, tenant blame, accuracy)
    │   + Visualizations  │
    └─────────────────────┘
```

---

## 📁 Project Structure

```
noisy-neighbors-detection/
├── README.md                          # This file
├── docker-compose.yml                 # Multi-container orchestration
│
├── app/                               # Target Flask application
│   ├── app.py                         # REST API with tenant tracking
│   ├── Dockerfile                     # Container image
│   └── requirements.txt               # Dependencies (psutil, flask)
│
├── scripts/                           # Analysis and data generation
│   ├── load_generator.py              # Simulates multi-tenant workload
│   ├── analysis.py                    # Main analysis pipeline (detection + attribution)
│   ├── preprocess_edgar.py            # Preprocessing for EDGAR logs
│   ├── monitor_local.py               # Local monitoring utility (optional)
│   ├── replay_plan.json               # Generated: attack schedule
│   └── edgar_data/                    # EDGAR csv files
│
├── monitoring/                        # Prometheus configuration
│   └── prometheus.yml                 # Metrics scrape config
│
├── telemetry.csv                      # Generated: raw per-second metrics
├── telemetry_labeled.csv              # Generated: windowed + labeled data
├── replay_plan.json                   # Generated: attack events
│
└── *.png                              # Generated: visualization plots
    ├── final_evidence.png
    ├── tenant_counts_attack_vs_normal.png
    ├── tenant_cpu_correlation.png
    ├── attack_zoom.png
    └── attribution_counts.png
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Docker & Docker Compose**
- **Git**

### 1. Clone and Setup

```bash
git clone https://github.com/tassyla/noisy-neighbors-detection.git
cd noisy-neighbors-detection

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Start the Application

```bash
# Start Flask app + Prometheus in containers
docker-compose up -d

# Verify Flask is running (should return "Hello, World!")
curl http://localhost:5000/

```

### 3. Generate Workload

```bash
# Terminal 1: App is already running from docker-compose

# Terminal 2: Run the load generator (creates telemetry.csv + replay_plan.json)
cd scripts
python load_generator.py

# This simulates:
# - 5 normal readers (/endpoint, low latency)
# - 5 processors (heavy work endpoint)
# - 1 attacker tenant (gradually increases load, then aggressive attack)
# 
# Duration: ~2-3 minutes (configurable)
# Output: telemetry.csv, replay_plan.json
```

### 4. Analyze and Detect

```bash
# Terminal 3: Run the analysis pipeline
cd scripts
python analysis.py

# This:
# 1. Loads telemetry.csv
# 2. Aggregates into WINDOW_S second windows (default: 75s)
# 3. Applies detection via Isolation Forest (contamination=0.35)
# 4. Attributes blame using multi-signal scoring:
#    - z-norm (35%): Statistical outliers
#    - rel-norm (25%): Relative activity increase
#    - cnt-norm (20%): Request volume
#    - baseline-dev (12%): Deviation from history
#    - der-norm (8%): Rate of change
# 5. Applies persistent attack tracking to improve accuracy
# 6. Evaluates against ground truth (replay_plan.json)
# 7. Generates labeled data + visualizations
#
# Output:
# - telemetry_labeled.csv (labeled windows)
# - Console: Detection metrics (Precision: 100%, Recall: 49.1%, F1: 65.8%)
# - Console: Attribution accuracy (66.7% with persistence)
```

### 5. View Results

```bash
# Inspect labeled data
python -c "import pandas as pd; print(pd.read_csv('telemetry_labeled.csv').head(20))"

# Open visualizations
# - final_evidence.png (CPU + RL hits over time)
# - tenant_counts_attack_vs_normal.png (per-tenant distribution)
# - tenant_cpu_correlation.png (correlation heatmap)
# - attack_zoom.png (zoomed time-series around attack)
# - attribution_counts.png (model blame distribution)
```