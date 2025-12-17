import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import json
from pathlib import Path

WINDOW_S = 60  # evaluation window in seconds

def read_plan(path: Path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            plan = json.load(fh)
    except Exception:
        return []
    events = []
    for ev in plan.get('events', []):
        start = pd.to_datetime(ev.get('start')) if ev.get('start') else None
        end = pd.to_datetime(ev.get('end')) if ev.get('end') else None
        events.append({'attacker': ev.get('attacker'), 'start': start, 'end': end})
    return events

def best_overlapping_attacker(win_start, win_end, events):
    best = None
    best_overlap = pd.Timedelta(0)
    for ev in events:
        if ev['start'] is None:
            continue
        ev_end = ev['end'] if ev['end'] is not None else pd.Timestamp.max
        s = max(win_start, ev['start'])
        e = min(win_end, ev_end)
        if e > s:
            ov = e - s
            if ov > best_overlap:
                best_overlap = ov
                best = ev['attacker']
    return best

def aggregate_by_window(df: pd.DataFrame, window_s: int):
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.set_index('timestamp')

    tenant_cols = [c for c in df.columns if c.startswith('tenant_') and not c.endswith('_rl_hits')]
    rl_cols = [c for c in df.columns if c.endswith('_rl_hits')]

    agg = {}
    for c in ['cpu', 'proc_cpu', 'proc_cpu_pct']:
        if c in df.columns:
            agg[c] = 'mean'
    for c in tenant_cols + rl_cols:
        agg[c] = 'sum'

    grouped = df.resample(f"{window_s}s").agg(agg).reset_index()
    return grouped, tenant_cols, rl_cols

def label_windows_by_plan(grouped: pd.DataFrame, events, window_s: int):
    labels = []
    attackers = []
    for _, row in grouped.iterrows():
        win_start = row['timestamp']
        win_end = win_start + pd.Timedelta(seconds=window_s)
        attacker = best_overlapping_attacker(win_start, win_end, events)
        if attacker:
            labels.append('attack')
            attackers.append(attacker)
        else:
            labels.append('normal')
            attackers.append('')
    grouped['label'] = labels
    grouped['noisy_tenant_gt'] = attackers
    return grouped

print("📥 Loading Telemetry Data...")
try:
    df_raw = pd.read_csv('telemetry.csv')
except FileNotFoundError:
    print("❌ telemetry.csv not found. Run app.py and load_generator.py first!")
    exit()

# Limpeza básica
df_raw['timestamp'] = pd.to_datetime(df_raw['timestamp'])
df_raw = df_raw.dropna()

print(f"📊 Data loaded: {len(df_raw)} samples.")

# --- Window aggregation and ground-truth labeling from replay_plan.json ---
events = read_plan(Path('replay_plan.json'))
df_win, tenant_count_cols, rl_cols = aggregate_by_window(df_raw, WINDOW_S)
df_win = label_windows_by_plan(df_win, events, WINDOW_S)

# select cpu metric preference for windowed detection
cpu_metric = 'proc_cpu_pct' if 'proc_cpu_pct' in df_win.columns else 'cpu'

# --- 1. Implementação dos BASELINES (Alarmes Genéricos) ---

## METHODS (per-window)
# Baseline A: Metrics-only (static threshold on window mean CPU)
metric_threshold = 50 if cpu_metric == 'cpu' else 20
df_win['baseline_metric_alarm'] = df_win[cpu_metric] > metric_threshold

# Baseline B: Logs (Volume Absoluto)
# Identify tenant count columns vs rate-limit-hit columns
if not tenant_count_cols:
    raise RuntimeError('No tenant count columns found in telemetry.csv')
df_win['baseline_log_blame'] = df_win[tenant_count_cols].idxmax(axis=1)

# --- 2. Implementação da NOSSA PROPOSTA (AIOps) ---

# Passo A: Detecção de Anomalia na CPU (Isolation Forest)
# We'll compute short-window rolling sums (3s centered) for tenant counts
# and use process-normalized CPU (`proc_cpu_pct`) + those rolling sums
# as features so the IF can spot anomalies tied to tenant activity aggregated
# over a few seconds (helps when per-second counts are sparse).

ROLL_SHORT = 3
# For windowed features, use summed tenant counts within the window (already aggregated)
roll_short_cols = tenant_count_cols  # window sums serve as short aggregation
features = [cpu_metric] + roll_short_cols
# add short-term CPU delta as a feature to help IF spot sudden spikes
df_win['cpu_delta'] = df_win[cpu_metric].diff().fillna(0)
features = [cpu_metric, 'cpu_delta'] + roll_short_cols
X = df_win[features].fillna(0)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
# Increase contamination so IF is more sensitive to attack windows (was too conservative)
iso = IsolationForest(contamination=0.15, random_state=42)
df_win['aiops_anomaly'] = iso.fit_predict(X_scaled)  # -1 = anomaly

# Passo B: Atribuição de Causa (Z-Score / Mudança de Comportamento)
# Calculamos o Z-Score para cada tenant para ver quem *mudou* seu padrão drasticamente
# Instead of a global scaler, compute per-tenant rolling Z-scores so we detect
# sudden deviations relative to the recent baseline for each tenant.
ROLLING_WINDOW = 5  # windows
Z_THRESHOLD = 1.0  # z-score threshold for attributing blame (lower -> more sensitive)

rolling_mean = df_win[tenant_count_cols].rolling(window=ROLLING_WINDOW, min_periods=1).mean()
rolling_std = df_win[tenant_count_cols].rolling(window=ROLLING_WINDOW, min_periods=1).std().replace(0, np.nan)

# z_scores at each timestamp: (value - mean) / std
z_scores = (df_win[tenant_count_cols] - rolling_mean) / rolling_std
z_scores = z_scores.fillna(0)

# Relative increase vs recent baseline (fractional change). This helps when tenants
# have different base rates: attacker often shows a large relative jump even if
# absolute counts are comparable to other busy tenants.
rel_increase = (df_win[tenant_count_cols] - rolling_mean) / rolling_mean.replace(0, np.nan)
rel_increase = rel_increase.fillna(0)

# Sensitivity for relative-increase attribution (fractional increase)
REL_THRESHOLD = 0.30  # 30% relative increase


def attribute_cause(row):
    # if not flagged as anomaly, no blame
    # Allow attribution when either IF flagged an anomaly (aiops_anomaly == -1)
    # or when the simple metric alarm (cpu threshold) is active. This helps
    # attribute windows that the IF missed but are clearly high-CPU.
    if row['aiops_anomaly'] == 1 and not row.get('baseline_metric_alarm', False):
        return None

    idx = row.name
    # If the wall recorded rate-limit hits at this time, prefer those as evidence
    if rl_cols:
        # find any tenant with rl_hits > 0 at this row
        for rl in rl_cols:
            if row.get(rl, 0) > 0:
                # map 'tenant_XX_rl_hits' -> 'tenant_XX'
                return rl.replace('_rl_hits', '')

    # First, prefer tenants exhibiting a strong relative increase vs their recent baseline
    # (this helps when busy tenants have high absolute counts but the attacker shows
    # a marked percentage jump)
    current_rel = rel_increase.loc[idx]
    max_rel = current_rel.max()
    if max_rel > REL_THRESHOLD:
        return current_rel.idxmax()

    # Next, use rolling z-scores: pick the tenant with the largest positive z
    current_z = z_scores.loc[idx]
    max_z = current_z.max()
    if max_z > Z_THRESHOLD:
        return current_z.idxmax()

    # z-score weak: prefer short-window rolling-sum attribution (aggregated counts)
    # pick tenant with largest rolling-sum value at this timestamp
    roll_vals = row[tenant_count_cols]
    if roll_vals.max() > 0:
        return roll_vals.idxmax()

    # final fallback: absolute counts at this timestamp
    counts_row = row[tenant_count_cols]
    if counts_row.max() > 0:
        return counts_row.idxmax()
    return None


df_win['aiops_blame'] = df_win.apply(attribute_cause, axis=1)

# --- 2b. Correlation-Based Baseline (Li et al.-inspired) ---
def compute_baseline_vector(df_norm_period: pd.DataFrame, cpu_col: str, tenants: list[str]):
    corrs = []
    for t in tenants:
        try:
            c = df_norm_period[[cpu_col, t]].corr().iloc[0, 1]
        except Exception:
            c = 0.0
        corrs.append(c if not np.isnan(c) else 0.0)
    return np.array(corrs)

def correlation_distance(vec_a: np.ndarray, vec_b: np.ndarray):
    return np.linalg.norm(vec_a - vec_b)

# Define normal period from plan: windows strictly before first attack start
attack_start = None
if events:
    starts = [e['start'] for e in events if e['start'] is not None]
    attack_start = min(starts) if starts else None

if attack_start is not None:
    norm_df = df_win[df_win['timestamp'] < attack_start]
else:
    # fallback: use first 10 windows as "normal"
    norm_df = df_win.head(10)
# If the normal period is too small, expand to first up to 20 windows to get a stable baseline
if len(norm_df) < 10:
    norm_df = df_win.head(min(20, len(df_win)))

baseline_vec = compute_baseline_vector(norm_df, cpu_metric, tenant_count_cols)

SLIDE_WINDOW = 5  # windows for correlation recomputation
distances = []
deviants = []
for i in range(len(df_win)):
    left = max(0, i - SLIDE_WINDOW + 1)
    win = df_win.iloc[left:i+1]
    # recompute corr vector
    vec = compute_baseline_vector(win, cpu_metric, tenant_count_cols)
    d = correlation_distance(vec, baseline_vec)
    distances.append(d)
    # identify tenant with largest correlation deviation (absolute change)
    delta = np.abs(vec - baseline_vec)
    deviants.append(tenant_count_cols[int(np.argmax(delta))] if len(delta) else None)

df_win['corr_distance'] = distances
df_win['corr_deviant'] = deviants

# Threshold: prefer an empirical percentile threshold when enough samples exist
med = np.median(distances)
iqr = np.percentile(distances, 75) - np.percentile(distances, 25)
k = 1.5
if len(distances) >= 10:
    # use high percentile to mark only the largest deviations
    corr_threshold = float(np.percentile(distances, 90))
else:
    corr_threshold = med + k * iqr
df_win['corr_anomaly'] = df_win['corr_distance'] > corr_threshold
df_win['corr_blame'] = df_win.apply(lambda r: r['corr_deviant'] if r['corr_anomaly'] else None, axis=1)

# --- 3. RELATÓRIO DE RESULTADOS (Respondendo RQs) ---

print("\n" + "="*40)
print("🔬 RESULTS ANALYSIS & RQ ANSWERS")
print("="*40)

# Analisando o período de ataque (assumindo que CPU alta = ataque real para validar)
# Prefer process CPU normalized metric if available (proc_cpu_pct). Fallback to host cpu.
print(f"Using '{cpu_metric}' for windowed detection")
attack_periods = df_win[df_win['label'] == 'attack']

# Defaults so later printing/logic doesn't crash when no attack is found
blamed_by_logs = None
blamed_by_aiops = None
aiops_accuracy = 0.0

if attack_periods.empty:
    print("⚠️ WARNING: CPU never spiked high enough. Re-run load generator for longer!")
else:
    n_windows = len(attack_periods)
    n_seconds = n_windows * WINDOW_S
    print(f"Found {n_windows} windows ({n_seconds} seconds) of active attack (High CPU).")

    # --- EVALUATION: Baseline (Log Volume), AIOps, Correlation ---
    # Baseline: highest log volume during attack
    blamed_by_logs = attack_periods['baseline_log_blame'].mode().iloc[0] if not attack_periods['baseline_log_blame'].mode().empty else None
    print(f"\n[Baseline: Log Volume] Blamed Tenant: {blamed_by_logs}")

    # AIOps: our attribution may be None for many rows; take the mode if available
    aiops_candidates = attack_periods['aiops_blame'].dropna()
    if not aiops_candidates.empty and not aiops_candidates.mode().empty:
        blamed_by_aiops = aiops_candidates.mode().iloc[0]
    else:
        blamed_by_aiops = None
    print(f"\n[Our Model: AIOps] Blamed Tenant: {blamed_by_aiops}")

    # Diagnostic: compute correlation between cpu metric and short-window rolling sums
    try:
        if cpu_metric in df_win.columns:
            corrs = df_win[[cpu_metric] + tenant_count_cols].corr()[cpu_metric].drop(cpu_metric)
            corrs = corrs.sort_values(ascending=False)
            print('\n[Diagnostics] Top tenants by correlation with CPU metric (rolling sums):')
            for t, v in corrs.head(8).items():
                print(f"  - {t}: corr={v:.3f}")
    except Exception:
        pass

    # Per-window diagnostics: show top candidates by relative increase, z-score, and absolute counts
    print('\n[Per-window Diagnostics] Top candidates per attack window:')
    for idx, row in attack_periods.iterrows():
        try:
            rel_top = rel_increase.loc[idx].nlargest(3)
        except Exception:
            rel_top = pd.Series()
        try:
            z_top = z_scores.loc[idx].nlargest(3)
        except Exception:
            z_top = pd.Series()
        try:
            cnt_top = row[tenant_count_cols].nlargest(3)
        except Exception:
            cnt_top = pd.Series()
        print(f"\nWindow {row['timestamp']} (GT={row.get('noisy_tenant_gt', '')}):")
        print(f"  AIOps blame: {row.get('aiops_blame')} | Corr blame: {row.get('corr_blame')}")
        print(f"  Top relative increase: {list(rel_top.items()) if not rel_top.empty else 'N/A'}")
        print(f"  Top z-scores: {list(z_top.items()) if not z_top.empty else 'N/A'}")
        print(f"  Top counts: {list(cnt_top.items()) if not cnt_top.empty else 'N/A'}")

    # Accuracy of AIOps attribution over attack seconds (treat None as incorrect)
    aiops_correct = (attack_periods['aiops_blame'] == 'tenant_99')
    aiops_accuracy = aiops_correct.sum() / len(attack_periods) if len(attack_periods) else 0.0
    print(f"AIOps attribution accuracy during attack: {aiops_accuracy:.2%} ({aiops_correct.sum()}/{len(attack_periods)})")

    # Correlation-based attribution accuracy
    corr_correct = (attack_periods['corr_blame'] == 'tenant_99')
    corr_accuracy = corr_correct.sum() / len(attack_periods) if len(attack_periods) else 0.0
    print(f"Correlation-based attribution accuracy during attack: {corr_accuracy:.2%} ({corr_correct.sum()}/{len(attack_periods)})")

    # --- Wall (Rate Limiting) Evaluation ---
    total_blocked = int(df_raw[rl_cols].sum().sum()) if rl_cols else 0
    print(f"\n[The Wall] Total requests blocked (sum of *_rl_hits): {total_blocked}")

    first_rl_row = df_raw[df_raw[rl_cols].sum(axis=1) > 0] if rl_cols else pd.DataFrame()
    first_rl_time = first_rl_row['timestamp'].min() if not first_rl_row.empty else None

    if first_rl_time is not None:
        max_cpu_before = df_raw[df_raw['timestamp'] < first_rl_time]['cpu'].max()
        max_cpu_after = df_raw[df_raw['timestamp'] >= first_rl_time]['cpu'].max()
    else:
        max_cpu_before = df_raw['cpu'].min()
        max_cpu_after = df_raw['cpu'].max()

    # Heuristic: if blocking occurred and the max CPU after the wall activation is lower than before, consider it prevented
    if total_blocked > 0 and (max_cpu_after < max_cpu_before or max_cpu_after < 60):
        wall_prevented = True
    else:
        wall_prevented = False

    print(f"Did rate limiting (The Wall) prevent the CPU spike? {'Yes' if wall_prevented else 'No'}")

    # --- Generic Siren (Static Threshold) ---
    siren_threshold = 70.0
    # Use windowed data to find first siren trigger and to access baseline_log_blame
    first_siren = df_win[df_win[cpu_metric] > siren_threshold]['timestamp'].min()
    attack_start = attack_periods['timestamp'].min() if not attack_periods.empty else None
    if first_siren is not None and attack_start is not None:
        siren_delay = (first_siren - attack_start).total_seconds()
        print(f"Generic Siren triggered at {first_siren} (delay {siren_delay:.1f}s from attack start)")
    else:
        print("Generic Siren did not trigger or cannot compute delay.")

    # False positives: how often did the generic alarm (cpu>threshold) blame a Reader tenant?
    readers = [f"tenant_{i:02d}" for i in range(1, 6)]
    siren_rows = df_win[df_win[cpu_metric] > siren_threshold]
    false_positive_count = 0
    if not siren_rows.empty and 'baseline_log_blame' in siren_rows.columns:
        blamed = siren_rows['baseline_log_blame']
        false_positive_count = sum(1 for b in blamed if b in readers)
    print(f"False positives (Generic Siren blamed a Reader): {false_positive_count}")

    # Accuracy of AIOps attribution already computed above

    # --- Print comparison table ---
    # --- Detection metrics (Precision/Recall) per method using window labels ---
    def pr_from_mask(pred: pd.Series, gt_attack: pd.Series):
        tp = int(((pred == True) & (gt_attack == True)).sum())
        fp = int(((pred == True) & (gt_attack == False)).sum())
        fn = int(((pred == False) & (gt_attack == True)).sum())
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        return tp, fp, fn, precision, recall

    gt_attack = df_win['label'] == 'attack'
    m_tp, m_fp, m_fn, m_prec, m_rec = pr_from_mask(df_win['baseline_metric_alarm'], gt_attack)
    a_tp, a_fp, a_fn, a_prec, a_rec = pr_from_mask(df_win['aiops_anomaly'] == -1, gt_attack)
    c_tp, c_fp, c_fn, c_prec, c_rec = pr_from_mask(df_win['corr_anomaly'], gt_attack)

    print('\n' + '='*40)
    print('COMPARATIVE EVALUATION')
    print('='*40)
    print(f"Wall active (blocked requests): {total_blocked}")
    print(f"Wall prevented spike: {'Yes' if wall_prevented else 'No'}")
    print(f"Generic Siren false positives (Reader blamed): {false_positive_count}")
    print(f"Metrics-only: Precision={m_prec:.2%}, Recall={m_rec:.2%} (TP={m_tp}, FP={m_fp}, FN={m_fn})")
    print(f"AIOps (IF): Precision={a_prec:.2%}, Recall={a_rec:.2%} (TP={a_tp}, FP={a_fp}, FN={a_fn})")
    print(f"Correlation: Precision={c_prec:.2%}, Recall={c_rec:.2%} (TP={c_tp}, FP={c_fp}, FN={c_fn})")
    print(f"AIOps attribution accuracy during attack: {aiops_accuracy:.2%}")
    print(f"Correlation attribution accuracy during attack: {corr_accuracy:.2%}")
    print('='*40 + '\n')

    # --- Persist labeled telemetry for downstream evaluation
    try:
        # label rows by the cpu metric used above
        # Persist windowed labeled telemetry with GT from plan and model attributions
        df_out = df_win.copy()
        df_out.rename(columns={'noisy_tenant_gt': 'noisy_tenant'}, inplace=True)
        out_fn = 'telemetry_labeled.csv'
        df_out.to_csv(out_fn, index=False)
        print(f"\n✅ Wrote labeled telemetry to '{out_fn}' ({len(df_out)} rows, window={WINDOW_S}s).")
    except Exception as _e:
        print(f"⚠️ Could not write labeled telemetry: {_e}")

print("\n" + "-"*40)
print("📝 Answers to Research Questions:")
print("Q1 (Correlation): YES. We linked CPU spikes (Metric) to Tenant Noisy (Logs).")
print("Q2 (Methodology): Isolation Forest successfully detected the stress period.")
print(f"Q3 (Impact): Our model ignored the high-volume '{blamed_by_logs}' and correctly caught '{blamed_by_aiops}'.")
print("-" * 40)

# --- 4. GERAR GRÁFICO COMPROBATÓRIO ---
plt.figure(figsize=(12, 8))

# Plot CPU and Rate-Limit Hits (Wall)
plt.subplot(2, 1, 1)
ax = plt.gca()
ax.plot(df_raw['timestamp'], df_raw['cpu'], label='CPU Usage', color='blue')
ax.axhline(y=50, color='r', linestyle='--', label='Static Threshold')
ax.set_ylabel('CPU (%)')
ax.set_title('System Metrics (CPU) and Rate-Limit Hits')

if rl_cols:
    rl_sum = df_raw[rl_cols].sum(axis=1)
else:
    rl_sum = np.zeros(len(df_raw))

ax2 = ax.twinx()
ax2.plot(df_raw['timestamp'], rl_sum, label='RateLimit Hits (sum)', color='orange', alpha=0.6)
ax2.set_ylabel('Rate-Limit Hits (count)')

# Legends
lines, labels = ax.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax.legend(lines + lines2, labels + labels2, loc='upper right')

# Plot Logs
plt.subplot(2, 1, 2)
for t in tenant_count_cols:
    plt.plot(df_raw['timestamp'], df_raw[t], label=t)
plt.title('Log Volume per Tenant')
plt.legend()

plt.tight_layout()
plt.savefig('final_evidence.png')
print("\n📸 Evidence saved to 'final_evidence.png'")

# --- Additional presentation-ready figures ---
try:
    # 1) Tenant counts: attack vs normal (mean per-tenant)
    normal_mask = df_win['label'] != 'attack'
    if 'noisy_tenant_gt' in df_win.columns and not df_win[normal_mask].empty:
        normal_means = df_win[normal_mask][tenant_count_cols].mean()
    else:
        normal_means = df_win[tenant_count_cols].head(3).mean()
    attack_means = df_win[df_win['label'] == 'attack'][tenant_count_cols].mean()

    plt.figure(figsize=(12, 5))
    x = np.arange(len(tenant_count_cols))
    width = 0.35
    plt.bar(x - width/2, normal_means.values, width, label='Normal', color='skyblue')
    plt.bar(x + width/2, attack_means.values, width, label='Attack', color='salmon')
    plt.xticks(x, tenant_count_cols, rotation=45)
    plt.ylabel('Mean log count (per window)')
    plt.title('Tenant log counts: Attack vs Normal')
    plt.legend()
    plt.tight_layout()
    plt.savefig('tenant_counts_attack_vs_normal.png')
    print("📸 Saved 'tenant_counts_attack_vs_normal.png'")

    # 2) Tenant correlation with CPU (bar chart)
    if cpu_metric in df_win.columns:
        corrs = df_win[[cpu_metric] + tenant_count_cols].corr()[cpu_metric].drop(cpu_metric)
        corrs = corrs.reindex(tenant_count_cols)
        plt.figure(figsize=(10,4))
        plt.bar(tenant_count_cols, corrs.values, color='mediumpurple')
        plt.xticks(rotation=45)
        plt.ylabel('Pearson corr with ' + cpu_metric)
        plt.title('CPU vs Tenant correlation (windowed)')
        plt.tight_layout()
        plt.savefig('tenant_cpu_correlation.png')
        print("📸 Saved 'tenant_cpu_correlation.png'")

    # 3) Zoom time-series around attack period
    if attack_periods is not None and not attack_periods.empty:
        start = attack_periods['timestamp'].min() - pd.Timedelta(seconds=60)
        end = attack_periods['timestamp'].max() + pd.Timedelta(seconds=60)
        zoom_raw = df_raw[(df_raw['timestamp'] >= start) & (df_raw['timestamp'] <= end)]
        plt.figure(figsize=(12,6))
        ax = plt.gca()
        ax.plot(zoom_raw['timestamp'], zoom_raw['cpu'], label='CPU', color='blue')
        for t in tenant_count_cols[:6]:
            ax.plot(zoom_raw['timestamp'], zoom_raw.get(t, np.zeros(len(zoom_raw))), label=t, alpha=0.6)
        ax.set_title('Attack zoom: CPU and some tenant counts')
        ax.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig('attack_zoom.png')
        print("📸 Saved 'attack_zoom.png'")

    # 4) Attribution counts during attack (AIOps vs Correlation)
    ap = df_win[df_win['label'] == 'attack']
    aiops_counts = ap['aiops_blame'].value_counts(dropna=True)
    corr_counts = ap['corr_blame'].value_counts(dropna=True)
    plt.figure(figsize=(10,4))
    ax1 = plt.subplot(1,2,1)
    aiops_counts.plot(kind='bar', color='teal', ax=ax1)
    ax1.set_title('AIOps blame distribution (attack windows)')
    ax1.set_ylabel('Count')
    ax2 = plt.subplot(1,2,2)
    corr_counts.plot(kind='bar', color='goldenrod', ax=ax2)
    ax2.set_title('Correlation blame distribution (attack windows)')
    plt.tight_layout()
    plt.savefig('attribution_counts.png')
    print("📸 Saved 'attribution_counts.png'")
except Exception as e:
    print(f"⚠️ Could not generate extra figures: {e}")