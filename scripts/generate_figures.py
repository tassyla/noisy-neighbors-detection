#!/usr/bin/env python3
"""
generate_figures.py - High-quality figure generation for IEEE report

Generates 4 publication-quality figures from analysis results:
1. Detection Timeline - Shows anomaly detections vs ground truth
2. Correlation Comparison - Normal vs Attack period correlations
3. Attribution Confusion Matrix - Predicted vs True attacker
4. Method Comparison - Bar chart comparing all methods

Usage:
    python generate_figures.py --input results/run_20251219_084255/analysis_filtered2.csv/telemetry_labeled.csv
    python generate_figures.py --input results/run_20251219_084255/analysis_filtered2.csv/telemetry_labeled.csv --output-dir figures/
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json
from pathlib import Path
import argparse
from sklearn.metrics import confusion_matrix
import sys

# Fix emoji rendering on Windows (cp1252 -> UTF-8)
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# Set publication-quality plot style
plt.style.use('seaborn-v0_8-paper')
plt.rcParams['figure.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9


def parse_args():
    parser = argparse.ArgumentParser(description="Generate publication-quality figures")
    parser.add_argument("--input", required=True, help="Path to telemetry_labeled.csv")
    parser.add_argument("--output-dir", default=".", help="Output directory for figures")
    parser.add_argument("--window", type=int, default=75, help="Window size used in analysis")
    return parser.parse_args()


def read_replay_plan(base_dir):
    """Read ground truth attack events from replay_plan.json"""
    plan_path = base_dir / 'replay_plan.json'
    if not plan_path.exists():
        # Try parent directories
        for parent in [base_dir.parent, base_dir.parent.parent, base_dir.parent.parent.parent]:
            plan_path = parent / 'replay_plan.json'
            if plan_path.exists():
                break
    
    if not plan_path.exists():
        print(f"⚠️ Warning: replay_plan.json not found, skipping ground truth visualization")
        return []
    
    try:
        with open(plan_path, 'r', encoding='utf-8') as f:
            plan = json.load(f)
        events = []
        for ev in plan.get('events', []):
            start = pd.to_datetime(ev.get('start')) if ev.get('start') else None
            end = pd.to_datetime(ev.get('end')) if ev.get('end') else None
            events.append({'attacker': ev.get('attacker'), 'start': start, 'end': end})
        return events
    except Exception as e:
        print(f"⚠️ Error reading replay_plan.json: {e}")
        return []


def figure1_detection_timeline(df, events, window_s, output_path):
    """
    Figure 1: Detection Timeline
    Shows CPU utilization over time with detected anomalies (red) and ground truth (yellow)
    """
    print("📊 Generating Figure 1: Detection Timeline...")
    
    fig, ax = plt.subplots(figsize=(10, 4))
    
    # Detect CPU column name (could be 'cpu', 'cpu_mean', or 'proc_cpu')
    cpu_col = None
    for col in ['cpu_mean', 'cpu', 'proc_cpu']:
        if col in df.columns:
            cpu_col = col
            break
    
    if cpu_col is None:
        print("   ⚠️ No CPU column found, skipping Figure 1")
        return
    
    # Plot CPU utilization
    ax.plot(df['timestamp'], df[cpu_col], 'b-', linewidth=1.5, label='CPU', alpha=0.8)
    
    # Ground truth attack periods (yellow boxes)
    if events:
        for i, event in enumerate(events):
            label = 'Ground Truth Attack' if i == 0 else None
            ax.axvspan(event['start'], event['end'], alpha=0.2, color='gold', label=label)
    
    # Detected anomalies (red shading)
    anomalies = df[df['aiops_anomaly'] == -1]
    for i, (idx, row) in enumerate(anomalies.iterrows()):
        label = 'Detected Anomaly' if i == 0 else None
        ax.axvspan(row['timestamp'], row['timestamp'] + pd.Timedelta(seconds=window_s), 
                   alpha=0.3, color='red', label=label)
    
    ax.set_xlabel('Time')
    ax.set_ylabel('CPU Utilization (%)')
    ax.set_title('Anomaly Detection Timeline: Ground Truth vs Detected Windows')
    ax.legend(loc='upper right')
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    plt.close()


def figure2_correlation_comparison(df, output_path):
    """
    Figure 2: Correlation Comparison
    Side-by-side bar charts showing tenant-CPU correlation during normal vs attack periods
    """
    print("📊 Generating Figure 2: Correlation Comparison...")
    
    # Detect CPU column
    cpu_col = None
    for col in ['cpu_mean', 'cpu', 'proc_cpu']:
        if col in df.columns:
            cpu_col = col
            break
    
    if cpu_col is None:
        print("   ⚠️ No CPU column found, skipping Figure 2")
        return
    
    # Identify tenant count columns
    tenant_cols = [col for col in df.columns if col.startswith('tenant_') and 
                   not col.endswith('_rl_hits') and col != 'tenant_id']
    
    if len(tenant_cols) == 0:
        print("   ⚠️ No tenant columns found, skipping Figure 2")
        return
    
    # Split into normal and attack periods
    df_normal = df[df['label'] == 'normal']
    df_attack = df[df['label'] == 'attack']
    
    if df_normal.empty or df_attack.empty:
        print("   ⚠️ Missing normal or attack periods, skipping Figure 2")
        return
    
    # Compute correlations with CPU
    corr_normal = df_normal[tenant_cols + [cpu_col]].corr()[cpu_col].drop(cpu_col)
    corr_attack = df_attack[tenant_cols + [cpu_col]].corr()[cpu_col].drop(cpu_col)
    
    # Create side-by-side comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    
    # Normal period
    x = np.arange(len(corr_normal))
    ax1.bar(x, corr_normal.values, color='steelblue', alpha=0.8)
    ax1.set_title('Normal Period Correlations')
    ax1.set_xlabel('Tenant')
    ax1.set_ylabel('Pearson Correlation with CPU')
    ax1.set_xticks(x)
    ax1.set_xticklabels([col.replace('tenant_', 'T') for col in corr_normal.index], rotation=45)
    ax1.axhline(y=0, color='gray', linestyle='--', linewidth=0.8)
    ax1.grid(axis='y', alpha=0.3)
    
    # Attack period
    ax2.bar(x, corr_attack.values, color='crimson', alpha=0.8)
    ax2.set_title('Attack Period Correlations')
    ax2.set_xlabel('Tenant')
    ax2.set_ylabel('Pearson Correlation with CPU')
    ax2.set_xticks(x)
    ax2.set_xticklabels([col.replace('tenant_', 'T') for col in corr_attack.index], rotation=45)
    ax2.axhline(y=0, color='gray', linestyle='--', linewidth=0.8)
    ax2.grid(axis='y', alpha=0.3)
    
    # Find attacker (highest correlation in attack period)
    attacker_idx = corr_attack.idxmax()
    attacker_pos = list(corr_attack.index).index(attacker_idx)
    ax2.bar(attacker_pos, corr_attack[attacker_idx], color='darkred', alpha=1.0, 
            edgecolor='black', linewidth=2, label='Suspected Attacker')
    ax2.legend()
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    print(f"      Mean correlation (normal): {corr_normal.mean():.3f}")
    print(f"      Mean correlation (attack): {corr_attack.mean():.3f}")
    print(f"      Correlation increase: {(corr_attack.mean()/corr_normal.mean() - 1)*100:.1f}%")
    plt.close()


def figure3_confusion_matrix(df, output_path):
    """
    Figure 3: Attribution Confusion Matrix
    Heatmap showing predicted tenant vs true attacker (only for windows with valid blame)
    """
    print("📊 Generating Figure 3: Attribution Confusion Matrix...")
    
    # Filter to attack windows with valid predictions
    attack_windows = df[(df['label'] == 'attack') & (df['aiops_blame'].notna())].copy()
    
    if attack_windows.empty:
        print("   ⚠️ No attack windows with predictions found, skipping Figure 3")
        return
    
    # Get ground truth and predictions
    y_true = attack_windows['noisy_tenant'].fillna('unknown')
    y_pred = attack_windows['aiops_blame'].fillna('none')
    
    # Get unique tenants (both predicted and true)
    all_tenants = sorted(set(y_true) | set(y_pred))
    all_tenants = [t for t in all_tenants if t not in ['unknown', 'none', '']]
    
    if len(all_tenants) < 2:
        # If only one tenant, show distribution instead
        print(f"   ⚠️ Only one unique tenant detected ({all_tenants}), creating distribution chart instead")
        
        fig, ax = plt.subplots(figsize=(8, 4))
        pred_counts = y_pred.value_counts().sort_index()
        
        colors = ['#2ecc71' if t == y_true.iloc[0] else '#e74c3c' for t in pred_counts.index]
        bars = ax.bar(range(len(pred_counts)), pred_counts.values, color=colors, alpha=0.8, edgecolor='black')
        
        ax.set_xlabel('Predicted Tenant')
        ax.set_ylabel('Number of Attack Windows')
        ax.set_title(f'Attribution Distribution\nTrue Attacker: {y_true.iloc[0]}')
        ax.set_xticks(range(len(pred_counts)))
        ax.set_xticklabels([t.replace('tenant_', 'T') for t in pred_counts.index], rotation=45)
        ax.grid(axis='y', alpha=0.3)
        
        # Add count labels
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}', ha='center', va='bottom', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"   ✅ Saved: {output_path} (as distribution chart)")
        plt.close()
        return
    
    # Create confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=all_tenants)
    
    # Plot
    fig, ax = plt.subplots(figsize=(8, 7))
    sns.heatmap(cm, annot=True, fmt='d', cmap='YlOrRd', cbar_kws={'label': 'Count'},
                xticklabels=[t.replace('tenant_', 'T') for t in all_tenants],
                yticklabels=[t.replace('tenant_', 'T') for t in all_tenants],
                ax=ax, linewidths=0.5, linecolor='gray')
    
    ax.set_xlabel('Predicted Tenant (AIOps Blame)')
    ax.set_ylabel('True Attacker (Ground Truth)')
    ax.set_title('Attribution Confusion Matrix\n(Attack Windows Only)')
    
    # Calculate attribution accuracy
    correct = (y_true == y_pred).sum()
    total = len(y_true)
    accuracy = correct / total if total > 0 else 0
    
    # Add accuracy text
    ax.text(0.02, 0.98, f'Accuracy: {accuracy:.1%}\n({correct}/{total} correct)',
            transform=ax.transAxes, verticalalignment='top',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    print(f"      Attribution Accuracy: {accuracy:.1%} ({correct}/{total} windows)")
    plt.close()


def figure4_method_comparison(df, output_path):
    """
    Figure 4: Method Comparison
    Bar chart comparing precision, recall, F1, and attribution across all methods
    Handles different data types (corr_anomaly is boolean, aiops_anomaly is -1/1)
    """
    print("📊 Generating Figure 4: Method Comparison...")
    
    # Calculate metrics for all methods present in dataframe
    methods = []
    precision_vals = []
    recall_vals = []
    f1_vals = []
    attribution_vals = []
    
    gt = df['label'] == 'attack'
    
    # AIOps (Heuristic Pipeline)
    if 'aiops_anomaly' in df.columns:
        detect = df['aiops_anomaly'] == -1
        tp = ((detect) & (gt)).sum()
        fp = ((detect) & (~gt)).sum()
        fn = ((~detect) & (gt)).sum()
        p = tp/(tp+fp) if (tp+fp) > 0 else 0
        r = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1 = 2*p*r/(p+r) if (p+r) > 0 else 0
        
        attack_df = df[gt]
        if 'aiops_blame' in df.columns and 'noisy_tenant' in df.columns:
            correct = ((attack_df['aiops_blame'] == attack_df['noisy_tenant']) & 
                      (attack_df['noisy_tenant'] != '') &
                      (attack_df['aiops_blame'].notna())).sum()
            attr = correct / ((attack_df['aiops_blame'].notna()).sum() if (attack_df['aiops_blame'].notna()).sum() > 0 else len(attack_df))
        else:
            attr = 0
        
        methods.append('Heuristic\nPipeline')
        precision_vals.append(p * 100)
        recall_vals.append(r * 100)
        f1_vals.append(f1 * 100)
        attribution_vals.append(attr * 100)
        
        print(f"      AIOps: P={p:.1%}, R={r:.1%}, F1={f1:.1%}, Attr={attr:.1%}")
    
    # Correlation-based (handle boolean True/False as anomaly detection)
    if 'corr_anomaly' in df.columns:
        detect = df['corr_anomaly'] == True  # corr_anomaly is boolean True for anomaly
        tp = ((detect) & (gt)).sum()
        fp = ((detect) & (~gt)).sum()
        fn = ((~detect) & (gt)).sum()
        p = tp/(tp+fp) if (tp+fp) > 0 else 0
        r = tp/(tp+fn) if (tp+fn) > 0 else 0
        f1 = 2*p*r/(p+r) if (p+r) > 0 else 0
        
        attack_df = df[gt]
        if 'corr_blame' in df.columns and 'noisy_tenant' in df.columns:
            correct = ((attack_df['corr_blame'] == attack_df['noisy_tenant']) & 
                      (attack_df['noisy_tenant'] != '') &
                      (attack_df['corr_blame'].notna())).sum()
            attr = correct / ((attack_df['corr_blame'].notna()).sum() if (attack_df['corr_blame'].notna()).sum() > 0 else len(attack_df))
        else:
            attr = 0
        
        methods.append('Correlation\nBased')
        precision_vals.append(p * 100)
        recall_vals.append(r * 100)
        f1_vals.append(f1 * 100)
        attribution_vals.append(attr * 100)
        
        print(f"      Correlation: P={p:.1%}, R={r:.1%}, F1={f1:.1%}, Attr={attr:.1%}")
    
    if len(methods) == 0:
        print("   ⚠️ No methods found in dataframe, skipping Figure 4")
        return
    
    # Create grouped bar chart
    x = np.arange(len(methods))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars1 = ax.bar(x - 1.5*width, precision_vals, width, label='Precision', color='#2ecc71', alpha=0.8)
    bars2 = ax.bar(x - 0.5*width, recall_vals, width, label='Recall', color='#3498db', alpha=0.8)
    bars3 = ax.bar(x + 0.5*width, f1_vals, width, label='F1-Score', color='#9b59b6', alpha=0.8)
    bars4 = ax.bar(x + 1.5*width, attribution_vals, width, label='Attribution', color='#e74c3c', alpha=0.8)
    
    # Add value labels on bars
    def autolabel(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f'{height:.0f}',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3),  # 3 points vertical offset
                           textcoords="offset points",
                           ha='center', va='bottom', fontsize=8)
    
    autolabel(bars1)
    autolabel(bars2)
    autolabel(bars3)
    autolabel(bars4)
    
    ax.set_ylabel('Percentage (%)')
    ax.set_title('Performance Comparison Across Detection Methods')
    ax.set_xticks(x)
    ax.set_xticklabels(methods)
    ax.legend(loc='upper left', ncol=4)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_ylim(0, 110)  # Leave room for labels
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"   ✅ Saved: {output_path}")
    print(f"      Methods compared: {', '.join(methods)}")
    plt.close()


def main():
    args = parse_args()
    
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("📈 High-Quality Figure Generator for IEEE Report")
    print(f"   Input: {input_path}")
    print(f"   Output: {output_dir}")
    print()
    
    # Load data
    print("📥 Loading telemetry data...")
    try:
        df = pd.read_csv(input_path)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        print(f"   Loaded {len(df)} windows")
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        return 1
    
    # Load ground truth
    events = read_replay_plan(input_path.parent)
    print()
    
    # Generate figures
    try:
        figure1_detection_timeline(df, events, args.window, 
                                   output_dir / 'fig1_detection_timeline.png')
        print()
        
        figure2_correlation_comparison(df, output_dir / 'fig2_correlation_comparison.png')
        print()
        
        figure3_confusion_matrix(df, output_dir / 'fig3_attribution_confusion.png')
        print()
        
        figure4_method_comparison(df, output_dir / 'fig4_method_comparison.png')
        print()
        
        print("✨ All figures generated successfully!")
        print(f"📁 Figures saved to: {output_dir.absolute()}")
        print()
        print("Next steps:")
        print("  1. Review the generated figures")
        print("  2. Copy figures to your LaTeX directory")
        print("  3. Add \\includegraphics commands to report.tex")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error generating figures: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
