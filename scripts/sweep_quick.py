#!/usr/bin/env python3
"""
Quick hyperparameter sweep for noisy-neighbor detection.
Tests focused grid of promising configurations after weight rebalancing.
"""
import subprocess
import pandas as pd
from pathlib import Path
import argparse
import sys
from datetime import datetime

def run_analysis(telemetry_file, output_dir, window, overlap, contamination, estimators, z_threshold, rel_threshold, hysteresis):
    """Run analysis.py with specified parameters and return path to labeled CSV."""
    cmd = [
        sys.executable, "analysis.py",
        "--window", str(window),
        "--overlap", str(overlap),
        "--contamination", str(contamination),
        "--estimators", str(estimators),
        "--z-threshold", str(z_threshold),
        "--rel-threshold", str(rel_threshold),
        "--hysteresis", str(hysteresis),
        "--input", telemetry_file,
        "--output-dir", output_dir
    ]
    
    print(f"▶️  w={window:3d} o={overlap:.1f} c={contamination:.2f} z={z_threshold:.1f} r={rel_threshold:.2f} h={hysteresis}", end=" ")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
        if result.returncode != 0:
            print(f"❌ FAILED")
            return None
        labeled_path = Path(output_dir) / "telemetry_labeled.csv"
        if labeled_path.exists():
            return str(labeled_path)
        print(f"❌ NO OUTPUT")
        return None
    except subprocess.TimeoutExpired:
        print(f"⏱️  TIMEOUT")
        return None
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return None


def extract_metrics(labeled_csv):
    """Extract precision/recall/attribution from labeled telemetry CSV."""
    try:
        df = pd.read_csv(labeled_csv)
        
        # Detection metrics
        if 'label' not in df.columns or 'aiops_anomaly' not in df.columns:
            return None
        
        gt_attack = df['label'] == 'attack'
        aiops_detect = df['aiops_anomaly'] == -1
        
        tp = int(((aiops_detect == True) & (gt_attack == True)).sum())
        fp = int(((aiops_detect == True) & (gt_attack == False)).sum())
        fn = int(((aiops_detect == False) & (gt_attack == True)).sum())
        tn = int(((aiops_detect == False) & (gt_attack == False)).sum())
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Attribution accuracy (only on attack windows)
        attack_windows = df[gt_attack]
        if len(attack_windows) > 0 and 'aiops_blame' in df.columns and 'noisy_tenant' in df.columns:
            correct = (attack_windows['aiops_blame'] == attack_windows['noisy_tenant']) & (attack_windows['noisy_tenant'] != '')
            attribution_acc = correct.sum() / len(attack_windows)
        else:
            attribution_acc = 0.0
        
        return {
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'attribution_accuracy': attribution_acc,
            'attack_windows': int(gt_attack.sum()),
            'normal_windows': int((~gt_attack).sum())
        }
    except Exception as e:
        return None


def main():
    parser = argparse.ArgumentParser(description="Quick hyperparameter sweep with rebalanced weights")
    parser.add_argument("--input", required=True, help="Input telemetry CSV file")
    parser.add_argument("--output", default="sweep_quick_results.csv", help="Output CSV file for results")
    parser.add_argument("--sweep-dir", default="sweep_quick_outputs", help="Directory for intermediate outputs")
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"❌ Input file not found: {args.input}")
        return
    
    # Focused grid: emphasize promising regions from previous runs
    # Windows: 60-120 (larger windows showed better F1)
    # Contamination: 0.25-0.35 (sweet spot for recall)
    # Z-threshold: 0.8-1.5 (aggressive, but balanced with new weights)
    # Overlap: 0.5-0.7
    param_grid = {
        'window': [60, 75, 90, 120],
        'overlap': [0.5, 0.6, 0.7],
        'contamination': [0.25, 0.30, 0.35],
        'estimators': [400],
        'z_threshold': [0.8, 1.0, 1.2, 1.5],
        'rel_threshold': [0.15, 0.18],
        'hysteresis': [1, 2]
    }
    
    sweep_dir = Path(args.sweep_dir)
    sweep_dir.mkdir(exist_ok=True)
    
    results = []
    total_configs = (len(param_grid['window']) * len(param_grid['overlap']) * 
                     len(param_grid['contamination']) * len(param_grid['z_threshold']) * 
                     len(param_grid['rel_threshold']) * len(param_grid['hysteresis']))
    
    print(f"🔬 Quick sweep: {total_configs} configurations")
    print(f"   Weights: baseline_dev 40%, z_norm 35%, rel_norm 18%, der_norm 5%")
    print(f"   Input: {args.input}")
    print()
    
    config_num = 0
    for window in param_grid['window']:
        for overlap in param_grid['overlap']:
            for contamination in param_grid['contamination']:
                for z_th in param_grid['z_threshold']:
                    for rel_th in param_grid['rel_threshold']:
                        for hyst in param_grid['hysteresis']:
                            config_num += 1
                            config_name = f"w{window}_o{int(overlap*100)}_c{int(contamination*100)}_z{int(z_th*10)}_r{int(rel_th*100)}_h{hyst}"
                            output_dir = sweep_dir / config_name
                            output_dir.mkdir(exist_ok=True)
                            
                            labeled_csv = run_analysis(
                                args.input, str(output_dir),
                                window, overlap, contamination, param_grid['estimators'][0],
                                z_th, rel_th, hyst
                            )
                            
                            if labeled_csv:
                                metrics = extract_metrics(labeled_csv)
                                if metrics:
                                    results.append({
                                        'config': config_name,
                                        'window': window,
                                        'overlap': overlap,
                                        'contamination': contamination,
                                        'z_threshold': z_th,
                                        'rel_threshold': rel_th,
                                        'hysteresis': hyst,
                                        **metrics
                                    })
                                    print(f"✅ P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.1%} Attr={metrics['attribution_accuracy']:.1%}")
                                else:
                                    print(f"❌ METRICS FAILED")
                            else:
                                print(f"❌ ANALYSIS FAILED")
    
    if results:
        df_results = pd.DataFrame(results)
        df_results.to_csv(args.output, index=False)
        print()
        print(f"✅ Sweep complete: {len(results)} successful | Results → {args.output}")
        print()
        print("📊 Top 5 by F1 Score:")
        top_f1 = df_results.nlargest(5, 'f1')[['config', 'precision', 'recall', 'f1', 'attribution_accuracy']]
        for idx, row in top_f1.iterrows():
            print(f"  {row['config']:40s} P={row['precision']:.2%} R={row['recall']:.2%} F1={row['f1']:.2%} Attr={row['attribution_accuracy']:.2%}")
        
        print()
        print("🎯 Top 5 by Attribution Accuracy:")
        top_attr = df_results.nlargest(5, 'attribution_accuracy')[['config', 'precision', 'recall', 'f1', 'attribution_accuracy']]
        for idx, row in top_attr.iterrows():
            print(f"  {row['config']:40s} P={row['precision']:.2%} R={row['recall']:.2%} F1={row['f1']:.2%} Attr={row['attribution_accuracy']:.2%}")
        
        print()
        print("⚖️  Best balanced (F1 > 0.50, Attr > 0.25):")
        balanced = df_results[(df_results['f1'] > 0.50) & (df_results['attribution_accuracy'] > 0.25)]
        if not balanced.empty:
            for idx, row in balanced.nlargest(3, 'f1').iterrows():
                print(f"  {row['config']:40s} P={row['precision']:.2%} R={row['recall']:.2%} F1={row['f1']:.2%} Attr={row['attribution_accuracy']:.2%}")
        else:
            print("   No configs met criteria (F1 > 0.50, Attr > 0.25)")
            print(f"   Best F1: {df_results.nlargest(1, 'f1').iloc[0]['f1']:.2%}")
            print(f"   Best Attr: {df_results.nlargest(1, 'attribution_accuracy').iloc[0]['attribution_accuracy']:.2%}")
    else:
        print("❌ No successful configurations")


if __name__ == "__main__":
    main()
