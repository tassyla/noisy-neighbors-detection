"""
EDGAR Calibrator: Extract diurnal workload profile from EDGAR logs
and use it to modulate baseline tenant traffic in load_generator.

Usage:
    python edgar_calibrator.py --input-dir ./edgar_data --output edgar_profile.json --sample-ratio 0.1
"""

import argparse
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import numpy as np


def detect_columns(csv_path):
    """Read first 5 rows to detect timestamp and identifier columns."""
    df_sample = pd.read_csv(csv_path, nrows=5, low_memory=False)
    cols = df_sample.columns.tolist()
    print(f"📊 Columns in {Path(csv_path).name}: {cols}")
    return cols


def infer_timestamp_col(cols):
    """Infer timestamp column from common EDGAR patterns."""
    patterns = ['timestamp', 'time', 'datetime', 'date', 'timestamp_utc', 'request_time', 'accessed', 'time_utc']
    for p in patterns:
        for col in cols:
            if p.lower() in col.lower():
                return col
    # fallback: first column that looks date-like
    return cols[0] if cols else None


def infer_id_col(cols):
    """Infer identifier column (CIK, user_id, ip, etc.)."""
    patterns = ['cik', 'identifier', 'user', 'ip', 'client', 'requester', 'entity', 'account']
    for p in patterns:
        for col in cols:
            if p.lower() in col.lower():
                return col
    # fallback: second column
    return cols[1] if len(cols) > 1 else None


def read_edgar_logs(input_dir, sample_ratio=0.1, max_files=3):
    """Read EDGAR CSV files (sample to avoid memory overload).
    Returns: list of (timestamp, identifier) tuples.
    """
    input_path = Path(input_dir)
    csv_files = sorted(input_path.glob("log*.csv"))[:max_files]
    
    if not csv_files:
        raise FileNotFoundError(f"No log*.csv files found in {input_dir}")
    
    print(f"Found {len(csv_files)} EDGAR files. Processing {len(csv_files[:max_files])}...")
    
    records = []
    for csv_file in csv_files:
        print(f"📖 Reading {csv_file.name}...")
        
        # Sample and parse
        df = pd.read_csv(csv_file, low_memory=False)
        
        # Auto-detect columns
        ts_col = infer_timestamp_col(df.columns.tolist())
        id_col = infer_id_col(df.columns.tolist())
        
        print(f"   Using timestamp_col={ts_col}, id_col={id_col}")
        
        if ts_col not in df.columns or id_col not in df.columns:
            print(f"⚠️ Could not auto-detect columns. Skipping.")
            continue
        
        # Sample rows
        df_sample = df.sample(frac=min(sample_ratio, 1.0), random_state=42)
        print(f"   Sampled {len(df_sample)} rows")
        
        # Extract (timestamp, identifier)
        for _, row in df_sample.iterrows():
            try:
                ts_str = str(row[ts_col])
                ident = str(row[id_col])
                # Try to parse timestamp (may fail; skip those)
                ts = pd.to_datetime(ts_str, errors='coerce')
                if pd.notna(ts):
                    records.append((ts, ident))
            except Exception:
                continue
        
        if len(records) > 10000:
            print(f"   Reached {len(records)} records, stopping sampling.")
            break
    
    print(f"✅ Extracted {len(records)} timestamp-identifier pairs from EDGAR.")
    return records


def compute_diurnal_profile(records):
    """Aggregate counts by hour-of-day to get diurnal pattern.
    Returns: dict {hour: normalized_count} where sum of all hours = 1.0
    """
    if not records:
        print("⚠️ No records to profile. Returning uniform distribution.")
        return {h: 1.0 / 24 for h in range(24)}
    
    hourly_counts = {}
    for ts, _ in records:
        hour = ts.hour
        hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
    
    # Normalize to [0, 1]
    total = sum(hourly_counts.values())
    diurnal = {h: hourly_counts.get(h, 0) / total for h in range(24)}
    
    print("📈 Diurnal profile (requests per hour, normalized):")
    for h in range(24):
        bar_len = int(diurnal[h] * 50)
        print(f"  Hour {h:02d}: {'█' * bar_len} {diurnal[h]:.4f}")
    
    return diurnal


def compute_tenant_distribution(records):
    """Aggregate request counts per identifier to understand traffic distribution.
    Returns: dict {identifier: count} sorted by popularity.
    """
    id_counts = {}
    for _, ident in records:
        id_counts[ident] = id_counts.get(ident, 1) + 1
    
    # Sort descending
    sorted_ids = sorted(id_counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"📊 Top 10 identifiers by request count:")
    for ident, count in sorted_ids[:10]:
        print(f"  {ident}: {count} requests")
    
    return dict(sorted_ids)


def save_profile(output_path, diurnal, tenant_distribution):
    """Save profile to JSON for load_generator to consume."""
    profile = {
        "diurnal_profile": diurnal,
        "tenant_distribution": tenant_distribution,
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "description": "EDGAR-derived workload profile for baseline tenants"
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(profile, f, indent=2)
    
    print(f"✅ Profile saved to {output_path}")
    return profile


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract EDGAR workload profile")
    parser.add_argument("--input-dir", default="./edgar_data", help="Directory containing log*.csv files")
    parser.add_argument("--output", default="edgar_profile.json", help="Output profile JSON")
    parser.add_argument("--sample-ratio", type=float, default=0.05, help="Sampling ratio per file (0.0-1.0)")
    parser.add_argument("--max-files", type=int, default=3, help="Max files to process")
    args = parser.parse_args()
    
    print("🚀 EDGAR Calibrator")
    print(f"Input: {args.input_dir}, Sample ratio: {args.sample_ratio}, Max files: {args.max_files}")
    
    # Extract records
    records = read_edgar_logs(args.input_dir, sample_ratio=args.sample_ratio, max_files=args.max_files)
    
    # Compute profiles
    diurnal = compute_diurnal_profile(records)
    tenant_dist = compute_tenant_distribution(records)
    
    # Save
    save_profile(args.output, diurnal, tenant_dist)
    
    print("\n✨ Done! Use this profile in load_generator with --edgar-profile edgar_profile.json")
