import pandas as pd
import json
from datetime import datetime
import sys
import argparse
import glob
import os


# Configurações
INPUT_DIR = 'scripts/edgar_data/'
OUTPUT_FILE = 'scripts/replay_plan.json'
SAMPLE_SIZE = 100_000  # Increased default because we ingest multiple files
MAX_READ_ROWS = 1_000_000  # Lê até 1M linhas por arquivo para descobrir colunas e amostrar
TARGET_DURATION_SECONDS = 600  # Stretch sampled events to 10 minutes total


parser = argparse.ArgumentParser(description='Preprocess EDGAR CSV into replay plan')
parser.add_argument('--ip-col', help='Override IP column name')
parser.add_argument('--timestamp-col', help='Override full timestamp column name')
parser.add_argument('--date-col', help='Override date column name')
parser.add_argument('--time-col', help='Override time column name')
parser.add_argument('--sample-size', type=int, default=SAMPLE_SIZE, help='Number of events to output')
parser.add_argument('--tenant-col', help='Fallback column to derive tenant IDs from (e.g. uri_path)')
parser.add_argument('--tenant-method', choices=['round_robin', 'hash'], default='hash', help='How to derive tenant IDs from the tenant column when IP is not available')
parser.add_argument('--tenant-count', type=int, default=20, help='Number of tenant buckets to create when mapping identifiers')
parser.add_argument('--input-dir', default=INPUT_DIR, help='Directory containing CSV files to ingest (default: scripts/edgar_data/)')
args = parser.parse_args()

input_dir = args.input_dir
print(f"🔄 Lendo todos os arquivos CSV em: {input_dir}...")

if not os.path.isdir(input_dir):
    print(f"❌ Directory not found: {input_dir}")
    print("Create the folder and place CSV files inside, e.g.: scripts/edgar_data/*.csv")
    sys.exit(1)

csv_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))
if not csv_files:
    print(f"❌ No CSV files found in {input_dir}. Place one or more .csv files there and re-run.")
    sys.exit(1)

try:
    # Read header from first file to discover columns
    header_df = pd.read_csv(csv_files[0], nrows=0)
    cols = list(header_df.columns)
except Exception as e:
    print(f"❌ Erro ao ler o CSV de exemplo ({csv_files[0]}): {e}")
    sys.exit(1)


def find_column(columns, candidates):
    """Return the first candidate that exists in columns (case-insensitive)."""
    lower_map = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    # fallback: try substring match
    for col in columns:
        for cand in candidates:
            if cand.lower() in col.lower():
                return col
    return None


# Possible column name variants
timestamp_candidates = ['timestamp', 'datetime', 'date_time', 'time_stamp', 'ts']
date_candidates = ['date', 'access_date', 'day']
time_candidates = ['time', 'access_time', 'hour']
ip_candidates = ['ip', 'client_ip', 'remote_addr', 'ip_address', 'remoteaddr']

timestamp_col = find_column(cols, timestamp_candidates)
date_col = find_column(cols, date_candidates)
time_col = find_column(cols, time_candidates)
# detect ip column
ip_col = find_column(cols, ip_candidates)
# detect uri-like column candidates (fallback)
uri_candidates = ['uri', 'uri_path', 'url', 'request_uri', 'path', 'request_path', 'host']
uri_col = find_column(cols, uri_candidates)
# Apply CLI overrides if provided
# Apply CLI overrides if provided
if args.ip_col:
    if args.ip_col in cols:
        ip_col = args.ip_col
    else:
        print(f"❌ Override ip-col '{args.ip_col}' not found in CSV columns: {cols}")
        sys.exit(1)
if args.timestamp_col:
    if args.timestamp_col in cols:
        timestamp_col = args.timestamp_col
    else:
        print(f"❌ Override timestamp-col '{args.timestamp_col}' not found in CSV columns: {cols}")
        sys.exit(1)
if args.date_col:
    if args.date_col in cols:
        date_col = args.date_col
    else:
        print(f"❌ Override date-col '{args.date_col}' not found in CSV columns: {cols}")
        sys.exit(1)
if args.time_col:
    if args.time_col in cols:
        time_col = args.time_col
    else:
        print(f"❌ Override time-col '{args.time_col}' not found in CSV columns: {cols}")
        sys.exit(1)

# Determine tenant source column: prefer IP, else tenant-col override, else uri-like column, else None
tenant_source_col = None
if ip_col:
    tenant_source_col = ip_col
else:
    if args.tenant_col:
        if args.tenant_col in cols:
            tenant_source_col = args.tenant_col
        else:
            print(f"❌ Override tenant-col '{args.tenant_col}' not found in CSV columns: {cols}")
            sys.exit(1)
    elif uri_col:
        tenant_source_col = uri_col


print(f"Detected columns: {cols}")
print(f"Mapped -> timestamp: {timestamp_col}, date: {date_col}, time: {time_col}, ip: {ip_col}, uri: {uri_col}")

if not tenant_source_col:
    print("❌ Could not find an IP or URI column to derive tenants from. Look for one of:", ip_candidates + uri_candidates)
    print("To inspect the CSV header run (PowerShell):")
    print(r"  Get-Content .\scripts\raw_edgar_data.csv -TotalCount 3")
    print("Or re-run this script with an override, e.g.:")
    print("  python scripts/preprocess_edgar.py --tenant-col uri_path")
    print("If no identifying column exists you can generate synthetic tenants by providing no tenant column; the script will fallback to round-robin assignment.")
    # continue: tenant_source_col may be None, but we will allow synthetic tenant generation later


# Decide which columns to read. Build usecols without None and always include tenant_source_col if available.
usecols = []
if timestamp_col:
    usecols.append(timestamp_col)
elif date_col and time_col:
    usecols.extend([date_col, time_col])
elif date_col:
    usecols.append(date_col)
else:
    # try to find any column with date/time keywords
    for c in cols:
        if 'time' in c.lower() or 'date' in c.lower() or 'timestamp' in c.lower():
            usecols.append(c)
            break

# Always include tenant_source_col (IP/URI) so we can map tenants
if tenant_source_col and tenant_source_col not in usecols:
    usecols.append(tenant_source_col)

# Filter out any None values and ensure we have something to pass to read_csv
usecols = [c for c in usecols if c]
if not usecols:
    # As a last resort, read all columns (limited by MAX_READ_ROWS)
    usecols = cols

print(f"Reading columns: {usecols} (up to {MAX_READ_ROWS} rows per file)")

# Hybrid proportional + stratified sampling (memory safe via chunked reads)
CHUNK_SIZE = 100_000

def count_rows_in_file(path, usecols):
    # Count rows via chunked reading (respects usecols)
    total = 0
    try:
        for chunk in pd.read_csv(path, usecols=usecols, chunksize=CHUNK_SIZE):
            total += len(chunk)
    except Exception:
        # fallback to line counting which is faster but ignores header nuances
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                total = sum(1 for _ in fh) - 1
        except Exception:
            total = 0
    return max(total, 0)

def allocate_file_quotas(files, sample_size):
    counts = {f: count_rows_in_file(f, usecols) for f in files}
    total = sum(counts.values())
    if total == 0:
        return {f: 0 for f in files}
    quotas = {}
    assigned = 0
    for i, f in enumerate(files):
        if i == len(files) - 1:
            # assign remaining to last file to ensure sum equals sample_size
            q = sample_size - assigned
        else:
            q = round(sample_size * counts[f] / total)
            assigned += q
        quotas[f] = max(0, q)
    return quotas

def get_stratum_series(chunk):
    # Stratify by tenant if available, else by hour-of-day of timestamp
    if tenant_source_col and tenant_source_col in chunk.columns:
        return chunk[tenant_source_col].astype(str).fillna('tenant_unknown')
    else:
        # Ensure chunk has timestamp parsed
        if 'timestamp' not in chunk.columns:
            if timestamp_col and timestamp_col in chunk.columns:
                chunk['timestamp'] = pd.to_datetime(chunk[timestamp_col], errors='coerce', utc=True)
            elif date_col and time_col and date_col in chunk.columns and time_col in chunk.columns:
                chunk['timestamp'] = pd.to_datetime(chunk[date_col].astype(str) + ' ' + chunk[time_col].astype(str), errors='coerce', utc=True)
            else:
                # fallback: try any datetime-like column
                for c in chunk.columns:
                    try:
                        if c == tenant_source_col:
                            continue
                        chunk['timestamp'] = pd.to_datetime(chunk[c], errors='coerce', utc=True)
                        break
                    except Exception:
                        continue
        # hour bucket as stratum
        return chunk['timestamp'].dt.hour.fillna(-1).astype(int).astype(str)

def stratified_sample_file(path, quota):
    # Two-pass approach: first compute stratum counts, then sample per-stratum proportionally
    if quota <= 0:
        return []

    # First pass: stratum counts
    stratum_counts = {}
    total_in_file = 0
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=CHUNK_SIZE):
        # parse minimal timestamp if needed for stratum computation
        s = get_stratum_series(chunk)
        vc = s.value_counts()
        for k, v in vc.items():
            stratum_counts[k] = stratum_counts.get(k, 0) + int(v)
        total_in_file += len(chunk)

    if total_in_file == 0:
        return []

    # Allocate quotas per stratum proportional to counts
    stratum_quotas = {}
    assigned = 0
    items = list(stratum_counts.items())
    for i, (stratum, cnt) in enumerate(items):
        if i == len(items) - 1:
            q = max(0, quota - assigned)
        else:
            q = round(quota * cnt / total_in_file)
            assigned += q
        stratum_quotas[stratum] = q

    # Second pass: sample from each chunk to fill per-stratum quotas
    sampled_parts = []
    remaining = dict(stratum_quotas)
    rng = 42
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=CHUNK_SIZE):
        s = get_stratum_series(chunk)
        chunk = chunk.assign(_stratum=s.values)
        for stratum, need in list(remaining.items()):
            if need <= 0:
                continue
            mask = chunk['_stratum'] == stratum
            available = mask.sum()
            if available <= 0:
                continue
            take = min(need, int(available))
            try:
                sampled = chunk[mask].sample(n=take, random_state=rng)
            except ValueError:
                sampled = chunk[mask]
            sampled_parts.append(sampled.drop(columns=['_stratum']))
            remaining[stratum] -= take
        # early exit if fulfilled
        if sum(remaining.values()) <= 0:
            break

    # If quotas not fully satisfied (due to rounding), try a final pass to pick any remaining rows
    still_needed = sum(max(0, v) for v in remaining.values())
    if still_needed > 0:
        # collect a small random sample from the file to fill gap
        try:
            fill = pd.read_csv(path, usecols=usecols).sample(n=still_needed, random_state=rng)
            sampled_parts.append(fill)
        except Exception:
            # ignore if we cannot fill
            pass

    return sampled_parts

# Compute per-file quotas
file_quotas = allocate_file_quotas(csv_files, args.sample_size)

sampled_list = []
for f in csv_files:
    q = file_quotas.get(f, 0)
    if q <= 0:
        continue
    try:
        parts = stratified_sample_file(f, q)
        sampled_list.extend(parts)
    except Exception as e:
        print(f"⚠️ Warning: sampling failed for {f}: {e}")

if not sampled_list:
    print("❌ No usable sampled rows read from CSV files.")
    sys.exit(1)

df = pd.concat(sampled_list, ignore_index=True)

# If we ended up with fewer rows than requested, do a final random upsample from available data
if len(df) < args.sample_size:
    needed = args.sample_size - len(df)
    try:
        extra = pd.concat([pd.read_csv(f, usecols=usecols, nrows=MAX_READ_ROWS) for f in csv_files], ignore_index=True)
        extra = extra.drop_duplicates().sample(n=min(needed, len(extra)), random_state=42)
        df = pd.concat([df, extra], ignore_index=True)
    except Exception:
        # best-effort, proceed with what we have
        pass

# Create unified timestamp column
if timestamp_col and timestamp_col in df.columns:
    df['timestamp'] = pd.to_datetime(df[timestamp_col], errors='coerce', utc=True)
elif date_col and time_col and date_col in df.columns and time_col in df.columns:
    df['timestamp'] = pd.to_datetime(df[date_col].astype(str) + ' ' + df[time_col].astype(str), errors='coerce', utc=True)
elif date_col and date_col in df.columns:
    df['timestamp'] = pd.to_datetime(df[date_col], errors='coerce', utc=True)
else:
    # try any column that looks datetime-like
    parsed = False
    for c in df.columns:
        if c == ip_col:
            continue
        try:
            df['timestamp'] = pd.to_datetime(df[c], errors='coerce', utc=True)
            parsed = True
            break
        except Exception:
            continue
    if not parsed:
        print('❌ Could not parse any timestamp column. Inspect the CSV headers and types.')
        sys.exit(1)

# Drop rows without timestamp and the tenant source column (if any)
if tenant_source_col and tenant_source_col in df.columns:
    df = df.dropna(subset=['timestamp', tenant_source_col])
else:
    df = df.dropna(subset=['timestamp'])

if df.empty:
    print('❌ No usable rows after parsing timestamps and tenant/source column.')
    sys.exit(1)

# 2. Random sampling from the concatenated dataset to mix records from all files
# Respect CLI sample-size if provided
if len(df) > args.sample_size:
    df = df.sample(n=args.sample_size, random_state=42).copy()

# 3. Ordenar por tempo (garantia)
df = df.sort_values('timestamp')

# 4. Calcular o "Delay" entre requisições (O segredo do Replay)
# O primeiro evento acontece no tempo 0. O segundo acontece X segundos depois do primeiro.
start_time = df['timestamp'].iloc[0]
df['seconds_from_start'] = (df['timestamp'] - start_time).dt.total_seconds()

# Time stretching: spread sampled events over TARGET_DURATION_SECONDS
original_duration = (df['timestamp'].iloc[-1] - start_time).total_seconds()
if original_duration <= 0:
    # avoid division by zero or negative durations; keep as-is
    stretch_factor = 1.0
else:
    stretch_factor = TARGET_DURATION_SECONDS / original_duration

df['seconds_from_start'] = df['seconds_from_start'] * stretch_factor
print(f"Applied time-stretch: original_duration={original_duration:.3f}s, stretch_factor={stretch_factor:.6f}, target={TARGET_DURATION_SECONDS}s")

# 5. Mapear valores (IP/URI/other) para Tenant IDs fictícios
# Isso simula que diferentes identifiers no log original são seus tenants
import hashlib

if tenant_source_col and tenant_source_col in df.columns:
    unique_vals = pd.Series(df[tenant_source_col].unique())
    if args.tenant_method == 'hash':
        # Hash each value into a tenant number 0-19
        def val_to_tenant(v):
            if pd.isna(v):
                return 'tenant_unknown'
            h = int(hashlib.sha1(str(v).encode('utf-8')).hexdigest(), 16)
            return f"tenant_{h % args.tenant_count:02d}"
        df['tenant_id'] = df[tenant_source_col].apply(val_to_tenant)
    else:
        # round_robin mapping of unique values to tenant_00..19
        mapping = {v: f"tenant_{i % args.tenant_count:02d}" for i, v in enumerate(unique_vals)}
        df['tenant_id'] = df[tenant_source_col].map(mapping)
else:
    # No source column to map from; assign round-robin by row order
    df = df.reset_index(drop=True)
    df['tenant_id'] = df.index.to_series().apply(lambda i: f"tenant_{i % args.tenant_count:02d}")

# 6. Exportar para JSON (A "Playlist" do Replayer)
replay_events = df[['seconds_from_start', 'tenant_id']].to_dict(orient='records')

with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    json.dump(replay_events, f)

print(f"✅ Processamento concluído!")
print(f"   Origem: {df['timestamp'].min()} até {df['timestamp'].max()}")
print(f"   Eventos gerados: {len(replay_events)}")
print(f"   Salvo em: {OUTPUT_FILE}")
print("   Exemplo do primeiro evento:", replay_events[0])

# Print tenant distribution summary to help evaluate fairness
counts = df['tenant_id'].value_counts()
print('\nTenant distribution (top 10):')
print(counts.head(10).to_string())
desc = counts.describe()
print('\nTenant counts summary:')
print(desc.to_string())

imbalance_ratio = counts.max() / counts.min() if counts.min() > 0 else float('inf')
print(f"\nImbalance ratio (max/min): {imbalance_ratio:.2f}")