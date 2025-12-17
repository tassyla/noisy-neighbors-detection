import logging
import time
import threading
import psutil
import csv
import os
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Configuração de Logs (apenas para console)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Variáveis para armazenar métricas em memória
request_counts = {} # {tenant_id: count}
rate_limit_hits = {} # {tenant_id: hits_in_current_window}
rate_counters = {}   # {tenant_id: (window_start_second, count)}
lock = threading.Lock()

# Rate limiting configuration
RATE_LIMIT = 100  # requests per second per tenant

def check_rate_limit(tenant_id: str) -> bool:
    """Fixed-window per-second rate limiter.
    Returns True if request is allowed, False if rate limit exceeded.
    When a limit is exceeded, increments `rate_limit_hits` for that tenant
    and logs a specific WARNING as required.
    """
    now = int(time.time())
    with lock:
        window_start, count = rate_counters.get(tenant_id, (now, 0))
        if window_start != now:
            # new window
            rate_counters[tenant_id] = (now, 1)
            return True
        else:
            if count < RATE_LIMIT:
                rate_counters[tenant_id] = (window_start, count + 1)
                return True
            else:
                # rate limit exceeded
                rate_limit_hits[tenant_id] = rate_limit_hits.get(tenant_id, 0) + 1
                logger.warning(f"WARNING: Rate limit exceeded for {tenant_id}.")
                return False

def get_tenant_id():
    return request.headers.get('X-Tenant-ID', 'unknown')

@app.route('/')
def index():
    tid = get_tenant_id()
    with lock:
        request_counts[tid] = request_counts.get(tid, 0) + 1
    logger.info(f"REQ /  tenant={tid}")
    return "OK"

@app.route('/heavy_work')
def heavy_work():
    tid = get_tenant_id()
    # Apply rate limiting specific to /heavy_work
    allowed = check_rate_limit(tid)
    if not allowed:
        # Do not count this denied request as a successful request
        logger.info(f"REQ /heavy_work DENIED tenant={tid}")
        return ("Rate limit exceeded", 429)

    with lock:
        request_counts[tid] = request_counts.get(tid, 0) + 1
    
    # Simula carga pesada na CPU
    start = time.time()
    # Loop para queimar CPU por 100ms
    while time.time() - start < 0.1: 
        _ = [x*x for x in range(500)]
    logger.info(f"REQ /heavy_work DONE tenant={tid}")
    return "Heavy Work Done"


@app.route('/debug_counts')
def debug_counts():
    """Return current in-memory request and rate-limit counters for debugging."""
    with lock:
        snapshot = {
            'request_counts': request_counts.copy(),
            'rate_limit_hits': rate_limit_hits.copy(),
            'rate_counters': {k: v for k, v in rate_counters.items()}
        }
    return jsonify(snapshot)


@app.route('/force_sample')
def force_sample():
    """Force immediate telemetry sample write for debugging.
    This writes one CSV row using current in-memory snapshots but does NOT
    clear the counters so it is safe for diagnostics.
    """
    # Copy snapshot under lock
    with lock:
        current_counts = request_counts.copy()
        current_rl_hits = rate_limit_hits.copy()
        # Make a best-effort snapshot of recent rate_counters
        epoch_now = int(time.time())
        rc_snapshot = {}
        for k, (start, cnt) in rate_counters.items():
            if start <= epoch_now:
                rc_snapshot[k] = cnt

    # Prepare known tenants and header same as collector
    known_tenants = [f"tenant_{i:02d}" for i in range(1, 11)] + ['tenant_99']
    file_path = 'telemetry.csv'

    # Read/ensure header exists and append one row
    file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0
    timestamp = datetime.now().isoformat()
    cpu = psutil.cpu_percent(interval=0.1)
    header = ['timestamp', 'cpu'] + known_tenants + [t + '_rl_hits' for t in known_tenants]
    counts = [rc_snapshot.get(t, current_counts.get(t, 0)) for t in known_tenants]
    hits = [current_rl_hits.get(t, 0) for t in known_tenants]

    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        writer.writerow([timestamp, cpu] + counts + hits)

    return jsonify({
        'written': {
            'timestamp': timestamp,
            'cpu': cpu,
            'counts': dict(zip(known_tenants, counts)),
            'rl_hits': dict(zip([t + '_rl_hits' for t in known_tenants], hits))
        }
    })

# --- MONITORAMENTO INTEGRADO (Substitui Prometheus/Docker Logs) ---
def telemetry_collector():
    print("📊 Telemetry Collector Started...")

    # Process object for measuring the app's own CPU usage
    proc = psutil.Process()
    # Prime the process cpu_percent() measurement
    try:
        proc.cpu_percent(None)
    except Exception:
        pass

    while True:
        timestamp = datetime.now().isoformat()
        cpu = psutil.cpu_percent(interval=1) # Bloqueia por 1s (host/system)
        # Measure process (app) CPU over the same interval and normalize
        try:
            proc_cpu = proc.cpu_percent(None)
        except Exception:
            proc_cpu = 0.0
        cpu_count = psutil.cpu_count(logical=True) or 1
        # proc_cpu may be >100 if using multiple cores; normalize to percent of total system
        proc_cpu_pct = proc_cpu / cpu_count

        # Epoch second for comparing with rate_counters windows
        epoch_now = int(time.time())

        # Snapshot dos contadores de log e de rate-limit hits
        with lock:
            current_counts = request_counts.copy()
            current_rl_hits = rate_limit_hits.copy()

            # Build a snapshot of per-window counts from rate_counters.
            # We accept counts whose window start is <= epoch_now (they may have been recorded
            # during the 1s cpu sampling); we then remove consumed entries to avoid double-counting.
            rc_snapshot = {}
            to_delete = []
            for k, (start, cnt) in rate_counters.items():
                if start <= epoch_now:
                    rc_snapshot[k] = cnt
                    to_delete.append(k)

            # Remove consumed windows from rate_counters so the limiter can start fresh next second
            for k in to_delete:
                try:
                    del rate_counters[k]
                except KeyError:
                    pass

            # Reseta contadores para o próximo segundo (Rate por segundo)
            request_counts.clear()
            rate_limit_hits.clear()
        
        # Prepara linha para o CSV
        # Formato: timestamp, cpu, tenant_01, ..., tenant_10, tenant_99, then *_rl_hits
        row_data = {'timestamp': timestamp, 'cpu': cpu}
        row_data.update(current_counts)

        # Define tenants expected by analysis (tenant_01..tenant_10 and tenant_99)
        known_tenants = [f"tenant_{i:02d}" for i in range(1, 11)] + ['tenant_99']

        # Build header: host cpu, process cpu, normalized process cpu, counts, then rate-limit-hits
        header = ['timestamp', 'cpu', 'proc_cpu', 'proc_cpu_pct'] + known_tenants + [t + '_rl_hits' for t in known_tenants]

        # Determine if we need to write header (file missing or empty)
        file_path = 'telemetry.csv'
        file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0

        with open(file_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(header)

            # Prefer per-window rate_counters snapshot when present, else fall back to request_counts
            counts = [rc_snapshot.get(t, current_counts.get(t, 0)) for t in known_tenants]
            hits = [current_rl_hits.get(t, 0) for t in known_tenants]
            writer.writerow([timestamp, cpu, proc_cpu, proc_cpu_pct] + counts + hits)

# Roda o monitor em uma thread separada dentro da app
t_monitor = threading.Thread(target=telemetry_collector, daemon=True)
t_monitor.start()

if __name__ == "__main__":
    # Desativa o reloader para não duplicar threads
    # Enable threaded to allow concurrent handling during experiments (not for production)
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)