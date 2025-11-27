import logging
import time
import threading
import psutil
import csv
from flask import Flask, request
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
    return "OK"

@app.route('/heavy_work')
def heavy_work():
    tid = get_tenant_id()
    # Apply rate limiting specific to /heavy_work
    allowed = check_rate_limit(tid)
    if not allowed:
        # Do not count this denied request as a successful request
        return ("Rate limit exceeded", 429)

    with lock:
        request_counts[tid] = request_counts.get(tid, 0) + 1
    
    # Simula carga pesada na CPU
    start = time.time()
    # Loop para queimar CPU por 100ms
    while time.time() - start < 0.1: 
        _ = [x*x for x in range(500)]
    return "Heavy Work Done"

# --- MONITORAMENTO INTEGRADO (Substitui Prometheus/Docker Logs) ---
def telemetry_collector():
    # Cria/Limpa o arquivo CSV
    with open('telemetry.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        # Cabeçalho dinâmico será tratado no loop
        pass

    print("📊 Telemetry Collector Started...")
    
    while True:
        timestamp = datetime.now().isoformat()
        cpu = psutil.cpu_percent(interval=1) # Bloqueia por 1s
        
        # Snapshot dos contadores de log e de rate-limit hits
        with lock:
            current_counts = request_counts.copy()
            current_rl_hits = rate_limit_hits.copy()
            # Reseta contadores para o próximo segundo (Rate por segundo)
            request_counts.clear()
            rate_limit_hits.clear()
        
        # Prepara linha para o CSV
        # Formato: timestamp, cpu, tenant_normal, tenant_spammy, tenant_noisy...
        row_data = {'timestamp': timestamp, 'cpu': cpu}
        row_data.update(current_counts)
        
        # Salva no CSV (Append)
        # Usamos DictWriter para lidar com novos tenants aparecendo dinamicamente
        file_exists = False
        try:
            with open('telemetry.csv', 'r') as f:
                file_exists = True
        except FileNotFoundError:
            pass

        # Para simplificar este script acadêmico, vamos salvar tudo num formato padronizado
        # Assumindo tenants conhecidos para facilitar o CSV
        known_tenants = ['tenant_normal', 'tenant_spammy', 'tenant_noisy']

        # Build header: counts for each tenant, then rate-limit-hits for each tenant
        header = ['timestamp', 'cpu'] + known_tenants + [t + '_rl_hits' for t in known_tenants]

        with open('telemetry.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(header)

            # Garante que tem valor 0 se não teve req
            counts = [current_counts.get(t, 0) for t in known_tenants]
            hits = [current_rl_hits.get(t, 0) for t in known_tenants]
            writer.writerow([timestamp, cpu] + counts + hits)

# Roda o monitor em uma thread separada dentro da app
t_monitor = threading.Thread(target=telemetry_collector, daemon=True)
t_monitor.start()

if __name__ == "__main__":
    # Desativa o reloader para não duplicar threads
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)