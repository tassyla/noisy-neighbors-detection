import requests
import threading
import time
import random

TARGET_URL = "http://localhost:5000"


def tenant_loop(tenant_id: str, endpoint: str, base_delay: float, jitter: float = 0.0, warmup: float = 0.0, attack_delay: float = None, warmup_start: float = None):
    """Generic tenant loop.
    If warmup > 0 and attack_delay is provided, the thread uses base_delay for the warmup period
    (measured relative to warmup_start) and then switches to attack_delay indefinitely.
    jitter adds random +/- jitter seconds to base_delay on each request.
    """
    print(f"👤 Tenant {tenant_id} started (Endpoint: {endpoint}, base_delay={base_delay}, jitter={jitter})")
    session = requests.Session()
    start = warmup_start or time.time()
    while True:
        try:
            now = time.time()
            if warmup and attack_delay is not None and (now - start) >= warmup:
                delay = attack_delay
            else:
                delay = base_delay
                if jitter:
                    delay = max(0.0, delay + random.uniform(-jitter, jitter))

            # Make request with reasonable timeout so threads don't hang
            session.get(f"{TARGET_URL}{endpoint}", headers={'X-Tenant-ID': tenant_id}, timeout=5)
            # If delay is zero, yield briefly to avoid tight CPU loop
            if delay == 0:
                time.sleep(0.001)
            else:
                time.sleep(delay)
        except Exception:
            # Ignore transient errors; keep running
            time.sleep(0.5)


def start_threads_for_tenants(tenant_ids, endpoint, threads_per_tenant, base_delay, jitter=0.0, warmup=0.0, attack_delay=None, warmup_start=None):
    threads = []
    for tid in tenant_ids:
        count = threads_per_tenant.get(tid, 0)
        for _ in range(count):
            t = threading.Thread(target=tenant_loop, args=(tid, endpoint, base_delay, jitter, warmup, attack_delay, warmup_start))
            t.daemon = True
            t.start()
            threads.append(t)
    return threads


if __name__ == "__main__":
    print("🚀 Starting Load Generator (profiled)...")

    # Configuration: 50 concurrent threads total
    TOTAL_THREADS = 50

    # Tenant groups
    readers = [f"tenant_{i:02d}" for i in range(1, 6)]      # tenants 01-05
    processors = [f"tenant_{i:02d}" for i in range(6, 11)]  # tenants 06-10
    attacker = ["tenant_99"]

    # Desired distribution: Readers (high frequency), Processors (low heavy requests), Attacker (1 tenant)
    # We'll assign threads per tenant programmatically to reach TOTAL_THREADS.

    # Base allocation
    readers_threads_total = 20
    processors_threads_total = 24
    attacker_threads_total = TOTAL_THREADS - (readers_threads_total + processors_threads_total)
    if attacker_threads_total < 1:
        attacker_threads_total = 1

    # Compute threads per tenant dicts
    threads_per_tenant = {}
    # Readers: distribute evenly
    per_reader = readers_threads_total // len(readers)
    extra = readers_threads_total % len(readers)
    for i, tid in enumerate(readers):
        threads_per_tenant[tid] = per_reader + (1 if i < extra else 0)

    # Processors: distribute evenly
    per_proc = processors_threads_total // len(processors)
    extra = processors_threads_total % len(processors)
    for i, tid in enumerate(processors):
        threads_per_tenant[tid] = per_proc + (1 if i < extra else 0)

    # Attacker threads
    threads_per_tenant['tenant_99'] = attacker_threads_total

    print(f"Thread distribution: readers={readers_threads_total}, processors={processors_threads_total}, attacker={attacker_threads_total}")
    print(f"Threads per tenant sample: {list(threads_per_tenant.items())[:6]}")

    # Warmup period for attacker (seconds)
    ATTACKER_WARMUP = 120  # 2 minutes

    now = time.time()

    # Start readers: high frequency to '/'
    start_threads_for_tenants(readers, '/', threads_per_tenant, base_delay=0.2, jitter=0.05, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start processors: low frequency to '/heavy_work'
    # These simulate real CPU-using tenants at low frequency
    start_threads_for_tenants(processors, '/heavy_work', threads_per_tenant, base_delay=3.0, jitter=1.0, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start attacker: starts with normal behavior (1s delay) for warmup, then switches to aggressive attack_delay
    attacker_attack_delay = 0.01  # very aggressive
    attacker_base_delay = 1.0     # normal behavior during warmup
    start_threads_for_tenants(attacker, '/heavy_work', threads_per_tenant, base_delay=attacker_base_delay, jitter=0.2, warmup=ATTACKER_WARMUP, attack_delay=attacker_attack_delay, warmup_start=now)

    print(f"⏳ System running with {TOTAL_THREADS} concurrent simulated users. Attacker warmup: {ATTACKER_WARMUP}s")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Load generator stopped.")