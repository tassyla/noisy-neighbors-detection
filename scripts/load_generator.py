import requests
import threading
import time
import random

TARGET_URL = "http://localhost:5000"

# Runtime stats
success_counts = {}
failure_counts = {}
error_log_lock = threading.Lock()
last_error_log = {}
# track consecutive failures per tenant to apply adaptive backoff
consecutive_failures = {}


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

            # apply adaptive backoff based on recent consecutive failures for this tenant
            backoff_factor = min(5.0, 0.1 * consecutive_failures.get(tenant_id, 0))

            # Make request with reasonable timeout so threads don't hang
            resp = session.get(f"{TARGET_URL}{endpoint}", headers={'X-Tenant-ID': tenant_id}, timeout=5)
            # record success/failure
            if resp.status_code >= 200 and resp.status_code < 400:
                success_counts[tenant_id] = success_counts.get(tenant_id, 0) + 1
                # reset consecutive failures on success
                consecutive_failures[tenant_id] = 0
            else:
                failure_counts[tenant_id] = failure_counts.get(tenant_id, 0) + 1
                consecutive_failures[tenant_id] = consecutive_failures.get(tenant_id, 0) + 1
            # If delay is zero, yield briefly to avoid tight CPU loop
            sleep_time = delay + backoff_factor
            if sleep_time <= 0:
                time.sleep(0.001)
            else:
                time.sleep(sleep_time)
        except Exception as e:
            # record a failure
            failure_counts[tenant_id] = failure_counts.get(tenant_id, 0) + 1
            consecutive_failures[tenant_id] = consecutive_failures.get(tenant_id, 0) + 1
            # rate-limit logging of exceptions per tenant (once every 10s)
            with error_log_lock:
                last = last_error_log.get(tenant_id, 0)
                if time.time() - last > 10:
                    print(f"⚠️ Tenant {tenant_id} request error: {e}")
                    last_error_log[tenant_id] = time.time()
            # sleep a bit and apply extra backoff proportional to consecutive failures
            extra = min(2.0, 0.2 * consecutive_failures.get(tenant_id, 1))
            time.sleep(0.5 + extra)


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


def reporter_thread(interval=10):
    """Print aggregated success/failure stats periodically."""
    while True:
        time.sleep(interval)
        total_succ = sum(success_counts.values())
        total_fail = sum(failure_counts.values())
        print(f"📈 Stats (last {interval}s): total_success={total_succ}, total_failure={total_fail}")
        # print per-tenant top contributors
        for tid in sorted(set(list(success_counts.keys()) + list(failure_counts.keys()))):
            s = success_counts.get(tid, 0)
            f = failure_counts.get(tid, 0)
            if s + f > 0:
                print(f"  - {tid}: success={s}, fail={f}")


def connectivity_check(retries=3, timeout=3):
    """Simple preflight: try a few GETs to the root and /heavy_work endpoints.
    Returns True on first successful request, False otherwise.
    """
    import requests as _requests
    # Try a set of common hostnames used in local/docker setups
    candidates = ["http://localhost:5000", "http://127.0.0.1:5000", "http://host.docker.internal:5000"]
    for base in candidates:
        urls = [f"{base}/", f"{base}/heavy_work"]
        for url in urls:
            for attempt in range(1, retries + 1):
                try:
                    r = _requests.get(url, timeout=timeout)
                    print(f"🔎 Preflight: GET {url} -> {r.status_code}")
                    if r.status_code >= 200 and r.status_code < 400:
                        # switch TARGET_URL to the working base for subsequent requests
                        global TARGET_URL
                        TARGET_URL = base
                        print(f"✅ Using TARGET_URL={TARGET_URL}")
                        return True
                    # otherwise try next endpoint or retry
                except Exception as e:
                    print(f"🔎 Preflight attempt {attempt} to {url} failed: {e}")
                time.sleep(0.5)
    return False


if __name__ == "__main__":
    print("🚀 Starting Load Generator (profiled)...")

    # Configuration: safer default to avoid overwhelming local dev server
    TOTAL_THREADS = 48

    # Tenant groups
    readers = [f"tenant_{i:02d}" for i in range(1, 6)]      # tenants 01-05
    processors = [f"tenant_{i:02d}" for i in range(6, 11)]  # tenants 06-10
    attacker = ["tenant_99"]

    # Desired distribution proportions (must sum to 1.0)
    readers_share = 0.41
    processors_share = 0.52
    attacker_share = 0.07

    # Compute integer thread totals that sum to TOTAL_THREADS
    readers_threads_total = max(1, int(round(TOTAL_THREADS * readers_share)))
    processors_threads_total = max(1, int(round(TOTAL_THREADS * processors_share)))
    # attacker gets the remainder to ensure sum equals TOTAL_THREADS
    attacker_threads_total = max(1, TOTAL_THREADS - (readers_threads_total + processors_threads_total))

    # Compute threads per tenant dicts (distribute evenly within groups)
    threads_per_tenant = {}
    per_reader = readers_threads_total // len(readers)
    extra = readers_threads_total % len(readers)
    for i, tid in enumerate(readers):
        threads_per_tenant[tid] = per_reader + (1 if i < extra else 0)

    per_proc = processors_threads_total // len(processors)
    extra = processors_threads_total % len(processors)
    for i, tid in enumerate(processors):
        threads_per_tenant[tid] = per_proc + (1 if i < extra else 0)

    # Attacker threads
    threads_per_tenant['tenant_99'] = attacker_threads_total

    print(f"Thread distribution (TOTAL_THREADS={TOTAL_THREADS}): readers={readers_threads_total}, processors={processors_threads_total}, attacker={attacker_threads_total}")
    print(f"Threads per tenant sample: {list(threads_per_tenant.items())[:6]}")

    # Warmup period for attacker (seconds)
    ATTACKER_WARMUP = 120  # 2 minutes

    now = time.time()
    # Emit a simple replay_plan.json describing attacker schedule so labeling can be authoritative.
    try:
        import json
        plan = {"events": []}
        # ATTACKER_WARMUP already defined; optionally set ATTACK_DURATION (seconds) here
        # If ATTACK_DURATION is None, plan will record start and leave end=null (labeler treats as open-ended)
        ATTACK_DURATION = None
        attacker_start_ts = now + ATTACKER_WARMUP
        if ATTACK_DURATION:
            attacker_end_ts = attacker_start_ts + ATTACK_DURATION
        else:
            attacker_end_ts = None

        from datetime import datetime as _dt
        start_iso = _dt.fromtimestamp(attacker_start_ts).isoformat()
        end_iso = _dt.fromtimestamp(attacker_end_ts).isoformat() if attacker_end_ts else None
        plan["events"].append({
            "attacker": "tenant_99",
            "start": start_iso,
            "end": end_iso,
        })

        with open("replay_plan.json", "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        print(f"🗂️ Wrote replay_plan.json (attacker start: {plan['events'][0]['start']}, end: {plan['events'][0]['end']})")
    except Exception as e:
        print(f"⚠️ Could not write replay_plan.json: {e}")
    # Run a simple connectivity preflight before starting many threads
    ok = connectivity_check(retries=3, timeout=3)
    if not ok:
        print()
        print("✋ Preflight failed: cannot reach the webapp. Aborting load generator to avoid spamming." )
        print("Suggestions:")
        print(" - Verify the webapp is running and listening on port 5000 (inside container or locally).")
        print(" - If using Docker, run: docker compose ps  OR docker ps")
        print(" - Check webapp logs: docker compose logs webapp --follow")
        print(" - Try a manual curl from this host: curl -v http://127.0.0.1:5000/")
        print(" - On Windows, inspect sockets: Get-NetTCPConnection -LocalPort 5000")
        raise SystemExit(1)

    # Start readers: high frequency to '/'
    start_threads_for_tenants(readers, '/', threads_per_tenant, base_delay=0.2, jitter=0.05, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start processors: low frequency to '/heavy_work'
    # These simulate real CPU-using tenants at low frequency
    start_threads_for_tenants(processors, '/heavy_work', threads_per_tenant, base_delay=3.0, jitter=1.0, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start attacker: starts with normal behavior (1s delay) for warmup, then switches to aggressive attack_delay
    attacker_attack_delay = 0.05  # less aggressive by default
    attacker_base_delay = 1.0     # normal behavior during warmup
    start_threads_for_tenants(attacker, '/heavy_work', threads_per_tenant, base_delay=attacker_base_delay, jitter=0.2, warmup=ATTACKER_WARMUP, attack_delay=attacker_attack_delay, warmup_start=now)

    print(f"⏳ System running with {TOTAL_THREADS} concurrent simulated users. Attacker warmup: {ATTACKER_WARMUP}s")
    # start reporter thread
    t_reporter = threading.Thread(target=reporter_thread, args=(10,), daemon=True)
    t_reporter.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Load generator stopped.")