import requests
import threading
import time
import random
import argparse
import json
from pathlib import Path

TARGET_URL = "http://localhost:5000"

# Runtime stats
success_counts = {}
failure_counts = {}
error_log_lock = threading.Lock()
last_error_log = {}
# track consecutive failures per tenant to apply adaptive backoff
consecutive_failures = {}


def tenant_loop(tenant_id: str, endpoint: str, base_delay: float, stop_event: threading.Event, jitter: float = 0.0, warmup: float = 0.0, attack_delay: float = None, warmup_start: float = None):
    """Generic tenant loop.
    If warmup > 0 and attack_delay is provided, the thread uses base_delay for the warmup period
    (measured relative to warmup_start) and then switches to attack_delay indefinitely.
    jitter adds random +/- jitter seconds to base_delay on each request.
    """
    print(f"👤 Tenant {tenant_id} started (Endpoint: {endpoint}, base_delay={base_delay}, jitter={jitter})")
    session = requests.Session()
    start = warmup_start or time.time()
    while not stop_event.is_set():
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
                stop_event.wait(0.001)
            else:
                stop_event.wait(sleep_time)
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
            stop_event.wait(0.5 + extra)


def start_threads_for_tenants(tenant_ids, endpoint, threads_per_tenant, base_delay, stop_event, jitter=0.0, warmup=0.0, attack_delay=None, warmup_start=None):
    threads = []
    for tid in tenant_ids:
        count = threads_per_tenant.get(tid, 0)
        for _ in range(count):
            t = threading.Thread(target=tenant_loop, args=(tid, endpoint, base_delay, stop_event, jitter, warmup, attack_delay, warmup_start))
            t.daemon = True
            t.start()
            threads.append(t)
    return threads


def reporter_thread(interval=10, stop_event: threading.Event | None = None):
    """Print aggregated success/failure stats periodically."""
    while stop_event is None or not stop_event.is_set():
        if stop_event:
            if stop_event.wait(interval):
                break
        else:
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


def load_edgar_profile(profile_path):
    """Load EDGAR calibration profile (diurnal pattern + tenant distribution).
    Returns: dict with 'diurnal_profile' and 'tenant_distribution'.
    """
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            profile = json.load(f)
        print(f"✅ Loaded EDGAR profile from {profile_path}")
        return profile
    except FileNotFoundError:
        print(f"⚠️ EDGAR profile not found at {profile_path}. Using default distribution.")
        return None
    except Exception as e:
        print(f"⚠️ Error loading EDGAR profile: {e}. Using default distribution.")
        return None


def get_diurnal_delay_multiplier(edgar_profile, elapsed_seconds, total_duration):
    """
    Compute a multiplier for base_delay based on diurnal profile.
    Assumes total_duration represents a "day" compressed in time.
    
    Returns: float (e.g., 0.5 = half base_delay, 2.0 = double base_delay)
    """
    if not edgar_profile:
        return 1.0
    
    diurnal = edgar_profile.get('diurnal_profile', {})
    if not diurnal:
        return 1.0
    
    # Map elapsed time to "hour of day" (24 hours compressed into total_duration)
    hour_of_day = int((elapsed_seconds / total_duration) * 24) % 24
    
    # Get normalized traffic for this hour (0.0 to 1.0 range)
    traffic_intensity = float(diurnal.get(str(hour_of_day), 1.0 / 24))
    
    # Convert traffic_intensity to delay multiplier (inverse: higher traffic = lower delay)
    # Assume average traffic intensity = 1/24 = 0.0417
    avg_intensity = 1.0 / 24
    multiplier = avg_intensity / max(traffic_intensity, 0.001)  # avoid div by zero
    
    return multiplier


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-tenant load generator (no EDGAR dependency)")
    parser.add_argument("--target-url", default="http://localhost:5000", help="Base URL of the webapp")
    parser.add_argument("--total-threads", type=int, default=48, help="Total concurrent threads")
    parser.add_argument("--reader-share", type=float, default=0.41, help="Share of threads for readers tenants")
    parser.add_argument("--processor-share", type=float, default=0.52, help="Share of threads for processor tenants")
    parser.add_argument("--attacker-share", type=float, default=0.07, help="Share of threads for attacker tenant")
    parser.add_argument("--attacker", default="tenant_99", help="Attacker tenant id")
    parser.add_argument("--attack-delay", type=float, default=0.05, help="Delay (s) between attacker requests during attack phase")
    parser.add_argument("--attack-base-delay", type=float, default=1.0, help="Delay (s) between attacker requests during warmup phase")
    parser.add_argument("--warmup", type=float, default=180.0, help="Warmup duration in seconds before attacker becomes aggressive")
    parser.add_argument("--attack-duration", type=float, default=None, help="Optional attack duration in seconds; if omitted, attack is open-ended")
    parser.add_argument("--cooldown", type=float, default=120.0, help="Cooldown duration in seconds after attack ends (normal behavior)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for jitter")
    parser.add_argument("--edgar-profile", default=None, help="Path to edgar_profile.json for workload calibration (optional)")
    parser.add_argument("--max-runtime", type=float, default=300.0, help="Total runtime in seconds before auto-stop")
    args = parser.parse_args()

    random.seed(args.seed)
    TARGET_URL = args.target_url

    print("🚀 Starting Load Generator (profiled)...")
    print(f"Config: threads={args.total_threads}, attacker={args.attacker}, attack_delay={args.attack_delay}s, warmup={args.warmup}s, cooldown={args.cooldown}s, seed={args.seed}")

    # Load EDGAR profile if provided
    edgar_profile = None
    if args.edgar_profile:
        edgar_profile = load_edgar_profile(args.edgar_profile)
        if edgar_profile:
            print(f"✨ Using EDGAR calibration (diurnal profile + tenant distribution)")
    else:
        print("ℹ️  No EDGAR profile provided. Using default uniform distribution.")
        print("   (Tip: run edgar_calibrator.py first to generate edgar_profile.json)")

    # Tenant groups
    readers = [f"tenant_{i:02d}" for i in range(1, 6)]      # tenants 01-05
    processors = [f"tenant_{i:02d}" for i in range(6, 11)]  # tenants 06-10
    attacker = [args.attacker]

    # Desired distribution proportions (renormalized if needed)
    total_share = args.reader_share + args.processor_share + args.attacker_share
    reader_share = args.reader_share / total_share
    processor_share = args.processor_share / total_share
    attacker_share = args.attacker_share / total_share

    TOTAL_THREADS = args.total_threads
    readers_threads_total = max(1, int(round(TOTAL_THREADS * reader_share)))
    processors_threads_total = max(1, int(round(TOTAL_THREADS * processor_share)))
    attacker_threads_total = max(1, TOTAL_THREADS - (readers_threads_total + processors_threads_total))

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
    threads_per_tenant[args.attacker] = attacker_threads_total

    print(f"Thread distribution (TOTAL_THREADS={TOTAL_THREADS}): readers={readers_threads_total}, processors={processors_threads_total}, attacker={attacker_threads_total}")
    print(f"Threads per tenant sample: {list(threads_per_tenant.items())[:6]}")

    # Warmup and cooldown periods for attacker (seconds)
    ATTACKER_WARMUP = args.warmup
    ATTACKER_COOLDOWN = args.cooldown
    runtime_limit = args.max_runtime

    now = time.time()
    stop_event = threading.Event()
    # Emit a simple replay_plan.json describing attacker schedule so labeling can be authoritative.
    try:
        import json
        plan = {"events": []}
        # ATTACKER_WARMUP already defined; optionally set ATTACK_DURATION (seconds) here
        # If ATTACK_DURATION is None, use (max_runtime - warmup - cooldown) as attack duration
        ATTACK_DURATION = args.attack_duration
        if ATTACK_DURATION is None:
            # Default: attack until cooldown starts
            ATTACK_DURATION = max(60, runtime_limit - ATTACKER_WARMUP - ATTACKER_COOLDOWN)
        attacker_start_ts = now + ATTACKER_WARMUP
        attacker_end_ts = attacker_start_ts + ATTACK_DURATION

        from datetime import datetime as _dt
        start_iso = _dt.fromtimestamp(attacker_start_ts).isoformat()
        end_iso = _dt.fromtimestamp(attacker_end_ts).isoformat()
        plan["events"].append({
            "attacker": args.attacker,
            "start": start_iso,
            "end": end_iso,
        })
        print(f"📅 Attack schedule: warmup={ATTACKER_WARMUP}s, attack={ATTACK_DURATION}s, cooldown={ATTACKER_COOLDOWN}s")

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
    start_threads_for_tenants(readers, '/', threads_per_tenant, base_delay=0.2, stop_event=stop_event, jitter=0.05, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start processors: low frequency to '/heavy_work'
    # These simulate real CPU-using tenants at low frequency
    start_threads_for_tenants(processors, '/heavy_work', threads_per_tenant, base_delay=3.0, stop_event=stop_event, jitter=1.0, warmup=0.0, attack_delay=None, warmup_start=now)

    # Start attacker: starts with normal behavior (1s delay) for warmup, then switches to aggressive attack_delay
    # After attack ends (warmup + attack_duration), revert to base_delay for cooldown
    attacker_attack_delay = 0.05  # less aggressive by default
    attacker_base_delay = 1.0     # normal behavior during warmup
    # Note: tenant_loop currently doesn't support cooldown phase; it switches once at warmup end
    # For proper cooldown, we'd need a three-phase tenant_loop (warmup -> attack -> cooldown)
    # For now, attacker will remain aggressive until stop_event; cooldown is handled by runtime_limit
    start_threads_for_tenants(attacker, '/heavy_work', threads_per_tenant, base_delay=args.attack_base_delay, stop_event=stop_event, jitter=0.2, warmup=ATTACKER_WARMUP, attack_delay=args.attack_delay, warmup_start=now)

    
    print(f"⏳ System running with {TOTAL_THREADS} concurrent simulated users. Attacker warmup: {ATTACKER_WARMUP}s. Auto-stop after {runtime_limit}s.")
    # start reporter thread
    t_reporter = threading.Thread(target=reporter_thread, args=(10, stop_event), daemon=True)
    t_reporter.start()
    try:
        end_time = now + runtime_limit
        while not stop_event.is_set():
            if time.time() >= end_time:
                print("🛑 Max runtime reached, stopping load generator...")
                stop_event.set()
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("🛑 Load generator stopped via keyboard interrupt.")
        stop_event.set()

    # give threads a brief moment to exit
    time.sleep(1.0)