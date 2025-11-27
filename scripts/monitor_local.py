import csv
import time
import datetime
import sys

# Try to import docker SDK; if not available we'll fall back to psutil process monitoring
try:
    import docker
    _HAS_DOCKER = True
except Exception:
    _HAS_DOCKER = False

import psutil


def find_app_process():
    """Return a psutil.Process instance running the app (app/app.py), or None."""
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            if not cmdline:
                continue
            # join to a single string to search for script path patterns
            joined = ' '.join(cmdline)
            if 'app/app.py' in joined or 'app\\app.py' in joined or joined.rstrip().endswith('app.py'):
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def find_app_container():
    """Return a docker.Container for the webapp if found, else None.

    The function looks for containers with a name containing 'webapp' or whose command
    references 'app.py'. Requires the docker SDK and daemon accessible from this host.
    """
    if not _HAS_DOCKER:
        return None
    try:
        client = docker.from_env()
        for c in client.containers.list():
            name = (c.name or '').lower()
            # try to inspect command/config
            cmd = ''
            try:
                cfg = c.attrs.get('Config', {})
                cmd_list = cfg.get('Cmd') or cfg.get('Entrypoint') or []
                if isinstance(cmd_list, (list, tuple)):
                    cmd = ' '.join([str(x) for x in cmd_list if x])
                else:
                    cmd = str(cmd_list)
            except Exception:
                cmd = ''

            if 'webapp' in name or 'app.py' in cmd or 'app/app.py' in cmd:
                return c
    except Exception:
        return None
    return None


def main():
    # Prefer monitoring the Docker container if available
    container = find_app_container()
    if container:
        print(f'Found app container: {container.name} (id={container.id[:12]})')
        csv_path = 'scripts/metrics_cpu.csv'
        f = open(csv_path, 'w', newline='', encoding='utf-8')
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'cpu_percent'])
        f.flush()

        try:
            # We'll poll docker stats twice and compute CPU percent from delta
            while True:
                prev = container.stats(stream=False)
                time.sleep(1)
                cur = container.stats(stream=False)

                try:
                    prev_cpu = prev['cpu_stats']['cpu_usage']['total_usage']
                    cur_cpu = cur['cpu_stats']['cpu_usage']['total_usage']
                    prev_system = prev['cpu_stats'].get('system_cpu_usage') or prev.get('system_cpu_usage')
                    cur_system = cur['cpu_stats'].get('system_cpu_usage') or cur.get('system_cpu_usage')
                    # number of CPUs
                    online_cpus = cur['cpu_stats'].get('online_cpus') or len(cur['cpu_stats']['cpu_usage'].get('percpu_usage', []) ) or 1

                    cpu_delta = cur_cpu - prev_cpu
                    system_delta = (cur_system or 0) - (prev_system or 0)
                    if system_delta > 0 and cpu_delta > 0:
                        cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
                    else:
                        cpu_percent = 0.0
                except Exception:
                    cpu_percent = 0.0

                ts = datetime.datetime.now().isoformat()
                writer.writerow([ts, round(cpu_percent, 3)])
                f.flush()
                print(f'{ts} container_cpu_percent={cpu_percent:.3f}%')

                # Check if container is still running
                container.reload()
                if container.status != 'running':
                    print('Container stopped. Exiting monitor.')
                    break

        except KeyboardInterrupt:
            print('\nKeyboardInterrupt received — closing container monitor.')
        finally:
            try:
                f.close()
            except Exception:
                pass
        return

    # Fallback: monitor a local process (non-container)
    print('Docker container not found or docker SDK unavailable — falling back to process monitoring')
    print('Searching for app process (app/app.py)...')
    proc = find_app_process()
    while proc is None:
        print('Waiting for app...')
        time.sleep(2)
        proc = find_app_process()

    print(f'Found app process PID={proc.pid}')

    csv_path = 'scripts/metrics_cpu.csv'
    f = open(csv_path, 'w', newline='', encoding='utf-8')
    writer = csv.writer(f)
    writer.writerow(['timestamp', 'cpu_percent'])
    f.flush()

    try:
        while True:
            try:
                # interval=1 blocks ~1 second and returns percent over that interval
                cpu = proc.cpu_percent(interval=1)
            except psutil.NoSuchProcess:
                print('App process terminated. Exiting monitor.')
                break

            ts = datetime.datetime.now().isoformat()
            writer.writerow([ts, cpu])
            f.flush()
            print(f'{ts} cpu_percent={cpu}%')

            # if process has ended, stop monitoring
            if not proc.is_running():
                print('App process not running anymore. Exiting monitor.')
                break

    except KeyboardInterrupt:
        print('\nKeyboardInterrupt received — closing monitor.')
    finally:
        try:
            f.close()
        except Exception:
            pass


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Monitor failed:', e, file=sys.stderr)
        sys.exit(1)
