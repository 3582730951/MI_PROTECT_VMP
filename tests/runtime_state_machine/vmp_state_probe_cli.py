import subprocess
import sys
import tempfile
from pathlib import Path


def run_case(exe: Path, event: str):
    audit = Path(tempfile.mkstemp(prefix='vmp_state_probe_', suffix='.log')[1])
    cp = subprocess.run([str(exe), '--no-exit', '--audit', str(audit), '--event', event], capture_output=True, text=True)
    if cp.returncode != 0:
        raise SystemExit(f'probe failed for {event}: {cp.stderr}')
    out = cp.stdout
    log = audit.read_text() if audit.exists() else ''
    if 'state=Ready' not in out or 'after=' not in out:
        raise SystemExit(f'missing state output for {event}: {out}')
    if event.startswith('integrity_failed') and 'integrity_failed' not in log:
        raise SystemExit('missing integrity_failed audit line')
    if event == 'shutdown' and 'terminating_grace_start' not in log:
        raise SystemExit('missing terminating_grace_start audit line')
    if event == 'env_anomaly' and 'state_transition' not in log:
        raise SystemExit('missing state_transition audit line')


def main():
    exe = Path(sys.argv[1])
    for event in ['integrity_failed:region_X', 'env_anomaly', 'shutdown', 'hw_breakpoint']:
        run_case(exe, event)
    print('vmp_state_probe_cli OK')


if __name__ == '__main__':
    main()
