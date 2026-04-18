#!/usr/bin/env python3
import subprocess
import sys

exe, policy = sys.argv[1], sys.argv[2]
proc = subprocess.run([exe, '--policy', policy], text=True, capture_output=True)
combined = proc.stdout + proc.stderr
if proc.returncode == 0:
    print(combined)
    raise SystemExit('expected non-zero exit code')
if 'vm_func_native' not in combined:
    print(combined)
    raise SystemExit('expected vm_func_native in output')
print('bad policy rejected as expected')
