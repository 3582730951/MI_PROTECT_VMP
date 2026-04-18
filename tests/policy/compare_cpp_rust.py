#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

cpp_bin = Path(sys.argv[1])
policy_file = Path(sys.argv[2])
repo_root = Path(sys.argv[3])

cpp = json.loads(subprocess.check_output([str(cpp_bin), str(policy_file)], text=True))
rust = json.loads(
    subprocess.check_output(
        ["cargo", "run", "-q", "-p", "vmp-policy", "--example", "summary", "--", str(policy_file)],
        text=True,
        cwd=repo_root,
    )
)

assert cpp == rust, f"cpp != rust\ncpp={cpp}\nrust={rust}"
print("compare_cpp_rust OK")
