#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import require, run_cmd, seeded_hex_values, temp_path


def main() -> int:
    vm1_asm = pathlib.Path(sys.argv[1])
    vm1_run = pathlib.Path(sys.argv[2])
    fixture = pathlib.Path(sys.argv[3])

    for index, seed_hex in enumerate(seeded_hex_values(5)):
        module_path = temp_path(f"vm1_fib20_seed_{index}", ".vm1")
        run_cmd([vm1_asm, "--opcode-seed", seed_hex, fixture, module_path])
        completed = run_cmd([vm1_run, module_path, "20"])
        require("ret_int=6765" in completed.stdout, f"vm1 fib20 incorrect for seed {seed_hex}")

    print("cryptor_semantic_equivalence_fib20 OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
