#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import patch_seed, require, run_cmd, temp_path


def main() -> int:
    vm1_asm = pathlib.Path(sys.argv[1])
    vm1_run = pathlib.Path(sys.argv[2])
    fixture = pathlib.Path(sys.argv[3])

    clean_module = temp_path("vm1_opcode_tamper", ".vm1")
    tampered_module = temp_path("vm1_opcode_tamper", ".vm1")
    audit_path = temp_path("vm1_opcode_tamper", ".log")

    run_cmd([vm1_asm, "--opcode-seed", "11111111111111111111111111111111", fixture, clean_module])
    tampered_module.write_bytes(clean_module.read_bytes())
    patch_seed(tampered_module, bytes.fromhex("22222222222222222222222222222222"), vm="vm1")

    completed = run_cmd([vm1_run, "--audit-path", audit_path, tampered_module, "20"], expected=(1,))
    require("opcode" in completed.stderr.lower(), "expected opcode-map validation failure in stderr")
    require("opcode_map_invalid" in audit_path.read_text(), "expected opcode_map_invalid audit event")

    print("cryptor_tampered_seed_detected OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
