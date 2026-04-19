#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import VM1_CALL_OPCODE, VM1_ENCRYPTED_FLAG, parse_vm1_module, require, run_cmd, temp_path


def main() -> int:
    vm1_asm = pathlib.Path(sys.argv[1])
    fixture = pathlib.Path(sys.argv[2])

    module_path = temp_path("vm1_no_encrypt", ".vm1")
    run_cmd([vm1_asm, "--no-encrypt-opcodes", fixture, module_path])
    parsed = parse_vm1_module(module_path)

    require((parsed.flags & VM1_ENCRYPTED_FLAG) == 0, "--no-encrypt-opcodes must clear VM1 encrypted flag")
    first_opcode = int.from_bytes(parsed.code[:2], "little")
    require(first_opcode == VM1_CALL_OPCODE, "identity VM1 code stream must keep canonical first opcode")

    print("cryptor_flag_off_identity OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
