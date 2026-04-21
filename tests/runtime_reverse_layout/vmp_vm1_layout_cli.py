from __future__ import annotations

from common import ROOT, VM1_REVERSE_FLAG, parse_vm1, require, run_cmd, temp_path


def main() -> None:
    build = ROOT / "build"
    asm = build / "tools" / "vmp-vm1-asm"
    layout = build / "tools" / "vmp-vm1-layout"
    fib = ROOT / "tests" / "runtime_vm1" / "fixtures" / "fib20.vm1s"
    module = temp_path("vm1_layout_cli", ".vm1")

    run_cmd([asm, "--no-encrypt-opcodes", fib, module])
    original = module.read_bytes()
    forward_report = run_cmd([layout, module]).stdout
    require("layout=forward" in forward_report, "forward report missing layout=forward")

    run_cmd([layout, "--convert-to-reverse", module])
    reverse_report = run_cmd([layout, module]).stdout
    require("layout=reverse" in reverse_report, "reverse report missing layout=reverse")
    require("instruction_count=" in reverse_report, "reverse report missing instruction_count")
    require("length_table_checksum=" in reverse_report, "reverse report missing checksum")
    require((parse_vm1(module)["flags"] & VM1_REVERSE_FLAG) != 0, "reverse flag missing after conversion")

    run_cmd([layout, "--convert-to-forward", module])
    require(module.read_bytes() == original, "forward -> reverse -> forward must be byte identical")
    print("vmp_vm1_layout_cli OK")


if __name__ == "__main__":
    main()
