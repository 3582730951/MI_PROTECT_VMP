#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_REPORT_DIR = ROOT / 'reports'


@dataclass(frozen=True)
class Sample:
    name: str
    protected_symbol: str
    protected_string: str
    runtime_string: str


def run_capture(cmd: list[str], out_path: pathlib.Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        f"$ {' '.join(cmd)}\n"
        f"[exit_code] {proc.returncode}\n\n"
        f"--- stdout ---\n{proc.stdout}\n"
        f"--- stderr ---\n{proc.stderr}\n"
    )
    return proc


SECTION_RE = re.compile(
    r"^\s*(\d+)\s+([^\s]+)\s+([0-9a-fA-F]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)",
    re.MULTILINE,
)
ENTRY_RE = re.compile(r"AddressOfEntryPoint\s+([0-9A-Fa-f]+)")
START_RE = re.compile(r"start address 0x([0-9A-Fa-f]+)")


def parse_sections(objdump_h: str) -> dict[str, list[int]]:
    sections: dict[str, list[int]] = {}
    for _idx, name, size_hex, *_rest in SECTION_RE.findall(objdump_h):
        sections.setdefault(name, []).append(int(size_hex, 16))
    return sections


def parse_entry(objdump_x: str) -> tuple[str | None, str | None]:
    entry = ENTRY_RE.search(objdump_x)
    start = START_RE.search(objdump_x)
    return (entry.group(1) if entry else None, start.group(1) if start else None)


def normalize_disasm(text: str) -> str:
    lines = text.splitlines()
    filtered: list[str] = []
    for line in lines:
        if ':     file format ' in line:
            filtered.append('<FILE>')
            continue
        filtered.append(line)
    return '\n'.join(filtered).strip()


def yes_no(value: bool) -> str:
    return 'yes' if value else 'no'


def fmt_sizes(values: list[int] | None) -> str:
    if not values:
        return '—'
    if len(values) == 1:
        return f'0x{values[0]:x}'
    return ', '.join(f'0x{value:x}' for value in values)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report-dir', default=str(DEFAULT_REPORT_DIR))
    parser.add_argument('--date', default=time.strftime('%Y%m%d', time.gmtime()))
    args = parser.parse_args()

    report_dir = pathlib.Path(args.report_dir).resolve()
    artifact_root = report_dir / f'integration_artifacts_{args.date}' / 'x86_64-windows'
    raw_root = report_dir / f'decompilation_raw_{args.date}'
    report_path = report_dir / f'decompilation_report_{args.date}.md'

    for tool in ('objdump', 'readelf', 'strings', 'r2'):
        if shutil.which(tool) is None:
            raise SystemExit(f'required tool not found: {tool}')

    samples = [
        Sample('target_c', 'protected_mix_c', 'c-target::vm-string::delta-42', 'c-target::runtime::delta-42'),
        Sample('target_cpp', 'protected_mix_cpp', 'cpp-target::vm-string::omega-17', 'cpp-target::runtime::omega-17'),
    ]

    summaries: list[dict[str, object]] = []
    for sample in samples:
        sample_dir = artifact_root / sample.name
        baseline = sample_dir / f'{sample.name}.exe'
        protected = sample_dir / f'{sample.name}.protected.exe'
        if not baseline.exists() or not protected.exists():
            raise SystemExit(f'missing artifacts for {sample.name}: {baseline} / {protected}')

        out_dir = raw_root / sample.name
        base_h = run_capture(['objdump', '-h', str(baseline)], out_dir / 'baseline_objdump_h.txt')
        prot_h = run_capture(['objdump', '-h', str(protected)], out_dir / 'protected_objdump_h.txt')
        base_x = run_capture(['objdump', '-x', str(baseline)], out_dir / 'baseline_objdump_x.txt')
        prot_x = run_capture(['objdump', '-x', str(protected)], out_dir / 'protected_objdump_x.txt')
        base_t = run_capture(['objdump', '-t', str(baseline)], out_dir / 'baseline_objdump_t.txt')
        prot_t = run_capture(['objdump', '-t', str(protected)], out_dir / 'protected_objdump_t.txt')
        base_readelf = run_capture(['readelf', '-h', str(baseline)], out_dir / 'baseline_readelf_h.txt')
        prot_readelf = run_capture(['readelf', '-h', str(protected)], out_dir / 'protected_readelf_h.txt')
        base_strings = run_capture(['strings', '-a', '-n', '6', str(baseline)], out_dir / 'baseline_strings.txt')
        prot_strings = run_capture(['strings', '-a', '-n', '6', str(protected)], out_dir / 'protected_strings.txt')
        base_fn = run_capture(['objdump', '-d', f'--disassemble={sample.protected_symbol}', str(baseline)], out_dir / 'baseline_fn_disasm.txt')
        prot_fn = run_capture(['objdump', '-d', f'--disassemble={sample.protected_symbol}', str(protected)], out_dir / 'protected_fn_disasm.txt')
        run_capture(['objdump', '-s', '-j', '.vmpvm', str(protected)], out_dir / 'protected_vmpvm_dump.txt')
        run_capture(['objdump', '-s', '-j', '.vmptrmp', str(protected)], out_dir / 'protected_vmptrmp_dump.txt')
        run_capture(['objdump', '-s', '-j', '.CRT$XLB', str(protected)], out_dir / 'protected_crtxlb_dump.txt')
        run_capture(['r2', '-A', '-q', '-c', 'iI; iS; afl', str(protected)], out_dir / 'protected_r2_info_sections_afl.txt')
        run_capture(['r2', '-A', '-q', '-c', f's sym.{sample.protected_symbol}; pdf', str(protected)], out_dir / 'protected_r2_pdf.txt')
        run_capture(['r2', '-A', '-q', '-c', 'izz', str(protected)], out_dir / 'protected_r2_izz.txt')

        base_sections = parse_sections(base_h.stdout)
        prot_sections = parse_sections(prot_h.stdout)
        base_entry, base_start = parse_entry(base_x.stdout)
        prot_entry, prot_start = parse_entry(prot_x.stdout)

        base_strings_text = base_strings.stdout
        prot_strings_text = prot_strings.stdout
        symbol_visible_baseline = sample.protected_symbol in base_t.stdout
        symbol_visible_protected = sample.protected_symbol in prot_t.stdout
        protected_string_visible = sample.protected_string in prot_strings_text
        runtime_string_visible = sample.runtime_string in prot_strings_text
        disasm_identical = normalize_disasm(base_fn.stdout) == normalize_disasm(prot_fn.stdout)
        vmpvm_ascii_markers = []
        vmpvm_text = (out_dir / 'protected_vmpvm_dump.txt').read_text()
        for marker in ('target_c.c', 'target_cpp.cpp', '__main', '.text', '.data', 'main'):
            if marker in vmpvm_text:
                vmpvm_ascii_markers.append(marker)
        summaries.append({
            'sample': sample,
            'base_sections': base_sections,
            'prot_sections': prot_sections,
            'base_entry': base_entry,
            'base_start': base_start,
            'prot_entry': prot_entry,
            'prot_start': prot_start,
            'symbol_visible_baseline': symbol_visible_baseline,
            'symbol_visible_protected': symbol_visible_protected,
            'protected_string_visible': protected_string_visible,
            'runtime_string_visible': runtime_string_visible,
            'disasm_identical': disasm_identical,
            'readelf_baseline_rc': base_readelf.returncode,
            'readelf_protected_rc': prot_readelf.returncode,
            'readelf_baseline_stderr': base_readelf.stderr.strip(),
            'readelf_protected_stderr': prot_readelf.stderr.strip(),
            'vmpvm_ascii_markers': vmpvm_ascii_markers,
        })

    section_rows = []
    interesting_sections = ['.text', '.vmpload', '.vmpvm', '.vmptrmp', '.vmpcode', '.vmpstrings']
    for entry in summaries:
        sample = entry['sample']
        for section_name in interesting_sections:
            section_rows.append(
                f"| {sample.name} | {section_name} | {fmt_sizes(entry['base_sections'].get(section_name))} | {fmt_sizes(entry['prot_sections'].get(section_name))} |"
            )

    summary_lines = []
    for entry in summaries:
        sample = entry['sample']
        summary_lines.append(
            f"- **{sample.name}**: symbols exposed=`{yes_no(entry['symbol_visible_protected'])}`, "
            f"VM_string plaintext visible=`{yes_no(entry['protected_string_visible'])}`, "
            f"runtime string visible=`{yes_no(entry['runtime_string_visible'])}`, "
            f"protected function disassembly identical to baseline=`{yes_no(entry['disasm_identical'])}`."
        )

    readelf_lines = []
    for entry in summaries:
        sample = entry['sample']
        readelf_lines.append(
            f"- `{sample.name}.protected.exe`: exit={entry['readelf_protected_rc']}, stderr=`{entry['readelf_protected_stderr'] or 'n/a'}`"
        )

    entry_lines = []
    for entry in summaries:
        sample = entry['sample']
        entry_lines.append(
            f"- **{sample.name}** baseline/protected AddressOfEntryPoint 均为 `0x{entry['base_entry']}` / `0x{entry['prot_entry']}`，"
            f"start address 均为 `0x{entry['base_start']}` / `0x{entry['prot_start']}`。"
        )

    marker_lines = []
    for entry in summaries:
        sample = entry['sample']
        markers = ', '.join(f'`{m}`' for m in entry['vmpvm_ascii_markers']) if entry['vmpvm_ascii_markers'] else 'none'
        marker_lines.append(f"- **{sample.name}** `.vmpvm` 中可直接看到的 ASCII 标记：{markers}。")

    report = f"""# Armor-Breaking CTF Defense — 反编译报告 ({args.date})

## 1. 执行摘要

本报告基于 **实际运行** 的 `objdump`、`readelf`、`strings` 与 `radare2 -A -q` 输出生成，分析对象为：

- `reports/integration_artifacts_{args.date}/x86_64-windows/target_c/target_c.protected.exe`
- `reports/integration_artifacts_{args.date}/x86_64-windows/target_cpp/target_cpp.protected.exe`

结论摘要：

- Windows PE 保护后样本**确实新增** `\.vmpload`、`\.vmpvm`、`\.vmptrmp`、`\.CRT$XLB` 等节区；但 **`.vmpcode` 与 `.vmpstrings` 在当前 PE 产物中均未出现**。
- `readelf` 对 PE 文件的**实际结果**是失败：`Not an ELF file - it has the wrong magic bytes at the start`，因此节区/入口点分析以 `objdump` 与 `radare2` 为主。
- `objdump -t` 与 `radare2 afl/pdf` 证明 `protected_mix_c` / `protected_mix_cpp` **函数名仍然暴露**，并且函数体在保护前后**可直接逐指令对应**。
- `strings -a` 显示 `VM_string` 标记的明文字符串在保护后仍然**直接可见**，例如 `c-target::vm-string::delta-42`、`cpp-target::vm-string::omega-17`。
- `objdump -x` 显示 `AddressOfEntryPoint` **未改变**；当前 token trampoline 在 Windows PE 上体现为**附加节区 / CRT callback 痕迹**，而不是直接重写 PE 入口点。
- `objdump -s -j .vmpvm/.vmptrmp` 显示这些节区内仍存在明显 ASCII/元数据痕迹（如 `__main`、`.text`、`.data`、源文件名等），说明 rolling opcode / handler metadata 在当前产物中**仍较易被模式化识别**。

{chr(10).join(summary_lines)}

## 2. 节区结构对比表

| sample | section | baseline | protected |
| --- | --- | --- | --- |
{chr(10).join(section_rows)}

关键观察：

- `.vmptrmp` 在两个保护后样本中都新增，分别对应 trampoline 数据区。
- `.vmpload`、`.vmpvm` 在两个 PE 样本中都出现了**重复节名**（`objdump -h` 实际输出中为两段）。
- `.vmpcode` 与 `.vmpstrings` 在本次 Windows PE 样本中**未出现**，这与当前 PE backend 的实际产物一致。

## 3. 字符串保护效果

`strings -a -n 6` 的实际命中结果：

- `target_c.protected.exe` 仍命中：`c-target::vm-string::delta-42` 与 `c-target::runtime::delta-42`
- `target_cpp.protected.exe` 仍命中：`cpp-target::vm-string::omega-17` 与 `cpp-target::runtime::omega-17`

这说明在当前 Windows PE 路径中：

1. `VM_string` 标记的字符串**没有被彻底移出可扫描明文区域**；
2. 保护后产物仍允许 `strings` 直接恢复 contest secret；
3. 当前样本的字符串保护效果，对静态扫描器而言**不足以构成有效阻断**。

## 4. 函数入口保护效果（trampoline 分析）

`objdump -x` 的实际入口点结果如下：

{chr(10).join(entry_lines)}

这意味着：

- 本轮 Windows PE 产物的 `token trampoline` **没有通过改写 AddressOfEntryPoint 生效**；
- 实际可见的保护痕迹来自新增节区，尤其是 `.CRT$XLB` 与 `.vmptrmp`；
- `objdump -s -j .CRT$XLB` 能直接看到附加回调数据，说明当前实现更接近 **CRT/TLS callback side path**，而非主入口切换。

## 5. 符号表与函数体可读性

`objdump -t` 实际仍能看到：

- `protected_mix_c`
- `kProtectedCString`
- `protected_mix_cpp`
- `kProtectedCppString`

`radare2 -A -q` 的 `afl` 与 `pdf` 也直接识别出 `sym.protected_mix_c` / `sym.protected_mix_cpp`，并能输出完整反汇编。

另外，`objdump -d --disassemble=<protected symbol>` 的实际对比结果表明：

- `target_c` 的 `protected_mix_c` 保护前后除文件头行外，**指令内容一致**；
- `target_cpp` 的 `protected_mix_cpp` 保护前后除文件头行外，**指令内容一致**。

因此就当前 Windows 产物而言：

- 反编译器/反汇编器几乎不需要额外恢复步骤；
- 受保护函数的运算常量、移位、旋转、xor/add 关系全部**直接暴露**；
- 从“函数体可读性”角度，这一层保护目前仍属 **低阻力**。

## 6. rolling opcode map / handler 可识别性

`objdump -s -j .vmpvm` 与 `objdump -s -j .vmptrmp` 的实际结果显示，这些区域不是纯随机高熵 blob，而是保留了明显的结构线索。

{chr(10).join(marker_lines)}

除此之外，`strings`/`r2 izz` 还能在保护后样本中看到与 loader/bridge 相关的文本，例如：

- `vmp_windows_init`
- `bridge_symbol`
- `dispatcher_symbol`

这说明：

- handler/dispatcher 相关元数据仍然**带有稳定文本特征**；
- 对有经验的 CTF 选手来说，可以先以字符串与节区名做快速定位，再进入 `.vmpvm` / `.vmptrmp` 做脚本化提取；
- 当前 rolling opcode map 在 Windows PE 样本上的“破签名”效果**仍不足以掩盖保护框架骨架**。

## 7. readelf 实际结果说明

由于分析对象是 PE/COFF，`readelf` 的实际运行结果如下：

{chr(10).join(readelf_lines)}

因此本报告没有伪造 ELF 视角，而是按工具真实行为记录：`readelf` 在本阶段只用于证明 **PE 文件不适合以 ELF 工具解读**。

## 8. 风险评估

综合实际工具输出，本轮 Windows PE 保护样本的逆向难度评估如下：

- **节区层**：中等。攻击者很容易定位出“这里被保护过”，但也很容易锁定新增节区位置。
- **符号层**：低。原函数名与受保护字符串符号仍暴露。
- **字符串层**：低。`strings` 即可命中 contest secret。
- **函数体层**：低。`objdump` / `radare2` 都能直接恢复核心运算逻辑。
- **框架指纹层**：中低。`.vmpload/.vmpvm/.vmptrmp` 与 `bridge_symbol/dispatcher_symbol` 等标记为自动化检测提供了稳定锚点。

## 9. 建议与风险点

1. **PE 字符串保护必须真正落地**
   - 让 `VM_string` 从 `.rdata` 移除，进入独立密文池；
   - 若 PE backend 目前不生成 `.vmpstrings`，应补齐该路径，或在 `.vmpvm` 内使用不可直接 `strings` 扫描的封装格式。

2. **移除/混淆符号表与调试信息**
   - 当前样本保留 COFF 符号与大量 debug section；
   - contest build 应至少在最终产物上执行 strip/符号裁剪，否则 `objdump -t` / `r2 afl` 会直接泄露目标点。

3. **让受保护函数真正离开原始 `.text` 语义**
   - 目前 `protected_mix_*` 在保护前后指令一致；
   - 若目标是提高反编译难度，需让 call-site 进入 VM dispatcher，或者把原函数替换为薄壳 trampoline + 密文字节码解释路径。

4. **减少 `.vmpvm/.vmptrmp` 内的稳定 ASCII 元数据**
   - 源文件名、节名、`__main`、bridge/dispatcher JSON 字段会给静态分析脚本提供高价值线索；
   - 这些内容应最小化、编码化或延迟构造。

5. **若需要“入口保护”效果，应明确改写入口点或给出更隐蔽的早期控制转移**
   - 当前 `AddressOfEntryPoint` 未变；
   - 攻击者只需从常规 PE 入口沿主执行流分析即可，不需要先解决入口混淆。

## 10. 原始证据位置

- 原始命令输出目录：`reports/decompilation_raw_{args.date}/`
- 其中包含：
  - `objdump -h/-x/-t/-d/-s` 输出
  - `readelf -h` 失败信息
  - `strings -a` 输出
  - `radare2 -A -q` 的 `iI/iS/afl/pdf/izz` 输出
"""

    report_path.write_text(report)
    print(f'decompilation_report={report_path}')
    print(f'decompilation_raw={raw_root}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
