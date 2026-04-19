# arch/common

统一 lifting / decoder 共享层。

## PC-relative 与 Label 基础抽象

- `pc_relative.h` 在 subtask 20 引入 `PcRelativeTarget` 与 `Label`：
  - `source_pc`：该 ISA 计算位移时使用的基准 PC。
    - x86/x64 branch/call/RIP-relative：下一条指令地址
    - ARM32 branch/literal：`PC+8`
    - Thumb branch/literal：`PC+4`（literal 再按 ISA 对齐）
    - ARM64 branch/ADR/ADRP/literal：当前指令地址
  - `displacement`：统一按字节保存；`ADRP` 的 page-relative 形式保存为 `4096` 的倍数。
  - `computed_absolute`：按 ISA 语义计算出的绝对目标。
  - `kind`：`branch / call / load / store / address_materialize / indirect_jump_via_table`
- `Label` 提供标签名与可选 `resolved_vm_pc`；真正的跨 basic-block 解析在 subtask 21 由 `LabelResolver` 落地。
- helper：
  - `encode_rel8/16/32(source_pc, target_pc)`：返回位移并做范围检查。
  - `encode_pc_page(source_pc, target_pc)`：按 4 KiB page 计算 byte displacement，并检查 ADRP 的 21-bit page-range。

## subtask 21: Label + Fixup + Resolver contract

### `Fixup`

`arch/common/include/vmp/arch/common/label_resolver.h` 定义统一 fixup 记录：

- `instruction_index`：VM bytecode 指令索引，不是字节偏移。诊断稳定按该索引回报。
- `field`：要补丁的字段类型。
  - `jump_offset_s32`
  - `call_offset_s32`
  - `load_disp_s32`
  - `address_materialize_s64`
- `target_label`：逻辑标签名。
- `allowed_range`：由 ISA 编码位宽推导出来的允许范围。
- `source_vm_pc`：做 range check 时使用的 VM 端基准 PC。
- `code_offset`：最终写回 `Vm1Module::code` 的字节偏移。

### `LabelResolver`

解析器提供两阶段协议：

1. `define(Label, VmPc)`：lifter/assembler 在发射 VM 指令时记录 label 对应 VM PC。
2. `reference(Fixup)`：对所有前向/后向引用记录 fixup。
3. `resolve()`：
   - 收集并排序所有定义与引用；
   - 先生成 diagnostics，再 staged 生成 patch 列表；
   - 只有在 **没有任何 diagnostic** 且已绑定输出字节缓冲区时，才一次性提交全部 patch；
   - 避免出现“部分标签已修补、部分失败”的中间态。
4. `clear()`：清空本轮 resolver 状态。

### Determinism contract

为保证同一输入在 repeated lift 下产生 byte-identical VM output，resolver 强制采用确定性顺序：

- label 定义按 `label.name` 排序聚合；
- fixup 按 `(target_label.name, instruction_index, code_offset, source_vm_pc, field)` 排序；
- diagnostics 按 `(target_label.name, instruction_index, kind, detail)` 排序；
- patch 按 `(code_offset, width, value)` 排序后统一写回。

因此相同输入、相同发射顺序、相同 const-pool 布局下，`resolve()` 结果稳定可复现。

### Diagnostic contract

`resolve()` 返回 `Result`，其中可能包含：

- `duplicate_label`：同名 label 多次定义。
- `unresolved_label`：记录了 fixup，但目标 label 从未定义。
- `out_of_range`：目标存在，但按对应 ISA encoding 的位宽/缩放后超出允许范围。

实现细节：diagnostic 出现时 **不写入任何 patch**。

## ISA encoding range table

下表记录当前 lifter / assembler 通过 `Fixup::allowed_range` 传入的典型范围；resolver 只负责执行这些范围约束，不自行扩张 jump-island：

| ISA / encoding | FixupField | 字节位移范围 |
| --- | --- | --- |
| x86/x64 near `jmp` / `call` / `jcc` rel32 | `jump_offset_s32` / `call_offset_s32` | `[-2147483648, 2147483647]` |
| x64 RIP-relative load/store/LEA disp32 | `load_disp_s32` | `[-2147483648, 2147483647]` |
| ARM32 `b` / `bl` imm24<<2 | `jump_offset_s32` / `call_offset_s32` | `[-33554432, 33554428]` |
| ARM32 literal `ldr [pc,#imm12]` | `load_disp_s32` | `[-4095, 4095]` |
| ARM64 `b` / `bl` imm26<<2 | `jump_offset_s32` / `call_offset_s32` | `[-134217728, 134217724]` |
| ARM64 `b.cond` / `cbz` / `cbnz` imm19<<2 | `jump_offset_s32` | `[-1048576, 1048572]` |
| ARM64 `tbz` / `tbnz` imm14<<2 | `jump_offset_s32` | `[-32768, 32764]` |
| ARM64 literal `ldr` imm19<<2 | `load_disp_s32` | `[-1048576, 1048572]` |
| ARM64 `adr` imm21 | `address_materialize_s64` | `[-1048576, 1048575]` |
| ARM64 `adrp` 21-bit signed page delta | `address_materialize_s64` | `[-4294967296, 4294963200]` |

## 当前集成点

- `runtime/vm1/src/vm1.cpp`
  - DSL assembler 继续保留 `resolve_target()` helper 入口；
  - 内部实现已切换为 `LabelResolver`，因此手写 DSL 与 lifter 路径共享同一标签解析行为。
- lifter 集成：
  - `arch/x86/src/x86.cpp`
  - `arch/x64/src/x64.cpp`
  - `arch/arm/src/arm.cpp`
  - `arch/arm64/src/arm64.cpp`
  - 这些 lifter 最终都通过共享 resolver 路径完成跨 basic-block 的标签定址。
- `vmp-protect --lift`
  - 通过 x64 lifter 的输出路径进入共享 resolver，因此 ELF 重写路径中的 loop / early-exit control flow 不再依赖测试里的一对一 stub label 映射。
