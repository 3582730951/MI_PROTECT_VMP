# arch

- 对应 plan：§10、§10.3、§10.4
- 当前状态：MVP lifting backends ready（x86 / x64 / ARM / ARM64）

## 目录
- `arch/common/`：`FunctionView` / `RelocationEntry` / `Diagnostic` / `IsaLifter` 统一接口。
- `arch/x86/`：x86-32 最小长度感知解码与 VM1 lifting。
- `arch/x64/`：x86_64 REX-aware 解码；默认发射 VM1，可按构造参数发射 VM2。
- `arch/arm/`：ARMv7 ARM-state 固定宽度解码；thumb 本轮诊断回退。
- `arch/arm64/`：AArch64 固定宽度解码与 VM1 lifting。

## 统一规则
- 不支持的指令：追加 `unsupported_opcode` 诊断并返回空模块，由上层回退到 passthrough thunk。
- 重定位：若立即数区间与 relocation 重叠，则运行时值使用 `resolved_value`，并把 `reloc:<tag>:<value>` 携带进模块常量池。
- ABI 入口映射：
  - x86: cdecl/stdcall 走栈参数
  - x64: SystemV / MS x64
  - ARM: AAPCS `r0..r3`
  - ARM64: AAPCS64 `x0..x7`
- rewriter `--lift`：当前 ELF 路径会把可成功 lifting 的函数模块序列化进 `.vmpcode`，并在可 patch 时生成 thunk。
