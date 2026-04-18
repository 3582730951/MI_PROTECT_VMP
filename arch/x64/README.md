# arch/x64

- 支持 ABI：`sysv_x64`、`msvc_x64`
- 发射域：默认 VM1；构造 `X64Lifter(TargetDomain::vm2)` 时发射 VM2
- 支持子集：`mov/add/sub/imul/and/or/xor/shl/shr/sar/cmp+jcc/jmp/call/ret`
- 访存：寄存器基址、`[rsp+disp]`、有限 RIP-relative 常量场景
- 当前 rewriter 集成：ELF/x86_64 + VM1 thunk patch（样例路径为 2 个整数参数 SysV thunk）
