# arch/x86

- 支持 ABI：`cdecl_x86`、`stdcall_x86`
- 发射域：VM1
- 支持子集：`mov/add/sub/imul/and/or/xor/shl/shr/sar/cmp+jcc/jmp/call/ret/push/pop`
- 访存：`[esp+disp]`、`[ebp+disp]`、一般寄存器基址；SIB 仅覆盖测试未用路径，复杂 SIB 直接诊断失败。
- 失败策略：返回空 `Vm1Module` + diagnostics，rewriter 回退 passthrough。
