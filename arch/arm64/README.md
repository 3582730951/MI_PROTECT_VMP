# arch/arm64

- 支持 ABI：AAPCS64 (`x0..x7`)
- 发射域：VM1
- 支持子集：`add/sub/mul/sdiv/udiv/lsl/lsr/asr/and/orr/eor/b/bl/ret/b.cond/ldr/str`
- 条件分支依赖上一条可比较的 `sub`/等价差值更新场景；更复杂 NZCV 组合本轮诊断回退
