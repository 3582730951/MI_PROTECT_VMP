# arch/arm

- 支持 ABI：AAPCS (`r0..r3`)
- 发射域：VM1
- 支持子集：ARM-state `mov/add/sub/and/orr/eor/cmp/b/bl/bx/ldr/str`
- 条件执行：本轮只稳定支持条件分支；thumb 遇到即给出 `unsupported_thumb_mode` 诊断
