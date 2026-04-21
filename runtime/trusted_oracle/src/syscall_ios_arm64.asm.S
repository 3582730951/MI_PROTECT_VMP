.text
.globl _vmp_trusted_oracle_ios_arm64_syscall6
.p2align 2
_vmp_trusted_oracle_ios_arm64_syscall6:
    mov x16, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    svc #0x80
    ret
.section .note.GNU-stack,"",@progbits
