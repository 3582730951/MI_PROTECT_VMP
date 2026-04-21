.text
.globl vmp_trusted_oracle_linux_arm64_syscall6
.type vmp_trusted_oracle_linux_arm64_syscall6,%function
vmp_trusted_oracle_linux_arm64_syscall6:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    svc #0
    ret
.section .note.GNU-stack,"",@progbits
