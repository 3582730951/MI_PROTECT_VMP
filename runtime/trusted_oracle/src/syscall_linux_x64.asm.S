.text
.globl vmp_trusted_oracle_linux_x64_syscall6
.type vmp_trusted_oracle_linux_x64_syscall6,@function
vmp_trusted_oracle_linux_x64_syscall6:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r10
    mov %r9, %r8
    mov 8(%rsp), %r9
    syscall
    ret
.section .note.GNU-stack,"",@progbits
