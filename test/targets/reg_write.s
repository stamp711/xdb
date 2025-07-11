.intel_syntax noprefix

.global main

.section .rodata
hex_format: .asciz "%#x"
float_format: .asciz "%.2f"
long_float_format: .asciz "%.2Lf"

.section .text

.macro trap # PID should be stored in r12
    mov rax, 62
    mov rdi, r12 # PID
    mov rsi, 5 # SIGTRAP
    syscall
.endm

.macro printf_fflush
    call printf@plt
    mov rdi, 0 # for all open output streams
    call fflush@plt
.endm

main:
    push rbp
    mov rbp, rsp

    # getpid
    mov rax, 39
    syscall
    mov r12, rax # save pid in r12

    trap

    # Print rsi
    lea rdi, [rip + hex_format] # relative addressing with -pie
    xor rax, rax
    printf_fflush

    trap

    # Print mm0
    movq rsi, mm0
    lea rdi, [rip + hex_format] # relative addressing with -pie
    xor rax, rax
    printf_fflush

    trap

    # Print xmm0
    lea rdi, [rip + float_format]
    mov rax, 1 # we have one argument in XMM registers
    printf_fflush

    trap

    # Print st0
    sub rsp, 16
    fstp tbyte ptr [rsp]
    lea rdi, [rip + long_float_format]
    xor rax, rax
    printf_fflush
    add rsp, 16

    trap

    mov rsp, rbp
    pop rbp
    ret
