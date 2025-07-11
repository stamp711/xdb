.intel_syntax noprefix

.global main

.section .rodata
# binary can exactly represent floating-point values whose denominators are
# powers of two (such as 0.5, 0.25, 0.125, and so on)
my_double: .double 42.25

.section .text

main:
    push rbp
    mov rbp, rsp

    # Store to r13
    mov r13, 0xdeadbeefcafebabe
    int3

    # Store to r13d
    mov r13d, 0xabcdef01
    int3

    # Store to r13w
    mov r13w, 0x1234
    int3

    # Store to r13b
    mov r13b, 42
    int3

    # Store to ah
    mov ah, 41
    int3

    # Store to mm0
    mov r13, 0xba5eba11
    movq mm0, r13
    int3

    # Store to xmm0
    movsd xmm0, [rip + my_double]
    int3

    # Store to st0
    emms
    fld qword ptr [rip + my_double]
    int3

    mov rsp, rbp
    pop rbp
    xor rax, rax
    ret
