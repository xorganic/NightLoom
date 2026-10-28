.data
    g_dwSyscallNumber       DWORD   0h
    g_pSyscallJmpTarget     QWORD   0h


.code

PrepareGate PROC
    mov g_dwSyscallNumber, ecx
    mov g_pSyscallJmpTarget, rdx
    ret
PrepareGate ENDP


DispatchGate PROC
    mov r10, rcx
    mov eax, g_dwSyscallNumber
    jmp qword ptr [g_pSyscallJmpTarget]
    ret
DispatchGate ENDP


end
