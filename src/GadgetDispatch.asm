.data

    g_pGadgetAddrQ      QWORD 0h
    g_pGadgetAddrD      QWORD 0h
    g_pGadgetAddrW      QWORD 0h

.code

;;

GadgetInit PROC

    mov g_pGadgetAddrQ, rcx
    mov g_pGadgetAddrD, rdx
    mov g_pGadgetAddrW, r8
    ret

GadgetInit ENDP

;;

GadgetReadQ PROC
    mov  rdx, g_pGadgetAddrQ
    test rdx, rdx
    jz   FALLBACK_Q

    mov  rax, rcx
    jmp  rdx

FALLBACK_Q:
    mov  rax, [rcx]
    ret
GadgetReadQ ENDP

;;

GadgetReadD PROC
    mov  rdx, g_pGadgetAddrD
    test rdx, rdx
    jz   FALLBACK_D

    mov  rax, rcx
    jmp  rdx

FALLBACK_D:
    jmp  GadgetReadQ
GadgetReadD ENDP

;;

GadgetReadW PROC
    mov  rdx, g_pGadgetAddrW
    test rdx, rdx
    jz   FALLBACK_W

    mov  rax, rcx
    jmp  rdx

FALLBACK_W:
    jmp  GadgetReadD
GadgetReadW ENDP

;;

end
