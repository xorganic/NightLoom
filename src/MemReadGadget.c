#include "MemReadGadget.h"

BOOL ScanReadGadgets(IN HMODULE hModule, IN OPTIONAL DWORD dwBufferSizeToScan)
{
#define GADGET_Q        0xC3008B48      // 48 8B 00 C3  |  mov rax, [rax]; ret
#define GADGET_D        0xC3008B        // 8B 00 C3     |  mov eax, [rax]; ret
#define GADGET_W        0xC300B70F      // 0F B7 00 C3  |  movzx eax, word [rax]; ret

#define GADGET_Q_ALT    0xC3018B48      // 48 8B 01 C3  |  mov rax, [rcx]; ret
#define GADGET_D_ALT    0xC3018B        // 8B 01 C3     |  mov eax, [rcx]; ret
#define GADGET_W_ALT    0xC301B70F      // 0F B7 01 C3  |  movzx eax, word [rcx]; ret

    if (!hModule) return FALSE;

    ULONG_PTR   uTextBase   = (ULONG_PTR)hModule + BUFFER_SIZE_4096;
    ULONG_PTR   uFoundQ     = 0;
    ULONG_PTR   uFoundD     = 0;
    ULONG_PTR   uFoundW     = 0;
    DWORD       dwScanSize  = dwBufferSizeToScan ? dwBufferSizeToScan : (BUFFER_SIZE_4096 * BUFFER_SIZE_512);

    for (DWORD i = 0; i < dwScanSize; i++)
    {
        if (!IsBadReadPtr((PVOID)(uTextBase + i), sizeof(DWORD)))
        {
            DWORD dwStub = *(DWORD*)(uTextBase + i);

            if (!uFoundQ && (dwStub == GADGET_Q || dwStub == GADGET_Q_ALT))
                uFoundQ = uTextBase + i;

            else if (!uFoundD && ((dwStub & 0x00FFFFFF) == GADGET_D || (dwStub & 0x00FFFFFF) == GADGET_D_ALT))
                uFoundD = uTextBase + i;

            else if (!uFoundW && (dwStub == GADGET_W || dwStub == GADGET_W_ALT))
                uFoundW = uTextBase + i;

            if (uFoundQ && uFoundD && uFoundW)
                break;
        }
    }

#undef GADGET_Q
#undef GADGET_D
#undef GADGET_W
#undef GADGET_Q_ALT
#undef GADGET_D_ALT
#undef GADGET_W_ALT

    if (!uFoundQ) return FALSE;

    GadgetInit(uFoundQ, uFoundD, uFoundW);
    return TRUE;
}
