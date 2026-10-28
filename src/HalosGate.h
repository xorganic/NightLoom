#ifndef HALOS_GATE_H
#define HALOS_GATE_H

#include "Common.h"
#include "PebResolver.h"
#include "MemReadGadget.h"

typedef struct _SYSCALL_ENTRY
{
    DWORD   dwSSn;
    PVOID   pSyscallAddress;
    PVOID   pSyscallInstAddress;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Located in SyscallDispatch.asm
extern VOID PrepareGate(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern NTSTATUS DispatchGate();

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define GATE_PREPARE(Entry)     (PrepareGate((DWORD)(Entry).dwSSn, (PVOID)(Entry).pSyscallInstAddress))
#define GATE_CALL(...)          (DispatchGate(__VA_ARGS__))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    BOOL ResolveSyscallByHash(IN DWORD dwSyscallNameHash, OUT PSYSCALL_ENTRY pEntry);

#ifdef __cplusplus
}
#endif


#endif // !HALOS_GATE_H
