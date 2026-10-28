#ifndef MEM_READ_GADGET_H
#define MEM_READ_GADGET_H

#include "Common.h"

// Located in GadgetDispatch.asm
extern VOID GadgetInit(IN ULONG_PTR uQwordGadget, IN ULONG_PTR uDwordGadget, IN ULONG_PTR uWordGadget);
extern ULONG_PTR GadgetReadQ(IN ULONG_PTR uPointer);
extern ULONG_PTR GadgetReadD(IN ULONG_PTR uPointer);
extern ULONG_PTR GadgetReadW(IN ULONG_PTR uPointer);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define MEM_RQ(base, type, field)       (ULONG_PTR)GadgetReadQ((ULONG_PTR)(base) + FIELD_OFFSET(type, field))
#define MEM_RD(base, type, field)       (DWORD)GadgetReadD((ULONG_PTR)(base) + FIELD_OFFSET(type, field))
#define MEM_RW(base, type, field)       (WORD)GadgetReadW((ULONG_PTR)(base) + FIELD_OFFSET(type, field))

#define MEM_RQ_RAW(addr)               (ULONG_PTR)GadgetReadQ((ULONG_PTR)(addr))
#define MEM_RD_RAW(addr)               (DWORD)GadgetReadD((ULONG_PTR)(addr))
#define MEM_RW_RAW(addr)               (WORD)GadgetReadW((ULONG_PTR)(addr))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#ifdef __cplusplus
extern "C" {
#endif

    BOOL ScanReadGadgets(IN HMODULE hModule, IN OPTIONAL DWORD dwBufferSizeToScan);

#ifdef __cplusplus
}
#endif

#endif // !MEM_READ_GADGET_H
