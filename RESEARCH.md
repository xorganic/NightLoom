# GhostCtx — Ldr Activation Context Callback Injection

**A Process Injection Technique via ntdll's Writable Function Pointer Dispatch**

---

## Abstract

We present a Windows process injection technique that exploits an undocumented writable function pointer in ntdll's `.data` section. During process initialization, the Windows loader (Ldr) stores kernel32's internal `CreateActCtxWWorker` address at a fixed offset within ntdll's writable data segment. On every `LoadLibrary` call, the Ldr dispatches through this pointer via a **fothk trampoline** — a `JMP RAX` gadget that bypasses Control Flow Guard (CFG) validation entirely. By overwriting this single QWORD from a remote process, an attacker redirects execution on the next natural DLL load without creating threads, queuing APCs, or manipulating any callback structures.

It requires only four core syscall primitives: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtProtectVirtualMemory` (for the RW→RX transition — no RWX pages are used). It triggers naturally through the target's own DLL loading activity, leaves no persistent hooks, and auto-restores the original pointer after a single execution.

**Keywords:** process injection, activation context, ntdll, loader, CFG bypass, fothk, indirect syscalls

---

## 1. Introduction

Process injection is a fundamental offensive capability on Windows, enabling code execution within the address space of another process. Established techniques include DLL injection via `CreateRemoteThread`, APC injection, thread hijacking, and various callback-based methods targeting structures such as the Vectored Exception Handler (VEH) chain, WNF callbacks, FLS callbacks, `KernelCallbackTable`, and others.

Modern defenses — particularly **Control Flow Guard (CFG)** and **Arbitrary Code Guard (ACG)** have significantly raised the bar. CFG validates indirect call targets against a bitmap of legitimate addresses, while ACG prevents dynamic code generation. Most published injection techniques require either creating new threads (detected by ETW), queuing APCs (monitored by EDR), or targeting callback structures that are now protected by CFG validation.

We identified an overlooked attack surface: the **Loader's activation context dispatch mechanism**. The Windows Loader stores function pointers for activation context operations in ntdll's writable `.data` section. These pointers are called through a dedicated **fothk** (fast-over-the-hook) trampoline section that uses `JMP RAX`, a register-indirect jump that does **not** pass through CFG's `__guard_dispatch_icall_fptr` validation. This creates a reliable, CFG-bypassing code execution primitive triggered by any `LoadLibrary` call in the target process.

### 1.1 Threat Model

GhostCtx assumes the attacker has:
- A handle to the target process with `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE` access
- Shellcode compatible with `LPTHREAD_START_ROUTINE` signature (receives one parameter, returns DWORD)

The technique does **not** require:
- Thread creation rights (`PROCESS_CREATE_THREAD`)
- Debug privileges
- Kernel-mode access
- Modification of any PE headers or protected structures

---

## 2. Technical Background

### 2.1 Activation Context Subsystem

Windows Activation Contexts are an XML-based mechanism for DLL versioning and side-by-side (SxS) assembly resolution. The subsystem is split between kernel32/KERNELBASE (user-facing APIs: `CreateActCtxW`, `ActivateActCtx`, `ReleaseActCtx`) and ntdll (internal loader support).

During process initialization, the Loader resolves kernel32's internal worker functions and stores their addresses in ntdll's `.data` section for subsequent use. Three pointers form a cluster:

| .data Offset | Function | Purpose |
|---|---|---|
| `+0x63F0` | `BasepGetPackageActivationTokenForSxS` | Package activation token resolution |
| `+0x63F8` | `ReleaseActCtx` (internal) | Activation context cleanup |
| **`+0x6410`** | **`CreateActCtxWWorker`** | **Activation context creation (our target)** |

> **Note:** These offsets are from Windows 11 26100 ntdll. The technique resolves them dynamically at runtime via pattern scanning (Section 4.2).

### 2.2 The fothk Trampoline

ntdll contains a dedicated PE section named **fothk** ("fast over the hook"). This section provides trampoline stubs used by the Loader to dispatch calls to kernel32 functions stored in `.data`. The dispatch follows a two-stage chain:

```
.text (Ldr code)                    fothk section
────────────────                    ─────────────
MOV RAX, [rip+disp]  ─── loads ──→ .data+0x6410 (function pointer)
CALL fothk_entry     ──────────┐
                               │
                     ┌─────────┘
                     ▼
                  E9 xx xx xx xx    ; JMP rel32 (stage 1)
                        │
                        ▼
                  48 FF E0          ; JMP RAX (stage 2)
                                      ↑
                                      └── NO CFG VALIDATION
```

The critical observation: **`JMP RAX` is an unconditional register-indirect jump, not a `CALL` through `__guard_dispatch_icall_fptr`**. CFG only validates indirect calls dispatched through its own guard function. The fothk trampoline bypasses this entirely because it was designed before CFG existed and operates on pointers considered "trusted" by the Loader.

### 2.3 Trigger Frequency

The `CreateActCtxWWorker` pointer at `.data+0x6410` is called on **every `LoadLibrary`/`LdrLoadDll` invocation**. In processes like `explorer.exe`, DLL loads occur constantly due to shell extensions, COM activation, and background tasks. This means the injected code fires within seconds without any explicit trigger — the target process triggers it through its own normal operation.

---

## 3. Why This Is Novel

We conducted extensive research to confirm this technique is not previously documented:

| Technique | Status | Key Difference from GhostCtx |
|---|---|---|
| VEH Chain Hijacking | Published (mehrn00/VEH-Hijack) | Modifies ntdll `.mrdata` (read-only at runtime) |
| WNF Callback Injection | Published (modexp) | Targets WNF subscription callbacks, CFG-validated |
| LdrpDllNotificationList | Published (multiple) | Targets DLL notification callbacks |
| FLS Callback Injection | Published (PoolParty) | Targets Fiber Local Storage callbacks |
| KernelCallbackTable | Published (modexp/odzhan) | Targets PEB callback table (kernel-to-user dispatch) |
| BaseThreadInitThunk | Published (ntos322, odzhan) | Overwrites thread init function pointer |
| PEB.ShimData | Published | Targets Application Compatibility shim data |
| Early Cascade | Published | Targets early process initialization |
| **GhostCtx (this work)** | **Novel** | **Targets Ldr activation context dispatch via fothk (no CFG)** |

The key distinction: GhostCtx targets a **loader-internal dispatch path** that uses `JMP RAX` through the fothk section, completely outside CFG's validation scope. No prior work has documented this attack surface.

---

## 4. Implementation

### 4.1 Architecture Overview

GhostCtx operates in five phases:

```
┌──────────────────────────────────────────────────────────┐
│  Phase 0: Initialize Halo's Gate (resolve 7 syscalls)    │
├──────────────────────────────────────────────────────────┤
│  Phase 1: Locate .data slot (3-method dynamic scanner)   │
├──────────────────────────────────────────────────────────┤
│  Phase 2: Open target process (NtOpenProcess)            │
├──────────────────────────────────────────────────────────┤
│  Phase 3: Verify remote slot matches local               │
├──────────────────────────────────────────────────────────┤
│  Phase 4: Build stub + payload → allocate + write        │
├──────────────────────────────────────────────────────────┤
│  Phase 5: Overwrite .data pointer → arm trigger          │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Dynamic Offset Resolution

Hard-coded offsets break across Windows versions. GhostCtx uses a three-method cascade to locate the target pointer at runtime:

**Method 1 — Export Resolution:** Attempt to resolve `CreateActCtxWWorker` from kernel32 by name and scan ntdll `.data` for a matching value. This works when kernel32 exports the worker function.

**Method 2 — Pattern Scan (primary):** Scan ntdll's `.text` section for the instruction pattern:
```asm
MOV RAX, [RIP+disp32]   ; 48 8B 05 xx xx xx xx — loads .data pointer
; ... (within 48 bytes) ...
CALL fothk_entry         ; E8 xx xx xx xx — calls into fothk section
```
For each match, verify that:
1. The RIP-relative displacement resolves to an address within `.data`
2. The value at that `.data` address is a valid kernel32 code pointer
3. The CALL target is within the fothk section
4. The fothk entry follows the `E9 (JMP rel32) → 48 FF E0 (JMP RAX)` chain

This method is version-independent because it identifies the pointer by its **usage pattern**, not its offset.

**Method 3 — Fallback Range Scan:** If pattern scanning fails (e.g., Ldr code was restructured), scan `.data+0x6300..0x6500` for kernel32 code pointers. The activation context pointer cluster has resided in this range across all observed Windows 10/11 builds.

### 4.3 Halo's Gate Indirect Syscalls

All NT API calls use **Halo's Gate** — a technique that resolves System Service Numbers (SSNs) dynamically by walking neighboring syscall stubs in ntdll's export table. If the target stub is hooked (first bytes are not `4C 8B D1; B8 xx xx 00 00`), GhostCtx walks up and down by stride 32 (the standard stub size), examining ±255 neighbors until an unhooked stub is found. The SSN is computed as `neighbor_SSN ± distance`.

Syscall dispatch is performed through an **indirect `JMP`** to the `syscall` instruction found inside a legitimate neighboring stub, avoiding the hooked stub entirely:

```asm
; SyscallDispatch.asm
PrepareGate:
    mov [ssn_store], ecx        ; SSN
    mov [target_store], rdx     ; legitimate syscall;ret address
    ret

DispatchGate:
    mov r10, rcx                ; first arg → r10 (syscall convention)
    mov eax, [ssn_store]        ; SSN → eax
    jmp qword ptr [target_store] ; jump to syscall instruction
```

Seven syscalls are resolved: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtProtectVirtualMemory`, `NtClose`, `NtQueryVirtualMemory`.

### 4.4 Shellcode Stub Design

The injected code consists of a **112-byte (0x70) stub** prepended to the user's payload. The stub must handle a critical constraint: **it fires while the Loader Lock is held**. The callback is invoked during `LdrLoadDll` → activation context processing, and the Ldr's critical section is actively owned by the calling thread.

**Loader Lock Deadlock Problem:**
If the payload calls any function that triggers a DLL load (e.g., `WinExec` → `CreateProcess` → `LoadLibrary`), it will attempt to re-acquire the Loader Lock on the same thread. Since Windows critical sections are recursive, this actually succeeds for the same thread — but `CreateProcess` spawns a new process whose initialization may involve cross-process Ldr operations that deadlock.

The real problem is more subtle: `WinExec("calc",1)` calls `CreateProcess`, which internally performs operations that attempt to acquire the Loader Lock in a way that causes a deadlock when called from within the Ldr's own processing path.

**Solution — CreateThread Dispatch:**
The stub calls `CreateThread` to spawn the payload in a new thread. `CreateThread` itself does not require the Loader Lock (it calls `NtCreateThreadEx` via syscall). The new thread starts independently, and when it eventually needs the Loader Lock (e.g., if the payload calls `LoadLibrary`), the original thread has already returned from the callback and released the lock.

```
Stub Layout (0x70 bytes):
┌─────────┬────────────────────────────────────────────┐
│ 00 - 0A │ Save 7 volatile registers (push)           │
│ 0B - 0E │ sub rsp, 0x30 (shadow space + stack args)  │
│ 0F - 25 │ Restore original .data pointer             │
│ 26 - 54 │ CreateThread(NULL, 0, payload, NULL, 0, 0) │
│ 55 - 63 │ Restore stack and registers (pop)          │
│ 64 - 6F │ JMP to original function (tail call)       │
│ 70+     │ Payload (LPTHREAD_START_ROUTINE)           │
└─────────┴────────────────────────────────────────────┘
```

Patch points (filled at runtime with resolved addresses):
- `+0x11`: ntdll `.data` slot address (for pointer restoration)
- `+0x1B`: Original function pointer value
- `+0x2C`: Payload address (remote allocation base + 0x70)
- `+0x4B`: `CreateThread` address (from kernel32, same base across processes)
- `+0x66`: Original function pointer (for tail-call return)

The stub performs **self-cleanup**: it restores the original `.data` pointer before calling `CreateThread`, ensuring the hook fires exactly once. The tail-call `JMP` to the original function ensures the Ldr's activation context operation completes normally, maintaining process stability.

### 4.5 Stack Alignment

The x64 ABI requires RSP to be 16-byte aligned before any `CALL` instruction. The stub's stack math:

1. **Entry:** RSP = 16n - 8 (return address from the original `CALL` that reached the fothk trampoline)
2. **7 pushes (56 bytes):** RSP = 16n - 8 - 56 = 16n - 64 = 16(n-4) → **aligned**
3. **sub rsp, 0x30 (48 bytes):** RSP = 16(n-4) - 48 = 16(n-7) → **aligned**
4. **Before `CALL rax` (CreateThread):** RSP is 16-byte aligned ✓

---

## 5. Attack Flow

```
 Attacker Process                         Target Process (explorer.exe)
 ────────────────                         ─────────────────────────────
                                          
 1. Resolve SSNs via                      ntdll .data+0x6410:
    Halo's Gate                           ┌──────────────────────┐
                                          │ kernel32+0x24FB0     │ ← CreateActCtxWWorker
 2. Pattern-scan ntdll                    └──────────────────────┘
    to find .data+0x6410                           │
                                                   │ (called on every LoadLibrary
 3. NtOpenProcess(target)                          │  via fothk JMP RAX)
                                                   │
 4. NtReadVirtualMemory                            ▼
    (verify remote slot)              
                                      
 5. Build stub (0x70) + payload       
    Patch: slot, orig, payload,       
           CreateThread, orig_jmp     
                                      
 6. NtAllocateVirtualMemory(RW)       ───→  [stub|payload] allocated
                                      
 7. NtWriteVirtualMemory(stub+pay)    ───→  [stub|payload] written
                                      
 8. NtProtectVirtualMemory(RX)        ───→  RW → RX (no RWX at any point)
                                      
 9. NtWriteVirtualMemory(.data slot)  ───→  .data+0x6410 = &stub
                                             ┌──────────────────────┐
                                             │ → stub address       │
                                             └──────────────────────┘
                                      
 ─── attacker is done ───                    ... time passes ...
                                      
                                      10. Target calls LoadLibrary (natural)
                                          → Ldr reads .data+0x6410
                                          → fothk: JMP RAX → stub
                                      
                                      11. Stub:
                                          a) Restores original pointer
                                          b) CreateThread(DecryptAndRun, pParams)
                                          c) JMP to original function
                                      
                                      12. New thread (PIC blob DecryptAndRun):
                                          VirtualProtect(RW) → ChaCha20 decrypt
                                          → VirtualProtect(RX) → CALL payload
                                          (outside Loader Lock)
                                      
                                      13. Process continues normally
```

---

## 6. Detection and Mitigation

### 6.1 Detection Opportunities

| Layer | Observable |
|---|---|
| **ETW / Syscall monitoring** | `NtWriteVirtualMemory` targeting ntdll `.data` section of a remote process |
| **Memory integrity** | ntdll `.data+0x6410` value changed to a non-kernel32 address |
| **Thread creation** | New thread with start address in a recently-allocated `PAGE_EXECUTE_READ` region |
| **Memory transitions** | `NtProtectVirtualMemory` RW→RX in remote process, or RX→RW→RX sequence in-process (decrypt blob) |

### 6.2 Mitigation Recommendations

1. **CFG coverage for fothk dispatch:** The root cause is that fothk uses `JMP RAX` without CFG validation. Microsoft could retrofit CFG checks on this dispatch path.

2. **Read-only protection for Ldr function pointers:** The `.data+0x6410` slot could be moved to `.mrdata` (read-only at runtime) after initialization, similar to how VEH handler pointers are protected.

3. **Integrity monitoring:** EDR vendors should monitor writes to ntdll's `.data` section, particularly the activation context pointer cluster at known offsets.

4. **Cross-process write heuristics:** Flag `NtWriteVirtualMemory` calls where the target address falls within ntdll's address range in the target process.

---

## 7. Responsible Disclosure

This research is published for defensive and educational purposes. The technique exploits a design limitation in the Windows Loader's dispatch mechanism. We recommend that:

- EDR/AV vendors add detection signatures for writes to the ntdll `.data` activation context pointer region
- Microsoft consider hardening the fothk dispatch path with CFG validation or making the Ldr function pointer storage read-only post-initialization

---

## 8. Implementation: NightLoom

The reference implementation of this technique is **NightLoom** (`NightLoom.exe`). It extends the core GhostCtx primitive with additional engineering for practical use:

**ChaCha20 payload encryption.** The payload is encrypted with a random 256-bit key and 96-bit nonce (generated via `BCryptGenRandom`) before being written to the target. It sits as ciphertext in `PAGE_EXECUTE_READ` memory until triggered. At trigger time, a position-independent (PIC) decrypt blob performs the full cycle: `VirtualProtect(RW)` → ChaCha20 decrypt in-place → `VirtualProtect(RX)` → `CALL payload`.

The PIC blob is compiled into a separate PE section (`.nlpic`) in the injector binary using `#pragma code_seg(".nlpic")`. The reason: the DecryptAndRun function must be extracted as a contiguous block of bytes and copied into the target process. A separate PE section guarantees the compiler does not interleave other functions or data, does not generate references to global variables or jump tables, and the blob size can be computed exactly as the difference between the section's start and end addresses. The function is compiled with `__declspec(safebuffers)` to suppress stack cookie insertion (which would reference `__security_cookie` — a global inaccessible in the target process).

**Key and nonce storage.** The key, nonce, and all addresses needed by the decrypt blob are embedded in a `DECRYPT_PARAMS` struct in the same RX allocation, passed as `lpParameter` to `CreateThread`. The purpose is anti-static-scanning — the payload is never plaintext in the target's memory until the moment of execution. This is **not** key confidentiality: an attacker with read access to the target's memory can extract the key from the params struct at a known offset from the allocation base.

**Memory discipline.** No `PAGE_EXECUTE_READWRITE` pages are created at any point. The injector allocates `PAGE_READWRITE`, writes all data (stub + params + PIC blob + encrypted payload), then flips to `PAGE_EXECUTE_READ` before arming the trigger. The decrypt blob temporarily flips the payload region to `PAGE_READWRITE` for decryption, then back to `PAGE_EXECUTE_READ` before calling it.

**Scanner simplification.** The paper (Section 4.2) documents three scanner methods for completeness. NightLoom uses only Method 2 (fothk pattern scan) — it proved reliable across all tested Windows builds, making the export-resolution fallback (Method 1) and range-scan fallback (Method 3) unnecessary.

**Relationship to this paper.** GhostCtx (this paper) describes the injection technique — the attack surface, the fothk CFG gap, the Loader dispatch path. NightLoom is the engineered implementation with production-grade features (ChaCha20 encryption, PIC decrypt blob, dynamic fothk pattern scanner, Halo's Gate indirect syscalls). The technique is the same; the implementation adds operational hardening.

## 9. Conclusion

GhostCtx demonstrates that Windows ntdll's internal data structures remain a rich attack surface. The Loader's activation context dispatch mechanism — designed for performance via the fothk trampoline — creates a CFG-bypassing code execution primitive accessible through standard virtual memory operations. The technique requires no thread creation rights, no APC queuing, and triggers naturally through the target's own DLL loading activity.

The combination of:
- **Writable function pointer** in ntdll `.data` (not protected by `.mrdata`)
- **fothk JMP RAX dispatch** (no CFG validation)
- **High-frequency natural trigger** (every LoadLibrary call)
- **Minimal primitive requirements** (4 syscalls: open + alloc + write + protect)

...makes this a practical and stealthy injection vector. We hope this disclosure helps the defensive community develop appropriate detections and encourages Microsoft to harden this dispatch path.

---

## Appendix A: Files

| File | Description |
|---|---|
| `src/Main.c` | NightLoom injector — scanner, stub builder, ChaCha20 encryption, injection |
| `src/ChaCha20.h/c` | ChaCha20 stream cipher (injector-side encryption) |
| `src/Common.h` | CRC32B hash constants for API/module resolution |
| `src/HalosGate.h/c` | Halo's Gate SSN resolver with neighbor walking |
| `src/PebResolver.h/c` | PEB-based module + API resolution with API set v2-v6 |
| `src/MemReadGadget.h/c` | `mov rax,[rax];ret` gadget scanner for safe remote reads |
| `src/SyscallDispatch.asm` | Indirect syscall dispatcher (PrepareGate/DispatchGate) |
| `src/GadgetDispatch.asm` | Memory read gadget dispatch |
| `src/Crc32Hash.c` | CRC32B hash computation |
| `src/NtDefs.h` | NT structure definitions |
| `src/Trace.h/c` | Debug logging |

> **Note:** The original development PoCs (`ghostctx_poc.c`, `poc_actctx2.c`, `verify_actctx.c`, `check_dispatch.c`) were used during research to validate each step of the technique individually. Their functionality has been fully absorbed into `src/Main.c` (NightLoom). The PoCs are not included in the published repo — `src/Main.c` is the complete reference implementation.

## Appendix B: Tested Environment

- **OS:** Windows 11 Pro 26100.2605
- **ntdll:** 10.0.26100.2605 (SHA256: version-specific)
- **Target:** explorer.exe (high DLL-load frequency)
- **Payload:** WinExec("calc",1) shellcode (123 bytes)
- **Result:** Calculator spawned in explorer's context; explorer remained stable

## Appendix C: Comparison with PoolParty Variants

SafeBreach's PoolParty research (2023) documented injection via Windows Thread Pool work items. While both PoolParty and GhostCtx avoid `CreateRemoteThread`, they target fundamentally different subsystems:

| | PoolParty | GhostCtx |
|---|---|---|
| **Target** | Thread Pool worker factories | Loader activation context dispatch |
| **Callback type** | Work item / timer / I/O completion | Function pointer in .data |
| **CFG** | Varies by variant | Bypassed (fothk JMP RAX) |
| **Trigger** | Pool thread scheduling | Any LoadLibrary call |
| **Primitives** | NtSetInformationWorkerFactory + others | NtAllocateVirtualMemory + NtWriteVirtualMemory |
| **Thread creation** | Indirect (pool) | CreateThread in stub (runs outside Ldr lock) |

---

*GhostCtx / NightLoom — Xorganic, 2026*  
