
<p align="center">
<pre>
                    ╔═══════════════════════════════════════╗
                    ║                                       ║
                    ║    ░░░░░░░░░░░░░░░░░                  ║
                    ║    ░  ┌─┬─┬─┬─┐  ░                    ║
                    ║    ░  │╶┼╶┼╶┼╶│  ░  N I G H T L O O M ║
                    ║    ░  │╶┼╶┼╶┼╶│  ░                    ║
                    ║    ░  │╶┼╶┼╶┼╶│  ░  the loom weaves   ║
                    ║    ░  └─┴─┴─┴─┘  ░  in darkness.      ║
                    ║    ░░░░░░│░░░░░░░░                    ║
                    ║          ▼                            ║
                    ║                                       ║
                    ╚═══════════════════════════════════════╝
</pre>
</p>

<p align="center">
  <b>Threadless, APC-less process injection through the Windows Loader itself</b><br>
  <sub>Hijack one pointer in ntdll. The Loader does the rest  .<br>
  CFG doesn't see it. ETW doesn't log it. Payload sits ChaCha20-encrypted until trigger.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D4?style=flat-square" />
  <img src="https://img.shields.io/badge/arch-x86__64-red?style=flat-square" />
  <img src="https://img.shields.io/badge/lang-C%20%2B%20MASM-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/category-research-blueviolet?style=flat-square" />
</p>

---

## What is this?

The Windows Loader stores a function pointer to `kernel32!CreateActCtxWWorker` in ntdll's writable `.data` section. Every `LoadLibrary` call dispatches through it via a **fothk trampoline** - `JMP RAX` with **zero CFG validation**.

**NightLoom** overwrites that pointer. One write. The Loader itself executes your payload on its next DLL load. No `CreateRemoteThread`. No `QueueUserAPC`. No `NtCreateThreadEx`. The target process does the work for you.

## How it works

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │                         TARGET PROCESS                               │
    │                                                                      │
    │  ntdll .data                                                         │
    │  ┌────────────────────┐     ┌──────────┐     ┌───────────── ─────┐   │
    │  │ CreateActCtxWWorker├────►│  fothk   │     │   Your payload    │   │
    │  │    slot (8 bytes)  │     │          │     │                   │   │
    │  └────────┬───────────┘     │ E9 xxxxx │     │  ┌─────────────┐  │   │
    │           │                 │ JMP rel32│     │  │ stub:       │  │   │
    │           │     OVERWRITE   │    │     │     │  │  save regs  │  │   │
    │           │◄────────────    │    ▼     │     │  │  restore ptr│  │   │
    │           │                 │ 48 FF E0 │     │  │  CreateThrd │  │   │
    │           ▼                 │ JMP RAX ─┼─X──►│  │  jmp orig   │  │   │
    │                             │ (NO CFG) │     │  └──────┬──────┘  │   │
    │  LoadLibrary ──────────►                     │  ┌────────────┐   │   │
    │                                              │  │ PIC blob:  │   │   │
    │                                              │  │ ChaCha20   │   │   │
    │                                              │  │  decrypt   │   │   │
    │                                              │  │ RW→RX flip │   │   │
    │                                              │  │ payload()  │   │   │
    │                                              │  └────────────┘   │   │
    │  Loader calls on every      └──────────┘     │         ▼         │   │
    │                                              └───────────────────┘   │
    └──────────────────────────────────────────────────────────────────────┘

    INJECTOR (this tool)                   ATTACK FLOW
    ───────────────────                    ──────────────
    1. Scan local ntdll .text              Pattern: MOV RAX,[rip+disp] → CALL fothk
       to find the .data slot              Verify:  fothk entry = JMP rel32 → JMP RAX
                                           Result:  exact offset, works on any build

    2. Open target process                 NtOpenProcess (indirect syscall)

    3. Allocate RW memory                  NtAllocateVirtualMemory (indirect syscall)

    4. Write stub + encrypted payload       NtWriteVirtualMemory (indirect syscall)
                                           Payload encrypted with ChaCha20 (256-bit key)
                                           Stub restores pointer, spawns decrypt thread

    5. Flip to RX                          NtProtectVirtualMemory (indirect syscall)
                                           No RWX pages - only RW → RX transition

    6. Overwrite the .data pointer         NtWriteVirtualMemory (indirect syscall)
                                           8 bytes. One write. Armed.

    7. Wait.                               Next LoadLibrary triggers the stub.
                                           New thread decrypts payload (RX→RW→RX),
                                           then executes. Loader Lock safe.
```

## What you're not doing

| Property | Detail |
|:---------|:-------|
| **No remote thread** | No `CreateRemoteThread`, `NtCreateThreadEx`, or `RtlCreateUserThread` |
| **No APC** | No `QueueUserAPC` or `NtQueueApcThread` |
| **No exception abuse** | No VEH/SEH/Vectored handlers |
| **No DLL loading** | No `LoadLibrary` in the injector's context |
| **CFG bypass built-in** | fothk dispatch is `JMP RAX` - no CFG bitmap check |
| **Natural trigger** | Any DLL load in the target fires the payload |
| **Self-cleaning** | Stub restores original pointer before executing - one-shot |
| **Encrypted payload** | ChaCha20 (256-bit key, 96-bit nonce) - plaintext never in target memory until trigger |
| **Loader Lock safe** | Payload runs in a separate thread, not under the lock |
| **Dynamic scanning** | Pattern scan finds the slot on any Windows build |

## Design decisions

```
 Syscalls     Halo's Gate - SSN resolved at runtime, dispatched through
              a legitimate ntdll syscall;ret instruction (indirect syscall).
              Avoids static SSN tables that break across Windows builds.

 API resolve  CRC32B hash-based - no plaintext API strings in the binary.
              Compile-time constants, no runtime string construction.

 Encryption   ChaCha20 (256-bit key, 96-bit nonce) - payload encrypted
              before write and stays encrypted in target memory until
              trigger. PIC blob decrypts just-in-time, then re-seals as RX.

 Memory       RW → RX only - no PAGE_EXECUTE_READWRITE at any point.
              Payload is written as ciphertext into RW, flipped to RX.
              Decrypt thread briefly flips to RW, then back to RX.

 Dispatch     CreateThread from inside target - not CreateRemoteThread.
              Needed to escape Loader Lock; the Loader holds the lock
              when the callback fires, so direct payload execution would
              deadlock on any API that loads a DLL.

 Scanner      fothk pattern scan - no hardcoded offsets. Scans ntdll .text
              for MOV RAX,[rip+disp] → CALL fothk sequences and verifies
              the fothk entry resolves to JMP RAX. Survives Windows updates.
```

## Build

Requirements: **Visual Studio 2022** (or Build Tools) with **MSVC v143** and **MASM**.

```
MSBuild NightLoom.vcxproj /p:Configuration=Release /p:Platform=x64
```

Or open `NightLoom.sln` in Visual Studio 2022 and build.

Output: `x64\Release\NightLoom.exe`

## Usage

```
NightLoom.exe <shellcode.bin> [target]
```

`target` can be a PID (numeric) or process name. Defaults to `explorer.exe`.

```
> NightLoom.exe payload.bin explorer.exe

  +------------------------------------------------------------+
  |  NightLoom                                                 |
  |  Ldr Activation Context Callback Injection                 |
  |  .data fptr -> fothk JMP RAX (no CFG) | ChaCha20 payload   |
  +------------------------------------------------------------+

[+] Shellcode: payload.bin (276 bytes)
[+] Target PID: 1234

[*] Phase 0: Initializing Halo's Gate...
[+] Halo's Gate: 7 syscalls resolved (indirect dispatch)

[*] Phase 1: Locating activation context callback slot...
[+] .data+0x63E8 -> kernel32+0x24F10 (fothk at ntdll+0x5A3C2)
[+] Confirmed: fothk -> JMP RAX (no CFG)

[*] Phase 4: Injecting (ChaCha20 encrypted)...
[+] ChaCha20 key/nonce generated (32 + 12 bytes)
[+] Payload encrypted with ChaCha20
[+] Allocated RW: 0x1A000000000 (4096 bytes)
[+] Protection: RW -> RX

[*] Phase 5: Arming trigger...
[+] Pointer overwritten -- trigger armed

[+] Injection complete!
[*] Trigger: next LoadLibrary call in PID 1234
[*] Payload is ChaCha20 encrypted in target memory
[*] Stub auto-restores original pointer -- process stays stable
```

## Project structure

```
NightLoom/
├── src/
│   ├── Main.c               # Injector - scanner, stub builder, ChaCha20 injection
│   ├── ChaCha20.h/c         # ChaCha20 stream cipher (injector-side encryption)
│   ├── Common.h              # CRC32B hash constants
│   ├── NtDefs.h              # NT structure definitions
│   ├── HalosGate.h/c         # Halo's Gate SSN resolver
│   ├── PebResolver.h/c       # PEB walk + hash-based API resolution
│   ├── MemReadGadget.h/c     # mov rax,[rax];ret gadget scanner
│   ├── SyscallDispatch.asm   # Indirect syscall trampoline (MASM)
│   ├── GadgetDispatch.asm    # Memory read gadget dispatch
│   ├── Crc32Hash.c           # CRC32B hash functions
│   └── Trace.h/c             # Debug logging
├── NightLoom.sln             # Visual Studio solution
├── NightLoom.vcxproj         # Project file (MSVC v143 + MASM)
├── RESEARCH.md               # Full technical writeup (English)
├── RESEARCH_RO.md            # Lucrare tehnică completă (Română)
└── README.md
```

> **Paper:** The full technical writeup covering the injection technique, fothk CFG gap analysis, Loader dispatch internals, and detection guidance is available in [RESEARCH.md](RESEARCH.md) (English) and [RESEARCH_RO.md](RESEARCH_RO.md) (Romanian). The paper describes the GhostCtx technique; NightLoom is the engineered implementation.

## The fothk section

The `fothk` (Fast Object Type Help) section in `ntdll.dll` contains trampolines used by the Loader for indirect dispatch. Each entry is:

```asm
fothk+0x00:  E9 xx xx xx xx       ; JMP rel32 → shared handler
             ...
shared:      48 FF E0              ; JMP RAX - NO CFG VALIDATION
```

This means any function pointer loaded into `RAX` and dispatched through `fothk` **skips CFG entirely**. The Loader uses this path for activation context callbacks - and NightLoom exploits exactly that.

## Prior art

The general idea of overwriting a function pointer in ntdll `.data` is not new. The closest prior work:

- **BaseThreadInitThunk hijacking** ([odzhan](https://github.com/odzhan/injection)) - overwrites `BaseThreadInitThunk` in ntdll `.data`. That pointer is called on thread creation and dispatched through a standard indirect call that **is validated by CFG**. The activation context slot targeted here is called on every `LoadLibrary` and dispatched through `fothk` - a `JMP RAX` with **no CFG bitmap check**. Different pointer, different dispatch path, different CFG story.

- **PoolParty** ([SafeBreach](https://github.com/SafeBreach-Labs/PoolParty)) - abuses worker factory callbacks in the thread pool. Targets `TP_WORK`/`TP_TIMER`/`TP_WAIT` structures. Different callback surface, requires specific thread pool state.

- **KernelCallbackTable** ([modexp](https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/)) - overwrites function pointers in the PEB's `KernelCallbackTable`. Well-documented and widely detected. Targets user-mode GUI callbacks, not Loader dispatch.

- **WNF/FLS callbacks** - various techniques abuse Windows Notification Facility or Fiber Local Storage callbacks. Different structures, different trigger conditions.

What's specific to this technique:
- **The target pointer** - `CreateActCtxWWorker` in ntdll `.data`, invoked on every `LoadLibrary` in the process
- **The CFG gap** - the fothk trampoline dispatches via `JMP RAX` without checking the CFG bitmap, unlike standard indirect calls
- **Trigger reliability** - DLL loads happen constantly in active processes; no need to force or wait for specific conditions

## FAQ

**"Isn't this just RWX allocation?"**

No. Memory transitions `PAGE_READWRITE` → `PAGE_EXECUTE_READ`. There is never a `PAGE_EXECUTE_READWRITE` page. The payload sits **ChaCha20-encrypted** in RX memory. At trigger time, the PIC decrypt blob flips it to RW, decrypts in-place, flips back to RX, then executes. Memory scanners looking for RWX will not flag this.

**"CreateThread is still called - ETW sees it."**

The thread is created from inside the target by the callback stub, not by the injector via `CreateRemoteThread` or `NtCreateThreadEx`. The start address is a PIC blob in a clean RX allocation - not a classic injected-thread signature, but not invisible either. The goal is to avoid the Loader Lock deadlock, not to hide threads.

**"Halo's Gate is old."**

It is - [published in 2021](https://blog.sektor7.net/#!res/2021/halosgate.md). It's used here as plumbing for the syscalls, not as the contribution. The contribution is the injection surface: the `fothk` CFG gap and the activation context callback as a hijack target.

## Detection

If you're building defenses:

- **Monitor ntdll .data writes** - cross-process writes to ntdll's `.data` section are rare and suspicious
- **Hook `NtWriteVirtualMemory`** - flag writes targeting ntdll address range in remote processes
- **Kernel callback on `.data` modification** - the activation context slot rarely changes after init
- **ETW for `NtProtectVirtualMemory`** - RW→RX transitions in remote processes are a signal
- **Validate fothk dispatch targets** - check that the pointer still resolves to kernel32/KERNELBASE
- **Thread start address validation** - flag threads starting in recently-allocated memory regions

Microsoft could patch this by adding CFG validation to the fothk dispatch path.

## Responsible disclosure

The underlying behavior - fothk dispatching indirect calls without CFG validation - was reported to Microsoft Security Response Center (MSRC) prior to publication. The fothk dispatch path is a design-time property of ntdll's trampoline architecture, not a memory corruption bug, so remediation (adding CFG validation to fothk entries) is at Microsoft's discretion.

This tool is published to help defenders understand the attack surface and build detection. If you discover related issues, report them to [MSRC](https://msrc.microsoft.com/create-report) before publishing.

## Disclaimer

This tool is published for **security research and educational purposes only**. It is intended to advance understanding of Windows Loader internals and help security teams develop detection for callback-hijacking techniques. Use it only in authorized testing environments with explicit permission. The author assumes no responsibility for unauthorized or malicious use.

## References

| Topic | Source |
|:------|:-------|
| Halo's Gate | [sektor7 - SSN resolution via neighboring stubs](https://blog.sektor7.net/#!res/2021/halosgate.md) |
| Hell's Gate | [am0nsec/HellsGate - direct syscall invocation](https://github.com/am0nsec/HellsGate) |
| PoolParty | [SafeBreach - worker factory callback injection](https://github.com/SafeBreach-Labs/PoolParty) |
| KernelCallbackTable | [modexp - PEB callback pointer hijacking](https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/) |
| BaseThreadInitThunk | [odzhan - .data pointer hijacking variants](https://github.com/odzhan/injection) |
| CFG internals | [Microsoft - Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) |
| CFG bypass survey | Bania - "Bypassing Control Flow Guard in Windows 10" (CanSecWest, 2019) |
| Windows Internals | Russinovich, Solomon, Ionescu - *Windows Internals 7th ed.*, Part 1, Ch. 3 (Loader) & Ch. 7 (Security) |
| Loader internals | [Geoff Chappell - ntdll LDR functions](https://www.geoffchappell.com/studies/windows/win32/ntdll/) |
| Activation contexts | [Microsoft - SxS / Activation Context API](https://learn.microsoft.com/en-us/windows/win32/sbscs/activation-contexts) |
| ChaCha20 | [RFC 8439 - ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) |
| PE/COFF | [Microsoft - PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) |

---

<p align="center">
  <sub>The loom weaves in darkness.</sub>
</p>
