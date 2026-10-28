
<p align="center">
<pre>
                    ╔═══════════════════════════════════════╗
                    ║                                       ║
                    ║    ░░░░░░░░░░░░░░░░░                  ║
                    ║    ░  ┌─┬─┬─┬─┐  ░                   ║
                    ║    ░  │╶┼╶┼╶┼╶│  ░  N I G H T L O O M║
                    ║    ░  │╶┼╶┼╶┼╶│  ░                   ║
                    ║    ░  │╶┼╶┼╶┼╶│  ░  the loom weaves  ║
                    ║    ░  └─┴─┴─┴─┘  ░  in darkness.     ║
                    ║    ░░░░░░│░░░░░░░░                    ║
                    ║          ▼                            ║
                    ║                                       ║
                    ╚═══════════════════════════════════════╝
</pre>
</p>

<p align="center">
  <b>Threadless, APC-less process injection through the Windows Loader itself</b><br>
  <sub>Hijack one pointer in ntdll. The Loader does the rest.<br>
  CFG doesn't see it. ETW doesn't log it. No thread ever touches your payload.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D4?style=flat-square" />
  <img src="https://img.shields.io/badge/arch-x86__64-red?style=flat-square" />
  <img src="https://img.shields.io/badge/lang-C%20%2B%20MASM-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/category-research-blueviolet?style=flat-square" />
</p>

---

## What is this?

The Windows Loader stores a function pointer to `kernel32!CreateActCtxWWorker` in ntdll's writable `.data` section. Every `LoadLibrary` call dispatches through it via a **fothk trampoline** — `JMP RAX` with **zero CFG validation**.

**NightLoom** overwrites that pointer. One write. The Loader itself executes your payload on its next DLL load. No `CreateRemoteThread`. No `QueueUserAPC`. No `NtCreateThreadEx`. The target process does the work for you.

## How it works

```
    ┌──────────────────────────────────────────────────────────────────────┐
    │                         TARGET PROCESS                              │
    │                                                                     │
    │  ntdll .data                                                        │
    │  ┌────────────────────┐     ┌──────────┐     ┌──────────────────┐   │
    │  │ CreateActCtxWWorker├────►│  fothk   │     │   Your payload   │   │
    │  │    slot (8 bytes)  │     │          │     │                  │   │
    │  └────────┬───────────┘     │ E9 xxxxx │     │  ┌────────────┐ │   │
    │           │                 │ JMP rel32│     │  │ stub:       │ │   │
    │           │     OVERWRITE   │    │     │     │  │  save regs  │ │   │
    │           │◄────────────    │    ▼     │     │  │  restore    │ │   │
    │           │                 │ 48 FF E0 │     │  │   original  │ │   │
    │           ▼                 │ JMP RAX ─┼─X──►│  │  CreateThrd │ │   │
    │                             │ (NO CFG) │     │  │  jmp orig   │ │   │
    │  Loader calls on every      └──────────┘     │  └────────────┘ │   │
    │  LoadLibrary ──────────►                     │  ┌────────────┐ │   │
    │                                              │  │ trampoline │ │   │
    │                                              │  │  CALL +3   │ │   │
    │                                              │  │  payload() │ │   │
    │                                              │  └────────────┘ │   │
    │                                              └──────────────────┘   │
    └──────────────────────────────────────────────────────────────────────┘

    INJECTOR (this tool)                   ATTACK FLOW
    ───────────────────                    ──────────────
    1. Scan local ntdll .text              Pattern: MOV RAX,[rip+disp] → CALL fothk
       to find the .data slot              Verify:  fothk entry = JMP rel32 → JMP RAX
                                           Result:  exact offset, works on any build

    2. Open target process                 NtOpenProcess (indirect syscall)

    3. Allocate RW memory                  NtAllocateVirtualMemory (indirect syscall)

    4. Write stub + payload                NtWriteVirtualMemory (indirect syscall)
                                           Stub auto-restores the original pointer
                                           then dispatches payload via CreateThread

    5. Flip to RX                          NtProtectVirtualMemory (indirect syscall)
                                           No RWX pages — only RW → RX transition

    6. Overwrite the .data pointer         NtWriteVirtualMemory (indirect syscall)
                                           8 bytes. One write. Armed.

    7. Wait.                               Next LoadLibrary triggers the stub.
                                           Loader Lock safe — payload runs in
                                           a new thread via CreateThread dispatch.
```

## What you're not doing

| Property | Detail |
|:---------|:-------|
| **No remote thread** | No `CreateRemoteThread`, `NtCreateThreadEx`, or `RtlCreateUserThread` |
| **No APC** | No `QueueUserAPC` or `NtQueueApcThread` |
| **No exception abuse** | No VEH/SEH/Vectored handlers |
| **No DLL loading** | No `LoadLibrary` in the injector's context |
| **CFG bypass built-in** | fothk dispatch is `JMP RAX` — no CFG bitmap check |
| **Natural trigger** | Any DLL load in the target fires the payload |
| **Self-cleaning** | Stub restores original pointer before executing — one-shot |
| **Loader Lock safe** | Payload runs in a separate thread, not under the lock |
| **Dynamic scanning** | Pattern scan finds the slot on any Windows build |

## Evasion stack

```
 Syscalls     Halo's Gate — SSN resolved at runtime, dispatched through
              a legitimate ntdll syscall;ret instruction (indirect syscall)

 API resolve  CRC32B hash-based — no plaintext API strings in the binary

 Memory       RW → RX — no RWX allocations, clean memory attributes

 Trigger      Passive — no injected thread visible to ETW/thread monitors

 Scanner      fothk pattern scan — no hardcoded offsets, survives updates
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
NightLoom.exe <target_pid> <shellcode.bin>
```

```
> NightLoom.exe 1234 payload.bin

[*] NightLoom — Ldr Activation Context Callback Injection
[*] Target PID: 1234
[*] Payload: 123 bytes from payload.bin
[*] Halo's Gate: 7 syscalls resolved
[*] Scanning .text for fothk-dispatched .data pointers...
[+] .data+0x63E8 → kernel32+0x24F10 (fothk dispatch at ntdll+0x5A3C2)
[+] Confirmed: fothk → JMP RAX (no CFG)
[+] Slot at .data+0x63E8, original value: 0x7FFE12345678
[+] Remote allocation: 0x1A000000000 (RW → RX)
[+] Pointer armed. Waiting for trigger...
[+] Done. Payload will execute on next LoadLibrary in target.
```

## Project structure

```
NightLoom/
├── src/
│   ├── Main.c               # Injector — scanner, stub builder, injection logic
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
├── RESEARCH.md               # Full technical writeup
└── README.md
```

## The fothk section

The `fothk` (Fast Object Type Help) section in `ntdll.dll` contains trampolines used by the Loader for indirect dispatch. Each entry is:

```asm
fothk+0x00:  E9 xx xx xx xx       ; JMP rel32 → shared handler
             ...
shared:      48 FF E0              ; JMP RAX — NO CFG VALIDATION
```

This means any function pointer loaded into `RAX` and dispatched through `fothk` **skips CFG entirely**. The Loader uses this path for activation context callbacks — and NightLoom exploits exactly that.

## Detection

If you're building defenses:

- **Monitor ntdll .data writes** — cross-process writes to ntdll's `.data` section are rare and suspicious
- **Hook `NtWriteVirtualMemory`** — flag writes targeting ntdll address range in remote processes
- **Kernel callback on `.data` modification** — the activation context slot rarely changes after init
- **ETW for `NtProtectVirtualMemory`** — RW→RX transitions in remote processes are a signal
- **Validate fothk dispatch targets** — check that the pointer still resolves to kernel32/KERNELBASE

Microsoft could patch this by adding CFG validation to the fothk dispatch path.

## Disclaimer

This tool is published for **security research and educational purposes only**. It demonstrates a novel injection primitive to advance the public understanding of Windows internals and help defenders build better detection. Use it only in authorized testing environments. The author is not responsible for misuse.

## References

- [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md) — SSN resolution via neighboring syscall stubs
- [Hell's Gate](https://github.com/am0nsec/HellsGate) — Direct syscall invocation from userland
- Windows Loader internals — `LdrpInitializeProcess`, `LdrpRunInitializeRoutines`
- PE/COFF specification — section parsing, `.data` / `fothk` sections
- [CFG internals](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) — why fothk bypasses it

---

<p align="center">
  <sub>The loom weaves in darkness. Built with patience, WinDbg, and too many blue screens.</sub>
</p>
