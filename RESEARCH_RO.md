# GhostCtx — Injectare prin Callback-ul Activation Context al Loader-ului

**O Tehnică Nouă de Injectare în Proces prin Dispatch-ul unui Pointer de Funcție Scriibil din ntdll**

---

## Rezumat

Prezentăm **GhostCtx**, o tehnică nouă de injectare în procese Windows care exploatează un pointer de funcție nedocumentat și scriibil din secțiunea `.data` a ntdll. În timpul inițializării procesului, Loader-ul Windows (Ldr) stochează adresa internă `CreateActCtxWWorker` din kernel32 la un offset fix în segmentul de date scriibil al ntdll. La fiecare apel `LoadLibrary`, Loader-ul dispatch-uiește prin acest pointer via un **trampolin fothk** — un gadget `JMP RAX` care ocolește complet validarea Control Flow Guard (CFG). Prin suprascrierea acestui singur QWORD dintr-un proces remote, un atacator redirecționează execuția la următorul DLL load natural, fără a crea thread-uri, a pune în coadă APC-uri sau a manipula vreo structură de callback.

GhostCtx necesită doar trei primitive syscall: `NtOpenProcess`, `NtAllocateVirtualMemory` și `NtWriteVirtualMemory`. Se declanșează natural prin activitatea proprie de încărcare DLL a țintei, nu lasă hook-uri persistente și restaurează automat pointerul original după o singură execuție.

**Cuvinte cheie:** injectare în proces, activation context, ntdll, loader, bypass CFG, fothk, syscall-uri indirecte

---

## 1. Introducere

Injectarea în proces este o capabilitate ofensivă fundamentală pe Windows, permițând execuția de cod în spațiul de adrese al unui alt proces. Tehnicile consacrate includ injectarea DLL via `CreateRemoteThread`, injectarea APC, deturnarea thread-urilor și diverse metode bazate pe callback-uri care vizează structuri precum lanțul VEH (Vectored Exception Handler), callback-uri WNF, callback-uri FLS, `KernelCallbackTable` și altele.

Apărările moderne — în special **Control Flow Guard (CFG)** și **Arbitrary Code Guard (ACG)** — au ridicat semnificativ ștacheta. CFG validează țintele apelurilor indirecte față de un bitmap de adrese legitime, iar ACG previne generarea dinamică de cod. Majoritatea tehnicilor de injectare publicate necesită fie crearea de thread-uri noi (detectate prin ETW), punerea în coadă a APC-urilor (monitorizate de EDR), fie vizarea structurilor de callback care sunt acum protejate de validarea CFG.

Am identificat o suprafață de atac trecută cu vederea: **mecanismul de dispatch al activation context-ului din Loader**. Loader-ul Windows stochează pointeri de funcție pentru operațiunile activation context în secțiunea scriibilă `.data` a ntdll. Acești pointeri sunt apelați prin secțiunea dedicată **fothk** (fast-over-the-hook) care folosește `JMP RAX` — un salt indirect prin registru care **nu** trece prin validarea `__guard_dispatch_icall_fptr` a CFG. Aceasta creează o primitivă de execuție de cod fiabilă, care ocolește CFG, declanșată de orice apel `LoadLibrary` din procesul țintă.

### 1.1 Modelul de Amenințare

GhostCtx presupune că atacatorul are:
- Un handle către procesul țintă cu acces `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE`
- Shellcode compatibil cu semnătura `LPTHREAD_START_ROUTINE` (primește un parametru, returnează DWORD)

Tehnica **nu** necesită:
- Drepturi de creare thread-uri (`PROCESS_CREATE_THREAD`)
- Privilegii de debug
- Acces kernel-mode
- Modificarea header-elor PE sau a structurilor protejate

---

## 2. Context Tehnic

### 2.1 Subsistemul Activation Context

Activation Context-urile Windows sunt un mecanism bazat pe XML pentru versionarea DLL-urilor și rezoluția assembly-urilor side-by-side (SxS). Subsistemul este împărțit între kernel32/KERNELBASE (API-uri user-facing: `CreateActCtxW`, `ActivateActCtx`, `ReleaseActCtx`) și ntdll (suport intern loader).

În timpul inițializării procesului, Loader-ul rezolvă funcțiile worker interne ale kernel32 și stochează adresele lor în secțiunea `.data` a ntdll pentru utilizare ulterioară. Trei pointeri formează un cluster:

| Offset .data | Funcție | Scop |
|---|---|---|
| `+0x63F0` | `BasepGetPackageActivationTokenForSxS` | Rezoluția token-ului de activare pachet |
| `+0x63F8` | `ReleaseActCtx` (intern) | Curățare activation context |
| **`+0x6410`** | **`CreateActCtxWWorker`** | **Crearea activation context (ținta noastră)** |

> **Notă:** Aceste offset-uri sunt din ntdll Windows 11 26100. Tehnica le rezolvă dinamic la runtime prin scanare de pattern-uri (Secțiunea 4.2).

### 2.2 Trampolinul fothk

ntdll conține o secțiune PE dedicată numită **fothk** ("fast over the hook"). Această secțiune oferă stub-uri trampolin folosite de Loader pentru a dispatch-ui apeluri către funcțiile kernel32 stocate în `.data`. Dispatch-ul urmează un lanț în două etape:

```
.text (cod Ldr)                     secțiunea fothk
───────────────                     ────────────────
MOV RAX, [rip+disp]  ─── încarcă ──→ .data+0x6410 (pointer funcție)
CALL fothk_entry     ──────────┐
                               │
                     ┌─────────┘
                     ▼
                  E9 xx xx xx xx    ; JMP rel32 (etapa 1)
                        │
                        ▼
                  48 FF E0          ; JMP RAX (etapa 2)
                                      ↑
                                      └── FĂRĂ VALIDARE CFG
```

Observația critică: **`JMP RAX` este un salt indirect necondiționat prin registru, nu un `CALL` prin `__guard_dispatch_icall_fptr`**. CFG validează doar apelurile indirecte dispatch-uite prin propria funcție guard. Trampolinul fothk ocolește acest lucru complet deoarece a fost proiectat înainte de CFG și operează pe pointeri considerați "de încredere" de Loader.

### 2.3 Frecvența de Declanșare

Pointerul `CreateActCtxWWorker` de la `.data+0x6410` este apelat la **fiecare invocare `LoadLibrary`/`LdrLoadDll`**. În procese precum `explorer.exe`, încărcările de DLL au loc constant datorită extensiilor shell, activării COM și task-urilor de fundal. Aceasta înseamnă că codul injectat se execută în câteva secunde fără nicio declanșare explicită — procesul țintă îl declanșează prin propria operare normală.

---

## 3. De Ce Este Nouă Această Tehnică

Am efectuat cercetări extinse pentru a confirma că această tehnică nu este documentată anterior:

| Tehnică | Status | Diferența cheie față de GhostCtx |
|---|---|---|
| VEH Chain Hijacking | Publicată (mehrn00/VEH-Hijack) | Modifică `.mrdata` din ntdll (read-only la runtime) |
| WNF Callback Injection | Publicată (modexp) | Vizează callback-uri WNF, validate CFG |
| LdrpDllNotificationList | Publicată (multiple) | Vizează callback-uri notificare DLL |
| FLS Callback Injection | Publicată (PoolParty) | Vizează callback-uri Fiber Local Storage |
| KernelCallbackTable | Publicată (modexp/odzhan) | Vizează tabelul callback PEB (dispatch kernel-to-user) |
| BaseThreadInitThunk | Publicată (ntos322, odzhan) | Suprascrie pointerul funcției de inițializare thread |
| PEB.ShimData | Publicată | Vizează datele shim Application Compatibility |
| Early Cascade | Publicată | Vizează inițializarea timpurie a procesului |
| **GhostCtx (această lucrare)** | **Nouă** | **Vizează dispatch-ul activation context al Ldr-ului via fothk (fără CFG)** |

Distincția cheie: GhostCtx vizează o **cale de dispatch internă a loader-ului** care folosește `JMP RAX` prin secțiunea fothk, complet în afara sferei de validare a CFG. Nicio lucrare anterioară nu a documentat această suprafață de atac.

---

## 4. Implementare

### 4.1 Prezentarea Arhitecturii

GhostCtx operează în cinci faze:

```
┌──────────────────────────────────────────────────────────┐
│  Faza 0: Inițializare Halo's Gate (rezolvă 6 syscall-uri)│
├──────────────────────────────────────────────────────────┤
│  Faza 1: Localizare slot .data (scanner dinamic 3 metode)│
├──────────────────────────────────────────────────────────┤
│  Faza 2: Deschidere proces țintă (NtOpenProcess)         │
├──────────────────────────────────────────────────────────┤
│  Faza 3: Verificare slot remote = slot local              │
├──────────────────────────────────────────────────────────┤
│  Faza 4: Construire stub + payload → alocare + scriere    │
├──────────────────────────────────────────────────────────┤
│  Faza 5: Suprascriere pointer .data → armare trigger      │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Rezoluția Dinamică a Offset-ului

Offset-urile hard-codate se strică între versiunile Windows. GhostCtx folosește o cascadă de trei metode pentru a localiza pointerul țintă la runtime:

**Metoda 1 — Rezoluție prin Export:** Se încearcă rezolvarea `CreateActCtxWWorker` din kernel32 după nume și scanarea `.data` din ntdll pentru o valoare potrivită. Funcționează când kernel32 exportă funcția worker.

**Metoda 2 — Scanare Pattern (principală):** Se scanează secțiunea `.text` a ntdll pentru pattern-ul de instrucțiuni:
```asm
MOV RAX, [RIP+disp32]   ; 48 8B 05 xx xx xx xx — încarcă pointer din .data
; ... (în 48 de bytes) ...
CALL fothk_entry         ; E8 xx xx xx xx — apelează în secțiunea fothk
```
Pentru fiecare potrivire, se verifică:
1. Displacement-ul RIP-relativ se rezolvă la o adresă din `.data`
2. Valoarea de la acea adresă `.data` este un pointer valid de cod kernel32
3. Ținta CALL este în secțiunea fothk
4. Intrarea fothk urmează lanțul `E9 (JMP rel32) → 48 FF E0 (JMP RAX)`

Această metodă este independentă de versiune deoarece identifică pointerul prin **pattern-ul său de utilizare**, nu prin offset.

**Metoda 3 — Scanare Fallback pe Interval:** Dacă scanarea de pattern-uri eșuează (de ex., codul Ldr a fost restructurat), se scanează `.data+0x6300..0x6500` pentru pointeri de cod kernel32. Cluster-ul de pointeri activation context a fost în acest interval pe toate build-urile Windows 10/11 observate.

### 4.3 Syscall-uri Indirecte Halo's Gate

Toate apelurile NT API folosesc **Halo's Gate** — o tehnică ce rezolvă System Service Numbers (SSN) dinamic prin parcurgerea stub-urilor syscall vecine din tabela de export-uri a ntdll. Dacă stub-ul țintă este hooked (primii bytes nu sunt `4C 8B D1; B8 xx xx 00 00`), GhostCtx parcurge în sus și în jos cu pasul 32 (dimensiunea standard a stub-ului), examinând ±255 vecini până când se găsește un stub nemodificat. SSN-ul este calculat ca `SSN_vecin ± distanță`.

Dispatch-ul syscall se efectuează printr-un **JMP indirect** către instrucțiunea `syscall` găsită într-un stub vecin legitim, evitând complet stub-ul hooked:

```asm
; SyscallDispatch.asm
PrepareGate:
    mov [ssn_store], ecx        ; SSN
    mov [target_store], rdx     ; adresa legitimă syscall;ret
    ret

DispatchGate:
    mov r10, rcx                ; primul arg → r10 (convenție syscall)
    mov eax, [ssn_store]        ; SSN → eax
    jmp qword ptr [target_store] ; salt la instrucțiunea syscall
```

Șase syscall-uri sunt rezolvate: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtClose`, `NtQueryVirtualMemory`.

### 4.4 Designul Stub-ului de Shellcode

Codul injectat constă dintr-un **stub de 112 bytes (0x70)** prefixat payload-ului utilizatorului. Stub-ul trebuie să gestioneze o constrângere critică: **se execută în timp ce Loader Lock-ul este deținut**. Callback-ul este invocat în timpul `LdrLoadDll` → procesarea activation context, iar secțiunea critică a Ldr-ului este activ deținută de thread-ul apelant.

**Problema Deadlock-ului Loader Lock:**
Dacă payload-ul apelează orice funcție care declanșează un DLL load (de ex., `WinExec` → `CreateProcess` → `LoadLibrary`), aceasta va încerca să re-achiziționeze Loader Lock-ul. `CreateProcess` efectuează intern operațiuni care duc la deadlock când sunt apelate din interiorul căii de procesare a Ldr-ului.

**Soluție — Dispatch prin CreateThread:**
Stub-ul apelează `CreateThread` pentru a lansa payload-ul într-un thread nou. `CreateThread` în sine nu necesită Loader Lock-ul (apelează `NtCreateThreadEx` prin syscall). Thread-ul nou pornește independent, iar când are nevoie eventual de Loader Lock (de ex., dacă payload-ul apelează `LoadLibrary`), thread-ul original a returnat deja din callback și a eliberat lock-ul.

```
Layout Stub (0x70 bytes):
┌─────────┬────────────────────────────────────────────────┐
│ 00 - 0A │ Salvare 7 registre volatile (push)             │
│ 0B - 0E │ sub rsp, 0x30 (shadow space + argumente stivă)│
│ 0F - 25 │ Restaurare pointer original .data              │
│ 26 - 54 │ CreateThread(NULL, 0, payload, NULL, 0, 0)     │
│ 55 - 63 │ Restaurare stivă și registre (pop)             │
│ 64 - 6F │ JMP la funcția originală (tail call)           │
│ 70+     │ Payload (LPTHREAD_START_ROUTINE)               │
└─────────┴────────────────────────────────────────────────┘
```

Puncte de patch (completate la runtime cu adresele rezolvate):
- `+0x11`: adresa slot-ului `.data` din ntdll (pentru restaurarea pointerului)
- `+0x1B`: valoarea originală a pointerului de funcție
- `+0x2C`: adresa payload (baza alocării remote + 0x70)
- `+0x4B`: adresa `CreateThread` (din kernel32, aceeași bază în toate procesele)
- `+0x66`: pointer funcție original (pentru tail-call)

Stub-ul efectuează **auto-curățare**: restaurează pointerul original din `.data` înainte de a apela `CreateThread`, asigurând că hook-ul se execută exact o singură dată. Tail-call-ul `JMP` către funcția originală asigură că operația activation context a Ldr-ului se completează normal, menținând stabilitatea procesului.

### 4.5 Alinierea Stivei

ABI-ul x64 necesită RSP aliniat la 16 bytes înainte de orice instrucțiune `CALL`. Matematica stivei stub-ului:

1. **Intrare:** RSP = 16n - 8 (adresa de retur din `CALL`-ul original care a ajuns la trampolinul fothk)
2. **7 push-uri (56 bytes):** RSP = 16n - 8 - 56 = 16n - 64 = 16(n-4) → **aliniat**
3. **sub rsp, 0x30 (48 bytes):** RSP = 16(n-4) - 48 = 16(n-7) → **aliniat**
4. **Înainte de `CALL rax` (CreateThread):** RSP este aliniat la 16 bytes ✓

---

## 5. Fluxul Atacului

```
 Procesul Atacatorului                    Procesul Țintă (explorer.exe)
 ────────────────────                     ─────────────────────────────
                                          
 1. Rezolvă SSN-urile via                 ntdll .data+0x6410:
    Halo's Gate                           ┌──────────────────────┐
                                          │ kernel32+0x24FB0     │ ← CreateActCtxWWorker
 2. Scanează pattern ntdll                └──────────────────────┘
    pentru .data+0x6410                            │
                                                   │ (apelat la fiecare LoadLibrary
 3. NtOpenProcess(țintă)                           │  via fothk JMP RAX)
                                                   │
 4. NtReadVirtualMemory                            ▼
    (verifică slot remote)              
                                      
 5. Construiește stub (0x70) + payload
    Patch: slot, orig, payload,       
           CreateThread, orig_jmp     
                                      
 6. NtAllocateVirtualMemory(RWX)      ───→  [stub|payload] alocat
                                      
 7. NtWriteVirtualMemory(stub+pay)    ───→  [stub|payload] scris
                                      
 8. NtWriteVirtualMemory(slot .data)  ───→  .data+0x6410 = &stub
                                             ┌──────────────────────┐
                                             │ → adresa stub        │
                                             └──────────────────────┘
                                      
 ─── atacatorul a terminat ───               ... trece timpul ...
                                      
                                      9. Ținta apelează LoadLibrary (natural)
                                         → Ldr citește .data+0x6410
                                         → fothk: JMP RAX → stub
                                      
                                      10. Stub-ul:
                                          a) Restaurează pointerul original
                                          b) CreateThread(payload)
                                          c) JMP la funcția originală
                                      
                                      11. Thread-ul nou rulează payload-ul
                                          (în afara Loader Lock-ului)
                                      
                                      12. Procesul continuă normal
```

---

## 6. Detecție și Mitigare

### 6.1 Oportunități de Detecție

| Nivel | Observabil |
|---|---|
| **ETW / Monitorizare syscall** | `NtWriteVirtualMemory` vizând secțiunea `.data` a ntdll dintr-un proces remote |
| **Integritate memorie** | Valoarea `.data+0x6410` din ntdll schimbată la o adresă non-kernel32 |
| **Creare thread** | Thread nou cu adresă de start într-o alocare `PAGE_EXECUTE_READWRITE` |
| **Analiză pagini cod** | Alocare RWX conținând un pattern stub → CreateThread → payload |

### 6.2 Recomandări de Mitigare

1. **Acoperire CFG pentru dispatch-ul fothk:** Cauza principală este că fothk folosește `JMP RAX` fără validare CFG. Microsoft ar putea adăuga verificări CFG pe această cale de dispatch.

2. **Protecție read-only pentru pointerii de funcție Ldr:** Slot-ul `.data+0x6410` ar putea fi mutat în `.mrdata` (read-only la runtime) după inițializare, similar cu modul în care pointerii handler-ilor VEH sunt protejați.

3. **Monitorizare integritate:** Vendorii EDR ar trebui să monitorizeze scrierile în secțiunea `.data` a ntdll, în special cluster-ul de pointeri activation context la offset-urile cunoscute.

4. **Euristici pentru scrieri cross-proces:** Semnalizarea apelurilor `NtWriteVirtualMemory` unde adresa țintă se află în intervalul de adrese al ntdll din procesul țintă.

---

## 7. Divulgare Responsabilă

Această cercetare este publicată în scopuri defensive și educaționale. Tehnica exploatează o limitare de design în mecanismul de dispatch al Loader-ului Windows. Recomandăm ca:

- Vendorii EDR/AV să adauge semnături de detecție pentru scrieri în regiunea pointerilor activation context din `.data` a ntdll
- Microsoft să ia în considerare întărirea căii de dispatch fothk cu validare CFG sau mutarea stocării pointerilor de funcție ai Ldr-ului în read-only post-inițializare

---

## 8. Concluzii

GhostCtx demonstrează că structurile de date interne ale ntdll Windows rămân o suprafață de atac bogată. Mecanismul de dispatch al activation context-ului din Loader — proiectat pentru performanță via trampolinul fothk — creează o primitivă de execuție de cod care ocolește CFG, accesibilă prin operațiuni standard de memorie virtuală. Tehnica nu necesită drepturi de creare thread-uri, nu pune APC-uri în coadă și se declanșează natural prin activitatea proprie de încărcare DLL a țintei.

Combinația de:
- **Pointer de funcție scriibil** în `.data` a ntdll (neprotejat de `.mrdata`)
- **Dispatch fothk JMP RAX** (fără validare CFG)
- **Trigger natural de frecvență ridicată** (fiecare apel LoadLibrary)
- **Cerințe minime de primitive** (3 syscall-uri: open + alloc + write)

...face din aceasta un vector de injectare practic și stealth. Sperăm că această divulgare ajută comunitatea defensivă să dezvolte detecții adecvate și încurajează Microsoft să întărească această cale de dispatch.

---

## Anexa A: Fișiere

| Fișier | Descriere |
|---|---|
| `GhostCtx/Main.c` | Tool complet — Halo's Gate, rezoluție dinamică, stub CreateThread |
| `ghostctx_poc.c` | PoC minimal cross-proces (NT API direct, offset hard-codat) |
| `poc_actctx2.c` | PoC local — hook-uiește toți 3 pointerii actctx, confirmă frecvența de declanșare |
| `verify_actctx.c` | Utilitar de analiză — dezasamblează lanțul de dispatch fothk |
| `check_dispatch.c` | Verificare pattern JMP RAX fothk |
| `GhostVEH/HalosGate.c` | Resolver SSN Halo's Gate cu parcurgere vecini |
| `GhostVEH/PebResolver.c` | Rezoluție modul + API bazată pe PEB cu API set v2-v6 |
| `GhostVEH/SyscallDispatch.asm` | Dispatcher syscall indirect (PrepareGate/DispatchGate) |

## Anexa B: Mediul Testat

- **OS:** Windows 11 Pro 26100.2605
- **ntdll:** 10.0.26100.2605
- **Țintă:** explorer.exe (frecvență ridicată de DLL-load)
- **Payload:** Shellcode WinExec("calc",1) (123 bytes)
- **Rezultat:** Calculator lansat în contextul explorer-ului; explorer-ul a rămas stabil

## Anexa C: Comparație cu Variantele PoolParty

Cercetarea PoolParty de la SafeBreach (2023) a documentat injectarea prin work item-uri din Thread Pool-ul Windows. Deși atât PoolParty cât și GhostCtx evită `CreateRemoteThread`, ele vizează subsisteme fundamental diferite:

| | PoolParty | GhostCtx |
|---|---|---|
| **Țintă** | Worker factories Thread Pool | Dispatch activation context Loader |
| **Tip callback** | Work item / timer / I/O completion | Pointer funcție în .data |
| **CFG** | Variază pe variantă | Ocolit (fothk JMP RAX) |
| **Declanșare** | Programare thread pool | Orice apel LoadLibrary |
| **Primitive** | NtSetInformationWorkerFactory + altele | NtAllocateVirtualMemory + NtWriteVirtualMemory |
| **Creare thread** | Indirectă (pool) | CreateThread în stub (rulează în afara Ldr lock-ului) |

---

*GhostCtx — Xorganic, 2026*
