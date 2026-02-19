# Stage 01 -- Entry Point & Command Dispatch

> Reverse engineering documentation for **mpengine.dll** v1.1.24120.x
> Source of truth: the actual binary at `engine/mpengine.dll`
---

## 1. Overview

The Windows Defender scan engine is a single monolithic DLL (`mpengine.dll`, ~14.3 MB) that
exposes **90 exports** to its host processes (`MsMpEng.exe`, `MpCmdRun.exe`, AMSI clients).
Every scan request -- whether initiated by real-time protection, scheduled scan, AMSI, or
the command-line tool -- enters through one of two primary dispatcher functions:

| Export         | Virtual Address  | Role                                          |
|----------------|------------------|-----------------------------------------------|
| `__rsignal`    | `0x10133CD0`     | Legacy command router (still the inner core)   |
| `rsignal`      | `0x102BF000`     | Newer outer dispatcher; delegates to `__rsignal` |
| `MpBootStrap`  | `0x102BD660`     | Engine initialization / VDM loading            |

The dispatcher model is **command-code based**: the caller passes an integer opcode
(e.g., `0x4003` for BOOT, `0x400B` for SCAN) and a pointer to a parameter block.
The dispatcher validates the engine state, selects a handler, and invokes it.

---

## 2. Entry Conditions

The entry point fires under these conditions:

1. **MsMpEng.exe** (the Defender service) calls `rsignal` for every real-time-protection event,
   scheduled scan, and on-demand scan.
2. **AMSI providers** (PowerShell, Office VBA, WSH) call `rsignal` with command `0x4019`.
3. **MpCmdRun.exe** (command-line tool) calls `rsignal` for manual scans.
4. **MpBootStrap** is called once during service startup to load VDM signature databases.

---

## 3. Export Table (Selected)

The full export table contains 90 entries. Key exports relevant to the scan pipeline:

```
Export                   VAddr         Description
────────────────────────────────────────────────────────────
__rsignal                0x10133CD0    Inner command dispatcher
rsignal                  0x102BF000    Outer command dispatcher
MpBootStrap              0x102BD660    Engine init / sig load
GetSigFiles              0x102BEE10    VDM file enumeration
MpContainerOpen          0x102BCF00    Container archive open
MpContainerAnalyze       0x102BCB80    Container scan dispatch
MpContainerClose         0x102BCC50    Container cleanup
MpContainerCloseObject   0x102BCCB0    Object cleanup
MpContainerCommit        0x102BCD00    Container write-back
MpContainerDelete        0x102BCD50    Container deletion
MpContainerFreeObjectInfo 0x102BCDA0   Free object metadata
MpContainerGetNext       0x102BCE30    Iterate container items
MpContainerOpenObject    0x102BD090    Open specific object
MpContainerRead          0x102BD120    Read object bytes
MpContainerSetSize       0x102BD1B0    Set object size
MpContainerWrite         0x102BD230    Write object bytes
FPU_finit                0x10266020    FPU emulator init
FPU_fadd                 0x10266C50    FPU emulator add
... (60+ FPU_* emulation helpers)
```

*(from RE of mpengine.dll @ export table)*

---

## 4. Command Codes

The dispatcher uses a flat integer-comparison chain to route commands.
These codes were extracted from the disassembly of `__rsignal` at `0x10133CD0`:

| Code     | Name              | Purpose                                         |
|----------|-------------------|-------------------------------------------------|
| `0x4003` | BOOT_ENGINE       | Initialize engine, load VDM signatures           |
| `0x4004` | UNLOAD_ENGINE     | Tear down engine context                         |
| `0x400A` | SHUTDOWN          | Full shutdown, clears initialized flag           |
| `0x400B` | SCAN_BUFFER       | Primary buffer-scan entry point                  |
| `0x4019` | SCAN_AMSI         | AMSI content scan (scripts, macros)              |
| `0x4036` | SCAN_FILE         | File-based scan (newer path)                     |
| `0x4047` | QUERY_CONFIG      | Configuration query                              |
| `0x4052` | SCAN_DISPATCH     | Direct dispatch (skips some checks)              |
| `0x4059` | SCAN_EXTENDED     | Extended scan with extra parameters              |
| `0x4069` | SCAN_ASYNC        | Async scan submission                            |
| `0x4074` | SCAN_NETWORK      | Network content scan                             |
| `0x4075` | SCAN_NOTIFY       | Notification-based scan trigger                  |
| `0x4090` | SCAN_RUNTIME      | Runtime / BM scan                                |

*(from RE of mpengine.dll @ 0x10133CD0 and 0x102BF000, disassembly comparison chains)*

---

## 5. __rsignal -- The Inner Dispatcher

### 5.1 Disassembly

```asm
; __rsignal @ 0x10133CD0
; Prototype: int __cdecl __rsignal(void* ctx, int cmd, void* param1, void* param2)
;
0x10133CD0    push  ebp
0x10133CD1    mov   ebp, esp
0x10133CD3    and   esp, 0xFFFFFFF8        ; 8-byte align stack
0x10133CD6    mov   eax, [ebp+0xC]         ; eax = cmd (2nd parameter)
0x10133CD9    cmp   eax, 0x4003            ; BOOT_ENGINE?
0x10133CDE    je    handler_common         ; -> 0x10133D02
0x10133CE0    cmp   eax, 0x400B            ; SCAN_BUFFER?
0x10133CE5    je    handler_common         ; -> 0x10133D02
0x10133CE7    cmp   eax, 0x4019            ; SCAN_AMSI?
0x10133CEC    je    handler_common         ; -> 0x10133D02
;
; Commands not in the fast-path: delegate to sub_dispatch @ 0x10133D35
0x10133CEE    push  [ebp+0x14]             ; param2
0x10133CF1    mov   ecx, [ebp+0x8]         ; ctx
0x10133CF4    mov   edx, eax               ; cmd
0x10133CF6    push  [ebp+0x10]             ; param1
0x10133CF9    call  0x10133D35             ; sub_dispatch_rsignal
0x10133CFE    pop   ecx
0x10133CFF    pop   ecx
0x10133D00    jmp   epilogue               ; -> 0x10133D31
;
; handler_common: Fast-path for BOOT/SCAN/AMSI
0x10133D02    mov   ecx, [0x10C707B0]      ; g_engine_context
0x10133D08    cmp   ecx, 0x10C707B0        ; self-pointer = uninitialized sentinel
0x10133D0E    je    return_error           ; -> 0x10133D2C
0x10133D10    test  byte [ecx+0x1C], 1     ; flags & ENGINE_READY?
0x10133D14    je    return_error           ; -> 0x10133D2C
;
; Engine is ready: dispatch via logging trampoline
0x10133D16    push  eax                    ; cmd
0x10133D17    push  0x109C3848             ; trace string addr
0x10133D1C    push  0x35                   ; trace level (53)
0x10133D1E    push  [ecx+0x14]             ; log context
0x10133D21    push  [ecx+0x10]             ; log handle
0x10133D24    call  0x1002C061             ; logging function
0x10133D29    add   esp, 0x14
;
; return_error:
0x10133D2C    mov   eax, 0x800E            ; ERROR_INVALID_STATE
;
; epilogue:
0x10133D31    mov   esp, ebp
0x10133D33    pop   ebp
0x10133D34    ret
```

### 5.2 Pseudocode

```c
// Reconstructed from disassembly at 0x10133CD0
int __cdecl __rsignal(void *ctx, int cmd, void *param1, void *param2) {
    // Fast-path: three most common commands
    if (cmd == 0x4003 || cmd == 0x400B || cmd == 0x4019) {
        ENGINE_CONTEXT *engine = *(ENGINE_CONTEXT**)0x10C707B0;

        // Sentinel check: pointer == address-of-pointer means uninitialized
        if (engine == (ENGINE_CONTEXT*)0x10C707B0)
            return 0x800E;  // ERROR_INVALID_STATE

        // Check ENGINE_READY flag at offset +0x1C
        if (!(engine->flags & 0x01))
            return 0x800E;

        // Log the command via trace subsystem
        log_trace(engine->log_handle,  // [ecx+0x10]
                  engine->log_ctx,     // [ecx+0x14]
                  0x35,                // level
                  0x109C3848,          // format string
                  cmd);

        // Dispatch to actual handler (elided -- large switch)
        return dispatch_command(engine, cmd, param1, param2);
    }

    // Slower path for other commands
    return sub_dispatch_rsignal(ctx, cmd, param1, param2);
}
```

---

## 6. rsignal -- The Outer Dispatcher

### 6.1 Disassembly

```asm
; rsignal @ 0x102BF000
; Prototype: int __cdecl rsignal(int cmd, void* param1, void* param2)
;
0x102BF000    push  ebp
0x102BF001    mov   ebp, esp
0x102BF003    and   esp, 0xFFFFFFF8        ; 8-byte stack alignment
0x102BF006    cmp   byte [0x10CA5654], 0   ; g_engine_initialized?
0x102BF00D    push  esi
0x102BF00E    mov   esi, [ebp+8]           ; esi = cmd
0x102BF011    push  edi
0x102BF012    je    not_initialized        ; -> 0x102BF05A
;
; Engine is initialized -- check for SCAN_DISPATCH (0x4052)
0x102BF014    mov   edx, 0x4052            ; SCAN_DISPATCH
0x102BF019    cmp   esi, edx
0x102BF01B    jne   other_commands         ; -> 0x102BF0BE
;
; Handle SCAN_DISPATCH: validate engine context
0x102BF021    mov   ecx, [0x10C707B0]      ; g_engine_context
0x102BF027    mov   esi, 0x8001            ; default error = E_FAIL
0x102BF02C    cmp   ecx, 0x10C707B0        ; sentinel check
0x102BF032    je    return_fail            ; -> 0x102BF053
0x102BF034    test  byte [ecx+0x1C], 1     ; ENGINE_READY flag
0x102BF038    je    return_fail            ; -> 0x102BF053
;
; Dispatch SCAN_DISPATCH with full parameters
0x102BF03A    push  esi                    ; status code
0x102BF03B    push  [ebp+0x10]             ; param2
0x102BF03E    push  [ebp+0xC]              ; param1
0x102BF041    push  edx                    ; cmd (0x4052)
0x102BF042    push  [ecx+0x14]             ; log_ctx
0x102BF045    push  [ecx+0x10]             ; log_handle
0x102BF048    push  0x36                   ; trace level (54)
0x102BF04A    pop   ecx                    ; calling convention adjust
0x102BF04B    call  0x102BEF4D             ; inner_dispatch
0x102BF050    add   esp, 0x18
;
; return_fail:
0x102BF053    mov   eax, esi               ; return status
0x102BF055    jmp   epilogue               ; -> 0x102BF11A
```

### 6.2 Extended Command Table in rsignal

The `rsignal` function handles additional command codes beyond those in `__rsignal`.
From the disassembly's comparison chain:

```asm
; not_initialized path (engine not booted yet):
0x102BF05A    mov   eax, 0x4059            ; SCAN_EXTENDED
0x102BF05F    cmp   esi, eax
0x102BF061    jg    check_higher           ; -> 0x102BF09A
0x102BF063    je    dispatch_common        ; -> 0x102BF0BE
0x102BF065    mov   eax, esi
0x102BF067    sub   eax, 0x4004            ; check UNLOAD_ENGINE
0x102BF06C    je    dispatch_common
0x102BF06E    sub   eax, 0x32              ; 0x4004 + 0x32 = 0x4036 (SCAN_FILE)
0x102BF071    je    dispatch_common
0x102BF073    sub   eax, 0x1C              ; 0x4036 + 0x1C = 0x4052 (SCAN_DISPATCH)
0x102BF076    je    boot_and_dispatch      ; -> 0x102BF083
;
; boot_and_dispatch: Initialize engine first, then dispatch
0x102BF083    cmp   byte [0x10CA564C], 0   ; g_boot_attempted?
0x102BF08A    je    do_boot                ; -> 0x102BF091
0x102BF08C    call  0x100B8204             ; perform boot sequence
0x102BF091    mov   byte [0x10CA5654], 1   ; g_engine_initialized = true
0x102BF098    jmp   dispatch_common
;
; check_higher: commands > 0x4059
0x102BF09A    mov   eax, esi
0x102BF09C    sub   eax, 0x4069            ; SCAN_ASYNC
0x102BF0A1    je    dispatch_common
0x102BF0A3    sub   eax, 0x0B              ; 0x4069 + 0x0B = 0x4074 (SCAN_NETWORK)
0x102BF0A6    je    dispatch_common
0x102BF0A8    sub   eax, 0x01              ; 0x4074 + 0x01 = 0x4075 (SCAN_NOTIFY)
0x102BF0AB    je    dispatch_common
0x102BF0AD    sub   eax, 0x1A              ; 0x4075 + 0x1A = 0x408F
0x102BF0B0    je    dispatch_common
0x102BF0B2    sub   eax, 0x11              ; 0x408F + 0x11 = 0x40A0 (SCAN_RUNTIME)
0x102BF0B5    je    dispatch_common
```

---

## 7. Global State Variables

| Address        | Size  | Name                   | Description                                  |
|----------------|-------|------------------------|----------------------------------------------|
| `0x10C707B0`   | 4     | `g_engine_context`     | Pointer to ENGINE_CONTEXT struct. Self-pointer (points to own address) when uninitialized. |
| `0x10CA5654`   | 1     | `g_engine_initialized` | Set to `1` after successful BOOT_ENGINE.     |
| `0x10CA564C`   | 1     | `g_boot_attempted`     | Set to `1` after first boot attempt.         |
| `0x10CA5650`   | 4     | `g_engine_handle`      | Opaque engine handle, cleared on SHUTDOWN.   |
| `0x10C6F880`   | 4     | `g_stack_cookie`       | Stack canary value (`0xBB40E64E` observed).  |

*(from RE of mpengine.dll @ 0x102BF006, 0x102BF091, 0x10133D02)*

### 7.1 ENGINE_CONTEXT Structure (Partial)

```c
// Reconstructed from field accesses across __rsignal, rsignal, MpBootStrap
struct ENGINE_CONTEXT {          // @ 0x10C707B0 (when initialized)
    /* +0x00 */ void*   vtable;             // virtual function table
    /* +0x04 */ uint32_t ref_count;
    /* +0x08 */ void*   vdm_handle;         // loaded signature database
    /* +0x0C */ void*   config_ptr;         // engine configuration
    /* +0x10 */ void*   log_handle;         // ETW/trace log handle
    /* +0x14 */ void*   log_ctx;            // trace context pointer
    /* +0x18 */ uint32_t engine_version;
    /* +0x1C */ uint8_t  flags;             // bit 0 = ENGINE_READY
                                            // bit 3 = LOGGING_ENABLED
    /* +0x1D */ uint8_t  reserved[3];
    /* +0x20 */ void*   scan_pool;          // thread pool for async scans
    /* +0x24 */ void*   sig_compiler;       // compiled signature state
    // ... (hundreds more fields)
};
```

*(from RE of mpengine.dll @ 0x10133D02, 0x102BF034, 0x102BF0F9)*

---

## 8. MpBootStrap -- Engine Initialization

### 8.1 Disassembly

```asm
; MpBootStrap @ 0x102BD660
; Prototype: HRESULT __cdecl MpBootStrap(void* config, void* output)
;
0x102BD660    push  0x0C                   ; SEH frame size
0x102BD662    mov   eax, 0x108D60DF        ; SEH handler address
0x102BD667    call  0x10268FD1             ; __SEH_prolog
0x102BD66C    mov   edx, [ebp+0xC]         ; output parameter
0x102BD66F    mov   ecx, [ebp+0x8]         ; config parameter
0x102BD672    mov   [ebp-4], 0             ; SEH state = 0
0x102BD679    call  0x10322CAA             ; inner_bootstrap(config, output)
0x102BD67E    mov   esi, eax               ; result = HRESULT
0x102BD680    jmp   check_result           ; -> 0x102BD696
;
; Exception handler path:
0x102BD682    push  [ebp-0x18]
0x102BD685    call  0x101E3424             ; exception cleanup
0x102BD68A    mov   [ebp-0x14], eax
;
; check_result:
0x102BD696    test  esi, esi               ; SUCCEEDED(result)?
0x102BD698    jns   success                ; -> 0x102BD6D5
;
; Failure path: log error
0x102BD69C    mov   [ebp-0x14], 0x80004005 ; E_FAIL
0x102BD6AC    mov   eax, [0x10C707B0]      ; g_engine_context
0x102BD6B1    cmp   eax, 0x10C707B0        ; sentinel check
0x102BD6B6    je    skip_log               ; -> 0x102BD6D5
0x102BD6B8    test  byte [eax+0x1C], 1     ; ENGINE_READY?
0x102BD6BC    je    skip_log
0x102BD6BE    push  esi                    ; error code
0x102BD6BF    push  [eax+0x14]             ; log context
0x102BD6C2    mov   edx, 0x109C35F8        ; format string address
```

### 8.2 Pseudocode

```c
HRESULT __cdecl MpBootStrap(void *config, void *output) {
    __try {
        HRESULT hr = inner_bootstrap(config, output);  // @ 0x10322CAA
        if (FAILED(hr)) {
            ENGINE_CONTEXT *engine = *(ENGINE_CONTEXT**)0x10C707B0;
            if (engine != (ENGINE_CONTEXT*)0x10C707B0 &&
                (engine->flags & ENGINE_READY)) {
                log_error(engine->log_ctx, "Bootstrap failed: 0x%08x", hr);
            }
            return E_FAIL;  // 0x80004005
        }
        return hr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        cleanup_exception();
        return E_FAIL;
    }
}
```

---

## 9. Sentinel Pattern -- Self-Pointer Initialization Guard

A distinctive pattern used throughout the engine is the **self-pointer sentinel**.
The global `g_engine_context` at `0x10C707B0` is initialized to point to its own
address (`0x10C707B0`). This creates a cheap NULL-like check:

```
; Pattern seen in __rsignal, rsignal, and MpBootStrap:
mov   ecx, [0x10C707B0]      ; load pointer
cmp   ecx, 0x10C707B0        ; compare with own address
je    not_initialized         ; if equal, engine is not ready
```

Once `MpBootStrap` succeeds, `g_engine_context` is overwritten with the address
of the actual `ENGINE_CONTEXT` heap allocation. The sentinel check then passes,
and the engine is operational.

---

## 10. Flow Diagram

```
                              ┌───────────────────────┐
                              │  MsMpEng.exe / AMSI   │
                              │  MpCmdRun.exe         │
                              └──────────┬────────────┘
                                         │
                                   rsignal(cmd, p1, p2)
                                   @ 0x102BF000
                                         │
                            ┌────────────┴────────────┐
                            │  Check g_initialized     │
                            │  @ 0x10CA5654            │
                            └────────────┬────────────┘
                                    ┌────┴────┐
                                    │ = 0 ?   │
                                    └────┬────┘
                              No ───┘         └─── Yes
                              │                     │
                     ┌────────┴────────┐   ┌───────┴────────┐
                     │ cmd == 0x4052?  │   │ Auto-boot path │
                     │ (SCAN_DISPATCH) │   │ call 0x100B8204│
                     └────────┬────────┘   │ set init = 1   │
                         ┌────┴────┐       └───────┬────────┘
                    Yes ─┘         └─ No           │
                    │                  │            │
           ┌────────┴──────┐    ┌─────┴──────┐     │
           │ Direct engine │    │ Delegate to│     │
           │ dispatch with │    │ __rsignal  │◄────┘
           │ context check │    │ @ 10133CD0 │
           └────────┬──────┘    └─────┬──────┘
                    │                  │
                    ▼                  ▼
           ┌──────────────────────────────────┐
           │        Command Switch            │
           │   0x4003 → BOOT_ENGINE           │
           │   0x400B → SCAN_BUFFER           │
           │   0x4019 → SCAN_AMSI             │
           │   0x4036 → SCAN_FILE             │
           │   ...                            │
           └───────────────┬──────────────────┘
                           │
                           ▼
           ┌──────────────────────────────────┐
           │  Stage 02: FRIENDLY_FILE Check   │
           │  (SHA-256 whitelist)             │
           └──────────────────────────────────┘
```

---

## 11. Relevant Strings from Binary

| Address        | String                          | Context                                |
|----------------|---------------------------------|----------------------------------------|
| `0x109C3848`   | *(trace format string)*         | Used in `__rsignal` logging call       |
| `0x109C35F8`   | *(error format string)*         | Used in `MpBootStrap` error logging    |
| `0x109D4BE0`   | `Engine.Scan.QuickScanStarted`  | ETW trace event for quick scan         |
| `0x109D4C14`   | `Engine.Scan.QuickScanEnded`    | ETW trace event for quick scan end     |
| `0x109D4C38`   | `Engine.Scan.FullScanStarted`   | ETW trace event for full scan          |
| `0x109D4C68`   | `Engine.Scan.FullScanEnded`     | ETW trace event for full scan end      |
| `0x109D4CF4`   | `Engine.Scan.ScanAborted`       | ETW trace event for scan abort         |
| `0x109D4E98`   | `Engine.Scan.LogFailedScan`     | ETW trace event for scan failure       |
| `0x109C3D94`   | `Engine.Scan.AsyncStats`        | ETW trace for async scan stats         |
| `0x109C6068`   | `Engine.Scan.Unpacker`          | ETW trace for unpacker events          |
| `0x10A33C0C`   | `Engine.Scan.FileScan`          | ETW trace for file scan start          |

---

## 12. Error Return Codes

| Code       | Meaning                                                  |
|------------|----------------------------------------------------------|
| `0x800E`   | `ERROR_INVALID_STATE` -- engine not initialized          |
| `0x8001`   | `E_FAIL` -- general failure from SCAN_DISPATCH path      |
| `0x80004005` | `E_FAIL` (HRESULT) -- bootstrap failure                |

---

## 13. Security Notes

- The 8-byte stack alignment (`and esp, 0xFFFFFFF8`) at both entry points ensures
  proper alignment for SSE instructions used deeper in the scan pipeline.
- Stack canary at `0x10C6F880` (observed value `0xBB40E64E`) protects the sub-dispatch
  function at `0x10133D35` from stack buffer overflows.
- The SEH chain in `MpBootStrap` (handler at `0x108D60DF`) ensures engine init failures
  do not crash the host process.

---

## 14. Cross-References

- **Next stage**: [02 -- FRIENDLY_FILE Check](02_friendly_file.md)
- **Pipeline overview**: [00 -- Master Overview](00_overview.md)
- **Static engine cascade**: [03 -- Static Engine Cascade](03_static_engine_cascade.md)

---

*All addresses are from the actual binary image base 0x10001000.*
