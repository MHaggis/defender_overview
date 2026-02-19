# Stage 5: PE Emulation

> How mpengine.dll emulates x86/x64/ARM PE executables to observe runtime behavior, unpack protected code, and extract behavioral signatures.
> All data from reverse engineering mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 5 is the PE emulation engine -- a full CPU emulator embedded within mpengine.dll that executes PE files in a sandboxed virtual environment. The emulator interprets x86, x64, and ARM instructions, provides 198 emulated Windows API handlers, loads 973 virtual DLLs (VDLLs) into a synthetic address space, and records behavioral telemetry (FOP opcode traces and API call logs) for signature matching.

The emulator's primary purpose is **dynamic unpacking**: many malware samples encrypt or compress their payloads and only reveal the real code at runtime. By emulating execution, Defender can observe the decrypted payload and scan it through the full pipeline recursively (Stage 6).

### Key RTTI Classes from the Binary

| RTTI Class | Address | Purpose |
|------------|---------|---------|
| `.?AVx86_IL_emulator@@` | `0x10C748CC` | x86 instruction-level emulator |
| `.?AVIL_emulator@@` | `0x10C74B6C` | Base emulator interface |
| `.?AVARM_IL_emulator@@` | `0x10C921C8` | ARM instruction-level emulator |
| `.?AVvdll_data_t@@` | `0x10C7C940` | Virtual DLL data structure |
| `.?AVVirtualProtectCallback@@` | `0x10C7B7B0` | VirtualProtect handler |
| `.?AVPEUnpacker@@` | `0x10C7F6D4` | PE unpacker base class |
| `.?AVUnpackerContext@@` | `0x10C79618` | Unpacker execution context |
| `.?AVUnpackerData@@` | `0x10C852A4` | Unpacker data storage |

*(from RE of mpengine.dll -- `.?AV` RTTI strings in .data section)*

---

## Architecture

### Emulator Class Hierarchy

```
IL_emulator (abstract base)          @ 0x10C74B6C
├── x86_IL_emulator                  @ 0x10C748CC
│   ├── Handles x86 (32-bit) instructions
│   ├── Full FPU emulation via 67 exported FPU_* functions
│   └── SSE conversion via SSE_convert export
├── x86_64_IL_emulator               (inferred from x64 sig types)
│   └── Extends x86 with 64-bit register support
└── ARM_IL_emulator                  @ 0x10C921C8
    └── Handles ARM 32-bit instructions
```

### Virtual Memory Layout

The emulator establishes a synthetic address space for each emulated PE:

```
Virtual Address Map (32-bit PE):
─────────────────────────────────────────────────
0x00010000  ┌─────────────────────────┐
            │  Stack                   │  ← ESP initialized here
            │  (grows downward)        │
0x00020000  ├─────────────────────────┤
            │  TEB / PEB              │  ← Thread/Process Environment
            │                          │     Blocks (synthetic)
0x00030000  ├─────────────────────────┤
            │  LDR Data               │  ← Loader data structures
            │  (module list)           │     (linked list of modules)
0x00400000  ├─────────────────────────┤
            │  PE Image               │  ← Scanned file mapped here
            │  (sections mapped per   │     (at preferred ImageBase)
            │   PE section table)     │
0x10000000  ├─────────────────────────┤
            │  Heap                    │  ← Dynamic allocations
            │  (VirtualAlloc, malloc)  │     from emulated API calls
0x70000000  ├─────────────────────────┤
            │  VDLLs (973 modules)     │  ← Virtual DLLs mapped here
            │  kernel32.dll (vdll)     │     Provide API stubs and
            │  ntdll.dll (vdll)        │     trampoline targets
            │  user32.dll (vdll)       │
            │  ...                     │
0x7FFE0000  ├─────────────────────────┤
            │  API Trampolines        │  ← Transition from emulated
            │                          │     code to WinAPI handlers
0xDEADBEEF  ├─────────────────────────┤
            │  Stop Sentinel           │  ← Execution terminates if
            │                          │     EIP reaches this address
            └─────────────────────────┘
```

*(from RE of mpengine.dll -- memory layout reconstructed from emulator initialization and VDLL mapping logic)*

---

## FPU Emulation

The emulator exports 67 `FPU_*` functions for x87 floating-point instruction emulation. These are real exports from mpengine.dll, callable externally:

### FPU Export Table (67 functions)

| Export | Address | Instruction |
|--------|---------|-------------|
| `FPU_initialize` | `0x10266050` | Initialize FPU state |
| `FPU_finit` | `0x10266020` | FINIT -- reset FPU |
| `FPU_push` | `0x102663B0` | Push value onto FPU stack |
| `FPU_pop` | `0x102663E0` | Pop value from FPU stack |
| `FPU_fld_single` | `0x10266450` | Load 32-bit float |
| `FPU_fld_double` | `0x102664C0` | Load 64-bit float |
| `FPU_fld_ext` | `0x10266530` | Load 80-bit extended |
| `FPU_fst_single` | `0x10266760` | Store 32-bit float |
| `FPU_fst_double` | `0x102667D0` | Store 64-bit float |
| `FPU_fst_ext` | `0x10266840` | Store 80-bit extended |
| `FPU_fadd` | `0x10266C50` | FADD -- addition |
| `FPU_fsub` | `0x10266ED0` | FSUB -- subtraction |
| `FPU_fsubr` | `0x10266F50` | FSUBR -- reverse subtract |
| `FPU_fmul` | `0x102670D0` | FMUL -- multiplication |
| `FPU_fdiv` | `0x10266FD0` | FDIV -- division |
| `FPU_fdivr` | `0x10267050` | FDIVR -- reverse divide |
| `FPU_fcom` | `0x10266CD0` | FCOM -- compare |
| `FPU_fcomi` | `0x10266DD0` | FCOMI -- compare to int |
| `FPU_fucom` | `0x10266D50` | FUCOM -- unordered compare |
| `FPU_fucomi` | `0x10266E50` | FUCOMI -- unordered compare int |
| `FPU_fchs` | `0x102672D0` | FCHS -- change sign |
| `FPU_fabs` | `0x10267340` | FABS -- absolute value |
| `FPU_fsqrt` | `0x10267570` | FSQRT -- square root |
| `FPU_fsin` | `0x10267650` | FSIN -- sine |
| `FPU_fcos` | `0x102676C0` | FCOS -- cosine |
| `FPU_fsincos` | `0x102678D0` | FSINCOS -- sine and cosine |
| `FPU_fptan` | `0x10267500` | FPTAN -- partial tangent |
| `FPU_fpatan` | `0x10267950` | FPATAN -- partial arctangent |
| `FPU_f2xm1` | `0x10267490` | F2XM1 -- 2^x - 1 |
| `FPU_fyl2x` | `0x10267730` | FYL2X -- y * log2(x) |
| `FPU_fyl2xp1` | `0x102677C0` | FYL2XP1 -- y * log2(x+1) |
| `FPU_fscale` | `0x10267250` | FSCALE -- scale by power of 2 |
| `FPU_frndint` | `0x102675E0` | FRNDINT -- round to integer |
| `FPU_fxch` | `0x10266BC0` | FXCH -- exchange registers |
| `FPU_fxtract` | `0x10267850` | FXTRACT -- extract exp/sig |
| `FPU_fprem` | `0x10267150` | FPREM -- partial remainder |
| `FPU_fprem1` | `0x102671D0` | FPREM1 -- IEEE remainder |
| `FPU_ftst` | `0x102673B0` | FTST -- test against 0.0 |
| `FPU_fxam` | `0x10267420` | FXAM -- examine FP value |
| `FPU_fld1` | `0x102679E0` | FLD1 -- load 1.0 |
| `FPU_fldl2t` | `0x10267A50` | FLDL2T -- load log2(10) |
| `FPU_fldl2e` | `0x10267AC0` | FLDL2E -- load log2(e) |
| `FPU_fldpi` | `0x10267B30` | FLDPI -- load pi |
| `FPU_fldlg2` | `0x10267BA0` | FLDLG2 -- load log10(2) |
| `FPU_fldln2` | `0x10267C10` | FLDLN2 -- load ln(2) |
| `FPU_fldz` | `0x10267C80` | FLDZ -- load 0.0 |
| `FPU_fild_s16` | `0x102665A0` | FILD -- load 16-bit int |
| `FPU_fild_s32` | `0x10266610` | FILD -- load 32-bit int |
| `FPU_fild_s64` | `0x10266680` | FILD -- load 64-bit int |
| `FPU_fist_s16` | `0x10266A00` | FIST -- store 16-bit int |
| `FPU_fist_s32` | `0x10266A70` | FIST -- store 32-bit int |
| `FPU_fist_s64` | `0x10266AE0` | FIST -- store 64-bit int |
| `FPU_fistt_s16` | `0x102668B0` | FISTTP -- store truncated 16 |
| `FPU_fistt_s32` | `0x10266920` | FISTTP -- store truncated 32 |
| `FPU_fistt_s64` | `0x10266990` | FISTTP -- store truncated 64 |
| `FPU_fbld` | `0x102666F0` | FBLD -- load BCD |
| `FPU_fbst` | `0x10266B50` | FBST -- store BCD |
| `FPU_fldenv_16` | `0x102661A0` | FLDENV -- load 16-bit env |
| `FPU_fldenv_32` | `0x10266210` | FLDENV -- load 32-bit env |
| `FPU_fstenv_16` | `0x10266270` | FSTENV -- store 16-bit env |
| `FPU_fstenv_32` | `0x102662E0` | FSTENV -- store 32-bit env |
| `FPU_fstsw` | `0x10266090` | FSTSW -- store status word |
| `FPU_ext2double` | `0x10266410` | Convert extended to double |
| `FPU_get_reg` | `0x10266350` | Read FPU register by index |
| `FPU_set_rndprec` | `0x10266150` | Set rounding/precision mode |
| `FPU_save_state` | `0x10266070` | Save entire FPU state |
| `FPU_restore_state` | `0x10266080` | Restore FPU state |

### SSE Support

| Export | Address | Purpose |
|--------|---------|---------|
| `SSE_convert` | `0x10267CF0` | SSE conversion operations |

---

## Emulated Windows API Handlers

The emulator provides 198 Windows API handler functions that intercept calls made by the emulated PE. When emulated code calls a WinAPI function, execution transfers to a trampoline at `0x7FFE0000+`, which routes to the corresponding handler.

### API Categories and Selected Handlers

**Memory Management:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `VirtualAlloc` | `0x10C6B4F6` | Allocate virtual memory |
| `VirtualProtect` | `0x10C6BA2A` | Change memory protection |
| `VirtualProtectEx` | `0x10C6CE14` | Change protection (extended) |

**File Operations:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `CreateFileW` | `0x10C6B562` | Create/open file (VFS write) |
| `CreateFileMappingW` | `0x10C6B710` | Memory-map a file |

**Library Loading:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `LoadLibraryA` | `0x10C6B78E` | Load DLL by ANSI name |
| `LoadLibraryW` | `0x10C6BDA8` | Load DLL by Unicode name |
| `LoadLibraryExW` | `0x10C6B458` | Load DLL with flags |

*(from RE of mpengine.dll -- WinAPI strings in .rdata near emulator dispatch tables)*

### API Handler Architecture

```
Emulated code at 0x00400000+
         │
         │ CALL [IAT entry]  →  resolves to VDLL stub
         │
         ▼
VDLL stub at 0x70000000+
         │
         │ JMP [trampoline]
         │
         ▼
Trampoline at 0x7FFE0000+
         │
         │ Triggers host-side handler dispatch
         │
         ▼
Handler in mpengine.dll (native code)
         │
         │ 1. Read parameters from emulated stack
         │ 2. Simulate API behavior
         │ 3. Record in APICLOG
         │ 4. Write return value to emulated EAX
         │ 5. Return control to emulator
         │
         ▼
Emulated code continues at return address
```

---

## Execution Engine

### Instruction Processing Loop

The core emulation loop fetches, decodes, and executes one instruction at a time:

```
Pseudocode:
─────────────────────────────────────────────────────────────────────────

fn emulate_main_loop(ctx: &mut EmuContext) -> ScanResult {
    let mut insn_count: u32 = 0;
    let max_instructions: u32 = 500_000;   // Hard limit

    loop {
        // Fetch instruction at current EIP
        let eip = ctx.regs.eip;

        // Check stop sentinel
        if eip == 0xDEADBEEF {
            break;  // Normal termination
        }

        // Decode instruction
        let insn = decode_instruction(ctx.memory, eip);

        // Check instruction limit
        insn_count += 1;
        if insn_count >= max_instructions {
            // "abort: execution limit met (%u instructions)"
            //     @ 0x109334D8
            break;
        }

        // Execute instruction
        match insn.opcode_type {
            DASM_OPTYPE_FPU_RM => {
                // Route to FPU_* export function
                // String: "DASM_OPTYPE_FPU_RM" @ 0x109815DC
                execute_fpu_instruction(ctx, &insn);
            }
            _ => execute_general_instruction(ctx, &insn),
        }

        // Check for API trampoline hit
        if eip >= 0x7FFE0000 && eip < 0x7FFF0000 {
            let api_index = (eip - 0x7FFE0000) / TRAMPOLINE_STRIDE;
            handle_api_call(ctx, api_index);
        }

        // Update EIP
        ctx.regs.eip = insn.next_eip;
    }

    return ctx.scan_result;
}
```

### Execution Limits

| Limit | Value | String/Source |
|-------|-------|---------------|
| Max instructions per run | 500,000 | `"abort: execution limit met (%u instructions)"` @ `0x109334D8` |
| Infinite loop detection | configurable | `"Infinite loop detected (more that %d instructions executed)"` @ `0x10983320` |

*(from RE of mpengine.dll -- execution limit strings)*

---

## Behavioral Recording

### FOP (First Opcode Profile)

FOP signatures capture the first N unique opcode sequences at the entry point. This creates a behavioral fingerprint independent of data values:

```
Signature types for FOP:
  SIGNATURE_TYPE_FOP            @ 0x10986C44
  SIGNATURE_TYPE_FOP64          @ 0x109871BC
  SIGNATURE_TYPE_FOPEX          @ 0x10986514
  SIGNATURE_TYPE_FOPEX64        @ 0x10986C70
  SIGNATURE_TYPE_VBFOP          @ 0x10986074
  SIGNATURE_TYPE_VBFOPEX        @ 0x109869F8
  SIGNATURE_TYPE_MSILFOP        @ 0x10986BCC
  SIGNATURE_TYPE_MSILFOPEX      @ 0x10986710
```

FOP rules in the VDM: **4,601** rules across all architectures.

### TUNNEL Signatures

TUNNEL signatures detect patterns in the code flow between the entry point and the first API call:

```
Signature types for TUNNEL:
  SIGNATURE_TYPE_TUNNEL_X86     @ 0x109860A4
  SIGNATURE_TYPE_TUNNEL_X64     @ 0x10986344
  SIGNATURE_TYPE_TUNNEL_ARM     @ 0x10986460
  SIGNATURE_TYPE_TUNNEL_ARM64   @ 0x1098713C
```

### THREAD Signatures

THREAD signatures detect patterns in multi-threaded behavior during emulation:

```
Signature types for THREAD:
  SIGNATURE_TYPE_THREAD_X86     @ 0x109860F4
  SIGNATURE_TYPE_THREAD_X64     @ 0x1098703C
  SIGNATURE_TYPE_THREAD_ARM     @ 0x10986B00
  SIGNATURE_TYPE_THREAD_ARM64   @ 0x10986B58
```

---

## Virtual DLL System

### VDLL Architecture

973 virtual DLLs are loaded into the emulated address space at `0x70000000+`. Each VDLL provides:
- Export stubs that route to API handler trampolines
- Symbolic information for import resolution (`SIGNATURE_TYPE_VDLL_SYMINFO` @ `0x1098614C`)
- Realistic PE structure for malware that validates loaded modules

### VDLL-Related Strings

| String | Address | Purpose |
|--------|---------|---------|
| `isvdllbase` | `0x109819CC` | Check if address is VDLL base |
| `isvdllimage` | `0x109819D8` | Check if address is in VDLL range |
| `reads_vdll_code` | `0x10985924` | VDLL code section reads |
| `dynmem_reads_vdll_code` | `0x10984F48` | Dynamic mem reads VDLL |
| `verbose_vdll_reads` | `0x10985DE8` | Verbose VDLL read logging |
| `NDAT_VFS_LINK` | `0x109811F8` | VFS link for VDLL data |

*(from RE of mpengine.dll -- VDLL strings in .rdata)*

### Import Resolution

When the emulated PE imports a function from e.g. `kernel32.dll`:

1. The emulator finds the corresponding VDLL for `kernel32.dll` in the 973-module list.
2. Resolves the export by name from the VDLL's export table.
3. Patches the Import Address Table (IAT) entry to point to the VDLL export stub.
4. When the emulated code calls through the IAT, it hits the VDLL stub, which jumps to a trampoline, which dispatches to the native handler.

---

## Re-emulation

The emulator supports re-emulation -- running a PE through the emulator again after initial analysis:

```
Key strings:
  "reemulate"     @ 0x10981878
  "MpReemulate"   @ 0x10B76A08
```

Re-emulation can be triggered by:
- Lua scripts requesting deeper analysis
- AAGGREGATOR rules that need post-emulation attributes
- Cloud-returned directives requesting re-analysis with different parameters

---

## Emulation Control Attributes

These attributes (set by static engine matches or DBVAR configuration) control emulation behavior:

| Attribute | Address | Effect |
|-----------|---------|--------|
| `force_unpacking` | `0x109852D4` | Force dynamic unpacking |
| `disable_static_unpacking` | `0x10984AE8` | Disable static unpackers |
| `dt_continue_after_unpacking` | `0x10984D1C` | Continue after unpack |
| `dt_continue_after_unpacking_damaged` | `0x10984D38` | Continue if damaged |
| `pea_force_unpacking` | `0x10A11570` | PE-specific force unpack |
| `pea_disable_static_unpacking` | `0x10A110B8` | PE-specific disable static |

### NID Control Tokens

NID (Named IDentifier) tokens in the VDM database provide engine-level control:

| Token | Address | Purpose |
|-------|---------|---------|
| `NID_DT_CONTINUE_AFTER_UNPACKING` | `0x10980A7C` | Continue post-unpack |
| `NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING` | `0x10980B5C` | Continue if damaged |
| `NID_DT_DISABLE_STATIC_UNPACKING` | `0x10980C30` | Disable static unpackers |
| `NID_DT_ENABLE_STATIC_UNPACKING` | `0x10980C50` | Enable static unpackers |
| `NID_DT_SKIP_UNIMPLEMENTED_OPCODES` | `0x10980A9C` | Skip unimplemented ops |
| `NID_DT_DISABLE_SKIP_UNIMPLEMENTED_OPCODES` | `0x10980AC0` | Force fail on unimpl ops |
| `NID_DT_DISABLE_MICROCODE` | `0x10980C8C` | Disable microcode engine |
| `NID_DT_ENABLE_MICROCODE` | `0x10980CA8` | Enable microcode engine |
| `NID_DISABLE_THREAD_API_LIMITS` | `0x10980CDC` | Remove thread API limits |

*(from RE of mpengine.dll -- NID_DT strings in .rdata)*

---

## PE Analysis Attributes (set_peattribute)

The `set_peattribute` function at string address `0x10981988` deposits structural attributes during PE header parsing, before emulation begins. These 302 `pea_*` attributes describe the static structure of the PE.

See [Stage 4 -- AAGGREGATOR Collection](04_aaggregator_collection.md) for the full list of PE attributes.

---

## VFS (Virtual File System) for Dropped Files

During emulation, when the emulated code calls `CreateFileW` / `WriteFile`, the emulator intercepts these and writes to a Virtual File System:

```
VFS-related strings:
  "NDAT_VFS_LINK"        @ 0x109811F8
  "VFSParams"            @ 0x10B76888
  "(VFS:%ls#%zd)"        @ 0x10B87920
  "(VFS:...%ls#%zd)"     @ 0x10B8790C
  "(VFS:#%zd)"           @ 0x10B87900
  "->(VFS:hosts)"        @ 0x10A4AE44
```

VFS-dropped files are extracted after emulation and fed back through the scan pipeline in Stage 6 (Unpacked Content Scanning).

---

## Emulator Statistics

| Metric | Value |
|--------|-------|
| FPU export functions | 67 |
| SSE export functions | 1 (SSE_convert) |
| Emulated WinAPI handlers | 198 |
| Virtual DLLs (VDLLs) | 973 |
| Max instructions per run | 500,000 |
| FOP behavioral rules | 4,601 |
| TUNNEL signature variants | 4 (x86, x64, ARM, ARM64) |
| THREAD signature variants | 4 (x86, x64, ARM, ARM64) |
| PE analysis attributes | 302 (`pea_*`) |
| Emulator RTTI classes | 3 (x86, base, ARM) |

---

## Cross-References

- **Previous stage**: [Stage 4 -- AAGGREGATOR Collection](04_aaggregator_collection.md) (PE attributes deposited here)
- **Next stage**: [Stage 6 -- Unpacked Content](06_unpacked_content.md) (unpacked PE and VFS files scanned)
- **Behavioral signatures**: Used by [Stage 9 -- BRUTE Matching](09_brute_matching.md) and [Stage 10 -- Lua Scripts](10_lua_scripts.md)
- **Attribute evaluation**: [Stage 11 -- AAGGREGATOR Evaluation](11_aaggregator_evaluation.md) (FOP/TUNNEL/THREAD attributes consumed)
- **Pipeline overview**: [Master Overview](00_overview.md)

---

*Generated from reverse engineering of mpengine.dll v1.1.24120.x*
