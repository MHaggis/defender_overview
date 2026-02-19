# Stage 6: Unpacked Content Scanning

> How mpengine.dll scans the output of PE emulation -- modified PE sections and VFS-dropped files -- by recursively feeding them back through the full scan pipeline.
> All data from reverse engineering mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 6 is the bridge between PE emulation (Stage 5) and the rest of the scan pipeline. After the emulator runs, the engine checks for two categories of modified content:

1. **Modified PE sections** -- Sections of the original PE that were overwritten during emulation (self-modifying code, runtime decryption, unpacking stubs).
2. **VFS-dropped files** -- Files created by the emulated code through intercepted `CreateFileW` / `WriteFile` API calls, stored in the Virtual File System.

Both types of content are extracted and fed back through the full scan pipeline starting at Stage 2 (FRIENDLY_FILE check), creating a recursive scan loop.

### Key Strings from the Binary

| String | Address | Section |
|--------|---------|---------|
| `Engine.Scan.Unpacker` | `0x109C6068` | `.rdata` |
| `Unpacker` | `0x109C6080` | `.rdata` |
| `dt_continue_after_unpacking` | `0x10984D1C` | `.rdata` |
| `dt_continue_after_unpacking_damaged` | `0x10984D38` | `.rdata` |
| `force_unpacking` | `0x109852D4` | `.rdata` |
| `disable_static_unpacking` | `0x10984AE8` | `.rdata` |
| `pea_disable_static_unpacking` | `0x10A110B8` | `.rdata` |
| `pea_force_unpacking` | `0x10A11570` | `.rdata` |
| `pea_dt_continue_after_unpacking` | `0x10A11A88` | `.rdata` |
| `pea_dt_continue_after_unpacking_damaged` | `0x10A11B28` | `.rdata` |
| `disable_dropper_rescan` | `0x10984A90` | `.rdata` |
| `pea_disable_dropper_rescan` | `0x10A11014` | `.rdata` |
| `amunpacker` | `0x109C7F34` | `.rdata` |
| `NID_DT_DISABLE_STATIC_UNPACKING` | `0x10980C30` | `.rdata` |
| `NID_DT_ENABLE_STATIC_UNPACKING` | `0x10980C50` | `.rdata` |
| `NID_DT_CONTINUE_AFTER_UNPACKING` | `0x10980A7C` | `.rdata` |
| `NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING` | `0x10980B5C` | `.rdata` |

---

## Architecture

### Unpacker Class Hierarchy

The binary contains RTTI for a rich unpacker class hierarchy, revealing both a generic emulation-based unpacker and many format-specific static unpackers:

```
PEUnpacker (base)                               @ 0x10C7F6D4
├── Generic emulation-based unpacker
│   ├── UnpackerContext                          @ 0x10C79618
│   └── UnpackerData                             @ 0x10C852A4
│
├── UPX family
│   ├── UpxwUnpacker                             @ 0x10C92FA0
│   ├── Upxw896Unpacker                          @ 0x10C92FBC
│   ├── Upxw60Unpacker                           @ 0x10C92FDC
│   ├── Upxw80Unpacker                           @ 0x10C92FFC
│   ├── Upxw896nUnpacker                         @ 0x10C9301C
│   └── Upx30LZMAUnpacker                        @ 0x10C930C4
│
├── PECompact family
│   ├── CPECompact2Unpacker                      @ 0x10C93560
│   ├── CPECompact2V250Unpacker                  @ 0x10C935E4
│   ├── CPECompact2V20x_21xUnpacker              @ 0x10C936E8
│   └── CPECompact2V230Unpacker                  @ 0x10C9373C
│
├── Petite family
│   ├── CPetiteUnpacker                          @ 0x10C93480
│   ├── CPetite12Unpacker                        @ 0x10C934FC
│   ├── CPetite13Unpacker                        @ 0x10C934DC
│   ├── CPetite14Unpacker                        @ 0x10C9351C
│   ├── CPetite21_22Unpacker                     @ 0x10C93460 (inferred)
│   └── CPetite23Unpacker                        @ 0x10C934BC
│
├── JDPack family
│   ├── CJDPackUnpacker                          @ 0x10C93F44
│   ├── CJDPack090Unpacker                       @ 0x10C93F90
│   ├── CJDPack20Unpacker                        @ 0x10C93FD8
│   └── CJDPack101bUnpacker / CJDPack101Unpacker @ 0x10C93FF8 / 0x10C9401C
│
├── Other format-specific unpackers
│   ├── FSGUnpacker                              @ 0x10C94040
│   ├── AspackUnpacker                           @ 0x10C942B4
│   ├── ShrinkerUnpacker                         @ 0x10C932F8
│   ├── PKLiteUnpacker                           @ 0x10C93440
│   ├── UPCUnpacker                              @ 0x10C9317C
│   ├── Exe32Unpacker                            @ 0x10C94118
│   ├── CCrypter1337Unpacker                     @ 0x10C94134
│   ├── CCrypter1337V2Unpacker                   @ 0x10C94180
│   ├── CArea51Unpacker / CArea51V11Unpacker     @ 0x10C943B8 / 0x10C943D8
│   ├── WExtractUnpacker                         @ 0x10C943FC
│   └── SfxCabUnpacker                           @ 0x10C941E4
│
└── Compression-specific
    ├── XZ stream decompressor (xz_unpack_helper)
    │   ├── XZReader                             @ 0x10C91DB0
    │   ├── XZWriterAdaptor                      @ 0x10C91E10
    │   └── XZReaderAdaptor                      @ 0x10C91E60
    └── DecompressXZStream                       (via unpackdata_t)
```

*(from RE of mpengine.dll -- RTTI strings containing "Unpacker" in .data section)*

---

## Unpacking Flow

### Main Unpack Pipeline

```
                    PE Emulation Complete (Stage 5)
                              │
                              ▼
                    ┌─────────────────────┐
                    │  HandleUnpacker()    │
                    │  @ RTTI 0x10C92DC8  │
                    │                      │
                    │  UnpackContextWrapper│
                    │  from pe_vars_t      │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                      │
                    ▼                      ▼
          ┌─────────────────┐   ┌──────────────────────┐
          │ Static Unpackers│   │ Emulation-based       │
          │ (format-specific│   │ Unpacking              │
          │  UPX, PECompact,│   │ (generic: observe     │
          │  Petite, etc.)  │   │  modified sections)    │
          └────────┬────────┘   └──────────┬───────────┘
                   │                        │
                   └──────────┬─────────────┘
                              │
                              ▼
                    ┌──────────────────────┐
                    │  Detect Modified     │
                    │  Content              │
                    │                       │
                    │  1. Scan PE sections  │
                    │     for writes        │
                    │  2. Collect VFS drops │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    │                      │
                    ▼                      ▼
          ┌─────────────────┐   ┌──────────────────┐
          │ Modified PE     │   │ VFS Dropped      │
          │ Sections         │   │ Files             │
          │                  │   │                   │
          │ - Decrypted code │   │ - Written by      │
          │ - Decompressed   │   │   CreateFileW     │
          │   payload        │   │ - Dropped payloads│
          │ - Self-modified  │   │ - Config files    │
          │   regions        │   │ - Child malware   │
          └────────┬────────┘   └────────┬─────────┘
                   │                      │
                   └──────────┬───────────┘
                              │
                              ▼
                    ┌──────────────────────┐
                    │  Engine.Scan.Unpacker│
                    │  @ 0x109C6068       │
                    │                      │
                    │  Recursive scan:     │
                    │  Each piece of       │
                    │  unpacked content    │
                    │  goes through full   │
                    │  pipeline (Stage 2+) │
                    └──────────────────────┘
```

### Detailed Control Flow

```
Pseudocode:
─────────────────────────────────────────────────────

fn handle_unpacked_content(pe_vars: &PeVars, emu_ctx: &EmuContext) -> ScanResult {
    let mut result = ScanResult::Clean;

    // Phase 1: Try static unpackers first (unless disabled)
    if !has_attribute("disable_static_unpacking")
       && !has_attribute("pea_disable_static_unpacking")
       && !has_nid(NID_DT_DISABLE_STATIC_UNPACKING) {

        result = try_static_unpackers(pe_vars);
        // Tries UPX, PECompact, Petite, ASPack, etc.
        // Each unpacker checks format signatures in the PE header
    }

    // Phase 2: Emulation-based unpacking
    if result == ScanResult::Clean || has_attribute("force_unpacking") {
        // Check each PE section for modifications during emulation
        for section in pe_vars.sections.iter() {
            if section.was_modified_during_emulation() {
                let unpacked_data = extract_modified_section(section);
                let child_result = recursive_scan(unpacked_data, depth + 1);
                result = merge_results(result, child_result);
            }
        }
    }

    // Phase 3: Scan VFS-dropped files
    if !has_attribute("disable_dropper_rescan")
       && !has_attribute("pea_disable_dropper_rescan") {
        for vfs_entry in emu_ctx.vfs.entries() {
            // "(VFS:%ls#%zd)" @ 0x10B87920
            let child_result = recursive_scan(vfs_entry.data, depth + 1);
            result = merge_results(result, child_result);
        }
    }

    // Phase 4: Continue after unpacking?
    if has_attribute("dt_continue_after_unpacking")
       || has_nid(NID_DT_CONTINUE_AFTER_UNPACKING) {
        // Continue to Stage 7 (containers) even after unpacking
    }

    if result != ScanResult::Clean
       && (has_attribute("dt_continue_after_unpacking_damaged")
           || has_nid(NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING)) {
        // Continue even if unpacked content appears damaged
    }

    result
}
```

---

## Static Unpackers

### UPX Family

UPX (Ultimate Packer for eXecutables) is the most common packer in the wild. The engine supports multiple UPX versions through specialized unpackers:

| Unpacker | RTTI Address | UPX Version |
|----------|-------------|-------------|
| `UpxwUnpacker` | `0x10C92FA0` | Generic UPXW |
| `Upxw896Unpacker` | `0x10C92FBC` | UPX 8.96 |
| `Upxw896nUnpacker` | `0x10C9301C` | UPX 8.96n variant |
| `Upxw60Unpacker` | `0x10C92FDC` | UPX 6.0 |
| `Upxw80Unpacker` | `0x10C92FFC` | UPX 8.0 |
| `Upx30LZMAUnpacker` | `0x10C930C4` | UPX 3.0 with LZMA |

The UPX unpackers include XOR decryptors for obfuscated UPX stubs:
```
.?AVXorDecryptor@?6??DeofuscateImage@Upxw60Unpacker@@...
    @ 0x10C93070
```

### PECompact Family

PECompact is another common commercial packer:

| Unpacker | RTTI Address | Version |
|----------|-------------|---------|
| `CPECompact2Unpacker` | `0x10C93560` | PECompact 2.x base |
| `CPECompact2V250Unpacker` | `0x10C935E4` | PECompact 2.50 |
| `CPECompact2V20x_21xUnpacker` | `0x10C936E8` | PECompact 2.0x-2.1x |
| `CPECompact2V230Unpacker` | `0x10C9373C` | PECompact 2.30 |

PECompact 2.50 includes multiple decrypter classes for different encryption algorithms:
- `CRC32Decrypter` -- CRC32-based decryption
- `CCryptDecrypter` -- Generic crypto decryption
- `CXorDecrypter` -- XOR decryption
- `CMessageBoxDecrypter` -- MessageBox-trick decryption
- `CRnd5Decrypter` -- Random polymorph decryption
- `CDECADA82Decrypter` -- DECADA82 algorithm
- `CCod1Decrypter` -- Cod1 algorithm
- `CVerifyDecrypter` -- CRC verification decryption
- `CSimpleCRC32Decrypter` -- Simple CRC32
- `CWincryptDecryptor` -- Windows CryptoAPI

*(from RE of mpengine.dll -- CPECompact2V250Unpacker nested RTTI classes)*

### Other Static Unpackers

| Unpacker | RTTI Address | Packer |
|----------|-------------|--------|
| `AspackUnpacker` | `0x10C942B4` | ASPack |
| `FSGUnpacker` | `0x10C94040` | FSG (Fast Small Good) |
| `ShrinkerUnpacker` | `0x10C932F8` | Shrinker |
| `PKLiteUnpacker` | `0x10C93440` | PKLite |
| `UPCUnpacker` | `0x10C9317C` | UPC |
| `Exe32Unpacker` | `0x10C94118` | Exe32Pack |
| `CCrypter1337Unpacker` | `0x10C94134` | Crypter1337 |
| `CCrypter1337V2Unpacker` | `0x10C94180` | Crypter1337 v2 |
| `CArea51Unpacker` | `0x10C943B8` | Area51 |
| `WExtractUnpacker` | `0x10C943FC` | WExtract (SFX) |
| `SfxCabUnpacker` | `0x10C941E4` | SFX CAB |
| `CJDPackUnpacker` | `0x10C93F44` | JDPack |

---

## Modified Section Detection

After emulation, the engine compares each PE section's current state against its initial (pre-emulation) state:

```
Section Analysis:
─────────────────────────────────────────────────

For each PE section:
    1. Compare current bytes against original image
    2. If significant modifications detected:
       a. Extract the modified region
       b. Attempt to reconstruct as valid PE or raw code
       c. Submit to recursive scan pipeline

Detection criteria:
    - Write operations to executable sections (.text)
    - Large-scale overwrites (typical of decryption loops)
    - New executable code in previously zero-filled regions
    - Section protection changes (via VirtualProtect)
```

The `VirtualProtectCallback` class at RTTI `0x10C7B7B0` monitors memory protection changes during emulation, flagging sections that transition to executable.

---

## Error Handling

### Unpacking Failures

```
"Failed to unpack %s"                    @ 0x10B6D70C
"failed decompress unpacker code"        @ 0x10B79514
"failed to copy EP instruction series"   @ 0x10B794EC
"failed to make jump instruction"        @ 0x10B795C8
"too many results to unpack"             @ 0x10B54704
```

### Damaged Content Handling

When unpacking produces damaged or incomplete content:

```
dt_continue_after_unpacking_damaged      @ 0x10984D38
pea_dt_continue_after_unpacking_damaged  @ 0x10A11B28
NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING  @ 0x10980B5C
```

These control flags determine whether the pipeline continues scanning the damaged output or discards it. The `_damaged` variant allows scanning content that fails PE structure validation, which can still contain recognizable malware signatures.

---

## XZ Stream Decompression

A specialized decompression path exists for XZ-compressed content:

```
RTTI classes:
  xz_unpack_helper  (contains nested classes)
  XZReader           @ 0x10C91DB0
  XZWriterAdaptor    @ 0x10C91E10
  XZReaderAdaptor    @ 0x10C91E60
  DecompressXZStream (via unpackdata_t @ 0x10C91E10)
  Canceler           @ 0x10C91AD0  (timeout/cancel support)
  VfoWrapper         @ 0x10C91D50  (virtual file object wrapper)
```

*(from RE of mpengine.dll -- xz_unpack_helper RTTI in .data section)*

---

## HandleUnpacker Entry Point

The main entry point for Stage 6 is the `HandleUnpacker` function, whose RTTI wrapper is visible:

```
.?AUUnpackContextWrapper@?DJ@??HandleUnpacker@@YA?AW4scanresult_t@@PAUpe_vars_t@@@Z@
    @ 0x10C92DC8

Decoded:
  HandleUnpacker(pe_vars_t*) -> scanresult_t
  Uses UnpackContextWrapper as a scoped RAII context
```

The function signature reveals:
- Input: `pe_vars_t*` -- the PE variable structure from emulation
- Output: `scanresult_t` -- an enum indicating clean/malware/error
- Uses `UnpackContextWrapper` for resource management

---

## AMUnpacker Integration

The `amunpacker` string at `0x109C7F34` references the Anti-Malware unpacker integration -- a subsystem that coordinates between the emulation engine and the scan pipeline:

```
"amunpacker" @ 0x109C7F34

ETW event:
  "Engine.Scan.Unpacker" @ 0x109C6068
```

The `Engine.Scan.Unpacker` ETW (Event Tracing for Windows) event is logged when unpacking begins, enabling diagnostic tracing of the unpacking pipeline.

---

## Recursive Scan Depth

Unpacked content re-enters the pipeline at Stage 2. The `scan_depth` counter in `ScanContext` prevents infinite recursion:

```
Recursive scan path:
  Stage 5 (Emulation) → Stage 6 (Unpack) → Stage 2 (FRIENDLY_FILE)
                                              ↓
                                           Stage 3 (Static)
                                              ↓
                                           Stage 4 (Attributes)
                                              ↓
                                           Stage 5 (Emulation again?)
                                              ↓
                                           (depth check prevents infinite loop)
```

The depth limit is controlled by DBVAR configuration. When `scan_depth` exceeds the limit, the recursive scan is abandoned and the pipeline continues with whatever results have been accumulated.

---

## Rescan Behavior

The `disable_dropper_rescan` attribute (`0x10984A90`) and its PE-specific variant `pea_disable_dropper_rescan` (`0x10A11014`) control whether VFS-dropped files trigger rescanning:

```
Rescan-related strings:
  "disable_dropper_rescan"               @ 0x10984A90
  "pea_disable_dropper_rescan"           @ 0x10A11014
  "%ls has rescanvmm set\n"             @ 0x10B76990 (UTF-16)
```

When `disable_dropper_rescan` is set, the engine skips the VFS file rescan phase. This optimization is used when the static analysis was already confident enough in the detection, or when the dropper behavior is a known pattern that does not require rescanning child files.

---

## Summary

| Metric | Value |
|--------|-------|
| Static unpacker classes | 25+ (from RTTI analysis) |
| UPX variant unpackers | 6 |
| PECompact variant unpackers | 4 |
| PECompact decrypter algorithms | 10 |
| Petite variant unpackers | 5 |
| Control attributes | 8 (force, disable, continue, damaged) |
| NID control tokens | 4 (enable/disable static, continue/damaged) |
| Error handling strings | 5 |
| ETW event | `Engine.Scan.Unpacker` |

---

## Cross-References

- **Previous stage**: [Stage 5 -- PE Emulation](05_pe_emulation.md) (produces the content this stage scans)
- **Recursive target**: [Stage 2 -- FRIENDLY_FILE](02_friendly_file.md) (unpacked content re-enters here)
- **Attribute control**: [Stage 4 -- AAGGREGATOR Collection](04_aaggregator_collection.md) (`pea_*` attributes control unpacking)
- **Next stage**: [Stage 7 -- Container Extraction](07_container_extraction.md)
- **Pipeline overview**: [Master Overview](00_overview.md)

---

*Generated from reverse engineering of mpengine.dll v1.1.24120.x*
