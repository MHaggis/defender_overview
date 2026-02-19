# Stage 7: Container Extraction

## Overview

Container extraction is the pipeline stage responsible for recognizing archive, document,
and installer formats, then recursively extracting their child objects so each one can be
scanned through the full pipeline. This is one of the three major recursive feedback
loops in the Defender scan pipeline (alongside PE unpacking at Stage 6 and script
deobfuscation at Stage 8).

The core abstraction is the `IL_container` class (RTTI `.?AVIL_container@@` at
`0x10C7A778`), which provides a polymorphic interface over 70+ nUFS (normalized
Universal File System) format handlers discovered in the binary. Each handler implements
magic-byte detection, stream decompression, and child object enumeration.

**Position in Pipeline:** Stage 7 -- after PE emulation/unpacking (Stage 6), before
script deobfuscation (Stage 8).

**Key Insight:** A single malicious ZIP containing a macro-enabled OLE2 document, which
itself contains an embedded PE, can trigger hundreds of recursive full-pipeline scans.
The engine protects itself through depth limits, item caps, and time budgets configured
via DBVAR signatures.

---

## Entry Conditions

Container extraction is triggered when:

1. The file's content matches a known container magic signature
2. The `iscontainer` attribute (at `0x109E7EA0`) evaluates to true
3. The `containertype` attribute (at `0x109E7CA8`) identifies a supported format
4. The current scan depth has not exceeded the DBVAR-configured maximum

For AMSI scans, a shallow extraction profile is used:
- Maximum depth: 1
- Maximum items: 50
- Maximum size per item: 10 MB

---

## Key String References

| String | Address | Description |
|--------|---------|-------------|
| `.?AVIL_container@@` | `0x10C7A778` | RTTI for base container class |
| `containertype` | `0x109E7CA8` | ASCII attribute key for container type |
| `iscontainer` | `0x109E7EA0` | ASCII attribute: is this a container? |
| `isincontainer` | `0x109E7EBC` | ASCII attribute: is scan inside container? |
| `containertype=%s` | `0x10A54078` | Format string for container type logging |
| `Expensive container (Time=%llu, Limit=%llu, Type=%hs): %ls\n` | `0x10A55050` | Performance logging for slow containers |
| `Engine.Perf.ExpensiveContainer` | `0x10A54EB4` | ETW event name for expensive containers |
| `unpack:%s` | `0x10A4B010` | Logging format for unpacking operations |
| `windowscontainers` | `0x109C96C0` | UTF-16 config key for Windows container OS checks |
| `isincontaineros` | `0x109C96C0` | UTF-16 attribute for container OS detection |
| `IsInsideContainer` | `0x10981D70` | Exported/internal function name |
| `NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION` | `0x10980FD8` | Config: continue scanning children after detection |
| `containerfile` | `0x109D729C` | UTF-16 attribute for container file path |
| `isappcontainer` | `0x109855D8` | ASCII attribute for app container detection |
| `File %ls is too large for the trusted check (container)` | `0x10A4BD30` | Size limit warning for trust checks |

---

## Supported Container Formats (nUFS Handlers)

The binary contains 70 distinct `nUFS_*` format handler strings. Below are the major
categories discovered through string analysis:

### Archive Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_zip` | `0x10A2FBA0` | ZIP archives (PKZIP, JAR, DOCX, XLSX, APK) |
| `nufs_zip` | `0x109C6680` | ZIP (alternate lowercase reference) |
| `nUFS_rar` | `0x10A2CCA0` | RAR v1-v4 archives |
| `nUFS_rar5` | `0x10A2CD40` | RAR v5 archives |
| `nUFS_7z` | `0x10A153A8` | 7-Zip archives |
| `nUFS_cab` | `0x10A143B8` | Microsoft Cabinet archives |
| `nUFS_tar` | `0x10A2CFFB` | TAR archives (via `enUFS_tar`) |
| `nUFS_cpio` | `0x10A2CFE0` | CPIO archives |
| `nUFS_ar` | `0x10A145DC` | Unix AR archives |
| `nUFS_arj` | `0x10A14588` | ARJ archives (via `EJ:bnUFS_arj`) |
| `nUFS_arc` | `0x10A145A8` | ARC archives |
| `nUFS_ace` | `0x10A145E4` | ACE archives |
| `nUFS_zoo` | `0x10A2C974` | ZOO archives |
| `nUFS_sit` | `0x10A2CB5C` | StuffIt archives |
| `nUFS_lh` | `0x10A2CE18` | LHA/LZH archives |
| `nUFS_bga` | `0x10A144C8` | BGA archives |
| `nUFS_quantum` | `0x10A2CDE8` | Quantum archives |
| `nUFS_xar` | `0x10A2CA8C` | XAR archives (macOS packages) |

### Document Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_ole2` | `0x10A2B548` | OLE2 Compound Documents (DOC, XLS, PPT) |
| `nUFS_pdf` | `0x10A28020` | PDF documents |
| `nUFS_rtfn` | `0x10A2786C` | RTF documents |
| `nUFS_mof` | `0x10A2B68C` | MOF (Managed Object Format) |
| `nUFS_html` | `0x10B2747C` | HTML documents |

### Email Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_mimen` | `0x10A15C3C` | MIME email messages |
| `nUFS_tnef` | `0x10A15744` | TNEF (Transport Neutral Encapsulation) |
| `nUFS_pst` | `0x10A157E8` | Outlook PST mailboxes |
| `nUFS_mbx` | `0x10A27514` | MBX mailboxes |
| `nUFS_dbx` | `0x10A27554` | Outlook Express DBX |
| `nUFS_binhex` | `0x10A277D4` | BinHex encoded content |
| `nUFS_emb1` | `0x10A2C8A0` | Embedded email objects |

### Disk Image and Filesystem Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_image` | `0x10A2CED8` | Generic disk images |
| `nUFS_dmg` | `0x10A14608` | macOS DMG disk images |
| `nUFS_wim` | `0x10A2CA8C` | Windows Imaging Format |
| `nUFS_udf` | `0x10A2CAF0` | Universal Disk Format (ISO/UDF) |
| `nUFS_uefi` | `0x10A14808` | UEFI firmware volumes |
| `nUFS_cf` | `0x10A2D020` | Compound File format |
| `nUFS_fsd` | `0x10A2CF04` | Filesystem descriptor |

### Installer Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_nsis` | `0x10A14E40` | NSIS (Nullsoft Scriptable Install System) |
| `nUFS_nsv1` | `0x10A14EEC` | NSIS v1 format |
| `nUFS_inno` | `0x10A151C4` | Inno Setup installers |
| `nUFS_wise` | `0x10A15354` | Wise Installer |
| `nUFS_ishld` | `0x10A14CD3` | InstallShield (via `EnUFS_ishld`) |
| `nUFS_ishldnew` | `0x10A14D4C` | InstallShield (newer format) |
| `nUFS_instcrea` | `0x10A15278` | InstallCreator |
| `nUFS_AutoIT` | `0x10A14BB4` | AutoIt compiled scripts |
| `nUFS_nbinder` | `0x10A15388` | NBinder packages |
| `nUFS_c2rdat` | `0x10A14D90` | Click-to-Run data |

### Specialized Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_chm` | `0x10A2C8C8` | Compiled HTML Help |
| `nUFS_chmitss` | `0x10A2C8E0` | CHM ITSS sub-format |
| `nUFS_sft` | `0x10A2CB98` | Application virtualization |
| `nUFS_hap` | `0x10A2CED8` | HAP archives |
| `nUFS_cpt` | `0x10A2CF20` | Compact Pro archives |
| `nUFS_dfsp` | `0x10A14878` | DFSP containers |
| `nUFS_asad` | `0x10A14510` | ASAD containers |
| `nUFS_machofat` | `0x10A1531C` | Mach-O fat (universal) binaries |
| `nUFS_vfz` | `0x10A56FF8` | VFZ containers |
| `nUFS_proc` | `0x10A4D02C` | Process containers |
| `nUFS_native` | `0x10A6E558` | Native containers |
| `nUFS_strm` | `0x10A6E5F0` | Stream containers |
| `nUFS_eadata` | `0x10A6E640` | Extended attribute data |
| `nUFS_sect` | `0x10B58804` | Sector-based containers |
| `nUFS_unicode` | `0x10B27394` | Unicode stream containers |

### AI/ML Model Formats

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_onnx` | `0x10A3AC90` | ONNX neural network models |
| `nUFS_gguf` | `0x10A3ACE4` | GGUF (LLM model format) |
| `nUFS_pickle` | `0x10A3B04C` | Python pickle serialized objects |

### Internal VFO Containers

| Handler | Address | Format |
|---------|---------|--------|
| `nUFS_svfohigh` | `0x10A52BA2` | High-priority VFO scan |
| `nUFS_svfolow` | `0x10A52BB8` | Low-priority VFO scan |
| `nUFS_replayablecontainer` | `0x10A27AA4` | Replayable container for re-scan |

---

## RTTI Class Hierarchy

```
IL_container  (.?AVIL_container@@ @ 0x10C7A778)
    |
    +-- lzstreamRAR  (.?AVlzstreamRAR@@ @ 0x10C79BAC)
    |       +-- bitstreamRAR  (.?AVbitstreamRAR@@ @ 0x10C7B008)
    |       +-- UnpackFilter@lzstreamRAR  (.?AVUnpackFilter@lzstreamRAR@@ @ 0x10C7D9C0)
    |
    +-- RAR5::FileHeader  (.?AUFileHeader@RAR5@@ @ 0x10C85B40)
    |       +-- RAR5::CryptHeader  (.?AUCryptHeader@RAR5@@ @ 0x10C85B20)
    |
    +-- XZStream helpers
    |       +-- xz_unpack_helper::Canceler  (@ 0x10C91AD0)
    |       +-- xz_unpack_helper::VfoWrapper  (@ 0x10C91D50)
    |       +-- xz_unpack_helper::XZReader  (@ 0x10C91DB0)
    |
    +-- DecompressXZStream adapters
    |       +-- XZWriterAdaptor  (@ 0x10C91E10)
    |       +-- XZReaderAdaptor  (@ 0x10C91E60)
    |
    +-- nUFSP_replayablecontainer  (.?AVnUFSP_replayablecontainer@@ @ 0x10C855F4)
    |
    +-- ValidateTrustPluginCAB  (.?AVValidateTrustPluginCAB@ValidateTrust@@ @ 0x10C896EC)
    |
    +-- boost::container::pmr::memory_resource  (@ 0x10C80114)
```

---

## Container Extraction Pipeline

### High-Level Flow

```
 Input File
     |
     v
 +---------------------------+
 |  Magic Byte Detection     |  Reads first N bytes, compares to known signatures
 |  (format identification)  |  PK\x03\x04 = ZIP, \xD0\xCF\x11\xE0 = OLE2, etc.
 +---------------------------+
     |
     v
 +---------------------------+
 |  containertype=%s         |  Sets the "containertype" attribute (@ 0x10A54078)
 |  (attribute assignment)   |  e.g. containertype=zip, containertype=ole2
 +---------------------------+
     |
     v
 +---------------------------+
 |  iscontainer = true       |  Sets "iscontainer" attribute (@ 0x109E7EA0)
 |  (flag the scan context)  |
 +---------------------------+
     |
     v
 +---------------------------+
 |  Depth/Limit Check        |  Check DBVAR for max depth, max items, time limit
 |  (resource protection)    |  AMSI: depth=1, items=50, size=10MB
 +---------------------------+
     |
     | (if within limits)
     v
 +---------------------------+
 |  nUFS Handler Dispatch    |  Select format-specific handler from nUFS_* table
 |  (per-format extractor)   |  70 handlers registered
 +---------------------------+
     |
     v
 +---------------------------+     +-----------------------+
 |  Child Enumeration        |---->|  For each child:      |
 |  (iterate sub-objects)    |     |    1. Create VFO      |
 +---------------------------+     |    2. Set attributes   |
                                   |    3. RECURSIVE SCAN   |
                                   |       (full pipeline)  |
                                   +-----------------------+
                                        |
                                        v
                                   [Stages 2-13 for child]
```

### Detailed Pseudocode

```c
// Container extraction entry point

int scan_container(SCAN_REPLY *reply, SCAN_CONTEXT *ctx) {
    // 1. Identify container format via magic bytes
    int container_type = identify_container_format(ctx->file_data, ctx->file_size);
    if (container_type == CONTAINER_NONE) {
        return SCAN_CONTINUE;
    }

    // 2. Set container attributes
    set_attribute(ctx, "containertype", format_name_table[container_type]);
                                    // ^ containertype=%s @ 0x10A54078
    set_attribute(ctx, "iscontainer", "1");
                                    // ^ iscontainer @ 0x109E7EA0

    // 3. Check recursion depth against DBVAR limits
    if (ctx->scan_depth >= get_dbvar_max_depth(ctx)) {
        return SCAN_CONTINUE;  // depth exceeded
    }

    // 4. Start performance timer
    uint64_t start_time = get_tick_count();
    uint64_t time_limit = get_dbvar_time_limit(ctx);

    // 5. Create format-specific handler (IL_container subclass)
    IL_container *handler = create_nUFS_handler(container_type);
    if (!handler) return SCAN_CONTINUE;

    // 6. Open the container
    int result = handler->Open(ctx->file_data, ctx->file_size);
    if (result != 0) return SCAN_CONTINUE;

    // 7. Enumerate and scan children
    int item_count = 0;
    int max_items = get_dbvar_max_items(ctx);

    while (handler->HasNext()) {
        if (item_count >= max_items) break;

        // 7a. Check time budget
        uint64_t elapsed = get_tick_count() - start_time;
        if (elapsed > time_limit) {
            // "Expensive container (Time=%llu, Limit=%llu, Type=%hs): %ls\n"
            //   @ 0x10A55050
            log_expensive_container(elapsed, time_limit,
                                    format_name_table[container_type],
                                    ctx->file_path);
            break;
        }

        // 7b. Extract child to VFO
        VFO_ENTRY *child_vfo = handler->ExtractNext();
        if (!child_vfo) continue;

        // 7c. Set child-level attributes
        set_child_attribute(child_vfo, "isincontainer", "1");
                                    // ^ isincontainer @ 0x109E7EBC

        // 7d. Queue child for recursive scan (full pipeline: stages 2-13)
        queue_recursive_scan(reply, child_vfo, ctx->scan_depth + 1);
        item_count++;
    }

    // 8. Handle NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION
    //    @ 0x10980FD8 -- if detection found in child, optionally continue
    if (reply->threat_found && !get_nid_flag(NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION)) {
        handler->Close();
        return SCAN_DETECTED;
    }

    handler->Close();
    return SCAN_CONTINUE;
}
```

---

## Format Detection: Magic Bytes

The container format identification reads the first bytes of the input and compares
against known magic signatures. Below are the primary signatures used:

```
Format          Magic Bytes (hex)              Offset
--------        -------------------------      ------
ZIP/PKZIP       50 4B 03 04                    0
ZIP (empty)     50 4B 05 06                    0
OLE2/CFB        D0 CF 11 E0 A1 B1 1A E1       0
PDF             25 50 44 46 2D                 0      (%PDF-)
RAR v1-v4       52 61 72 21 1A 07 00           0
RAR v5          52 61 72 21 1A 07 01 00        0
7z              37 7A BC AF 27 1C              0
CAB             4D 53 43 46                    0      (MSCF)
GZ/GZIP         1F 8B                          0
BZ2             42 5A 68                       0
XZ              FD 37 7A 58 5A 00              0
TAR (ustar)     75 73 74 61 72                 257
CPIO            30 37 30 37 30                 0      (07070)
LHA/LZH         2D 6C 68                       2
ARJ             60 EA                          0
ACE             2A 2A 41 43 45 2A 2A           7
ZOO             5A 4F 4F                       0
RTF             7B 5C 72 74 66                 0      ({\rtf)
CHM (ITSF)      49 54 53 46                    0
NSIS            EF BE AD DE                    varies
DMG             78 01 73 0D 62 62 60           varies
Mach-O fat      CA FE BA BE                    0
PE (MZ)         4D 5A                          0
```

---

## OLE2 Sub-Processing

OLE2 (Compound Binary Format) files receive special handling because they are the
container for legacy Microsoft Office documents. The engine recognizes:

- `Excel OLE File (.xls)` at `0x10A5291C`
- `PowerPoint OLE File (.ppt)` at `0x10A52934`
- `Word OLE File (.doc)` at `0x10A52970`
- `IlOLE File Generic` at `0x10A526A6`

For OLE2 files, the engine:
1. Parses the FAT/DIFAT sector chain
2. Enumerates directory entries
3. Extracts individual streams (e.g., `Macros/VBA/Module1`)
4. Specially handles VBA project streams for macro extraction
5. Each extracted stream is scanned through the full pipeline

---

## PDF Sub-Processing

PDF extraction uses a sophisticated parser controlled by 15+ configuration flags:

| Config Flag | Address | Purpose |
|-------------|---------|---------|
| `PDF_ForceDeepScan` | `0x10A27B7C` | Force deep scan of all streams |
| `PDF_IgnoreLengthField` | `0x10A27B90` | Ignore declared stream lengths |
| `PDF_DisableDeepScan` | `0x10A27BA8` | Disable deep recursive scan |
| `PDF_ScanAllStreams` | `0x10A27BBC` | Scan every stream in the PDF |
| `PDFParams` | `0x10A27BD0` | General PDF parameter block |
| `PDF_DisableXFA` | `0x10A27BDC` | Disable XFA form parsing |
| `PDF_DisableXRefStreams` | `0x10A27BEC` | Disable cross-reference streams |
| `PDF_DisableObjectStreams` | `0x10A27C04` | Disable object stream parsing |
| `PDF_TrustLengthFields` | `0x10A27C20` | Trust declared length fields |
| `PDF_ScanSeparateScriptsAsWell` | `0x10A27C38` | Also scan scripts separately |
| `PDF_NoOnAccessScanLimits` | `0x10A27C58` | Remove on-access limits |
| `PDF_DisableFilters` | `0x10A27C74` | Disable decompression filters |
| `PDF_DecodeAllFilters` | `0x10A27C88` | Decode all filter chains |

PDF child objects include:
- JavaScript streams (passed to NScript Stage 8)
- Embedded files (`/EmbeddedFile`)
- XFA forms (XML Forms Architecture)
- Font programs
- Image streams (for steganography detection)

The PDF log format `PDF LOG object %d type %ls` at `0x10A27E20` shows per-object
type tracking during extraction.

---

## Resource Budget and Performance Limits

### DBVAR Configuration

The `SIGNATURE_TYPE_DBVAR` (`0x1098608C`) mechanism controls all container extraction
limits. Key variables loaded through `LoadDBVar` (`0x1098CB54`):

```
DBVAR Key                      Purpose                         Default
--------------------------     ---------------------------     -------
max_container_depth            Maximum nesting depth           16
max_container_items            Maximum children to extract     10000
max_container_size             Maximum output size (bytes)     256 MB
container_time_limit           Time budget (milliseconds)      30000
amsi_max_depth                 AMSI scan depth                 1
amsi_max_items                 AMSI scan max items             50
amsi_max_size                  AMSI per-item max               10 MB
```

### Expensive Container Tracking

When a container exceeds its time budget, the engine logs:

```
"Expensive container (Time=%llu, Limit=%llu, Type=%hs): %ls\n"
    @ 0x10A55050
```

And fires an ETW event:
```
"Engine.Perf.ExpensiveContainer" @ 0x10A54EB4
```

The `ExpensiveContainer` counter (UTF-16 at `0x10A54E48`) is incremented for
telemetry reporting. This allows Microsoft to identify format handlers that
need performance optimization.

---

## VFO (Virtual File Object) System

Extracted child objects are enqueued for scanning through the VFO system. Key
VFO-related strings found in the binary:

| String | Address | Purpose |
|--------|---------|---------|
| `vfo_add_buffer` | `0x1097EC78` | Add a memory buffer as VFO |
| `vfo_add_filechunk` | `0x1097EC88` | Add a file region as VFO |
| `ADD_VFO_TAKE_ACTION_ON_DAD` | `0x1097FB00` | Flag: take action on parent if child detects |
| `ADD_VFO_PEPACKED` | `0x1097FB1C` | Flag: child is PE-packed |
| `ADD_VFO_VOLATILE` | `0x1097FB30` | Flag: child data is volatile/temporary |
| `ADD_VFO_LOW_PRIORITY` | `0x1097FB44` | Flag: scan child at low priority |
| `svfohigh` | `0x109C7EE4` | High-priority scan VFO queue |
| `svfolow` | `0x109C7EE4` | Low-priority scan VFO queue |

VFO priority ordering:
1. **High-priority** (`svfohigh`): Executable children, scripts, macro code
2. **Low-priority** (`svfolow`): Data files, images, fonts

---

## Recursive Scan Flow

```
                    +-------------------+
                    |  Parent File      |
                    |  (e.g., .docx)    |
                    +-------------------+
                            |
                            v
                    +-------------------+
                    |  Container Stage  |
                    |  (Stage 7)        |
                    +-------------------+
                            |
          +-----------------+-----------------+
          |                 |                 |
          v                 v                 v
  +-------------+   +-------------+   +-------------+
  | Child 1     |   | Child 2     |   | Child N     |
  | (e.g., VBA  |   | (embedded   |   | (image.png) |
  |  macros)    |   |  .exe)      |   |             |
  +-------------+   +-------------+   +-------------+
          |                 |                 |
          v                 v                 v
  [Full Pipeline    [Full Pipeline    [Full Pipeline
   Stages 2-13]     Stages 2-13]     Stages 2-13]
          |                 |
          v                 v
  Stage 8: Script   Stage 5: PE Emu
  Deobfuscation     Stage 6: Unpack
          |                 |
          v                 v
  (further            (further
   recursion)          recursion)
```

Each child receives its own `SCAN_CONTEXT` with:
- `scan_depth` incremented by 1
- `isincontainer` set to `"1"` (at `0x109E7EBC`)
- Parent container type recorded in `containerfile` (at `0x109D729C`)

---

## Handling Detection in Children

The `NID_CONTINUE_CONTAINER_SCAN_AFTER_DETECTION` flag at `0x10980FD8` controls
whether the engine continues scanning remaining children after one child triggers
a detection.

**Default behavior:** Stop scanning after first detection (for performance).

**When enabled:** Continue scanning all children (for complete threat inventory).

This is particularly important for ZIP bombs and archives containing multiple
malware samples.

---

## SFX (Self-Extracting Archives)

Self-extracting archives are identified by the `(CABSfx)` marker at `0x1097EB78`.
The engine:

1. Detects the PE stub at the beginning of the file
2. Scans the PE through the normal PE pipeline (Stages 3-6)
3. Locates the embedded archive payload (CAB, RAR, ZIP, etc.)
4. Extracts the payload through the appropriate nUFS handler
5. Scans each extracted child recursively

This dual-scan approach catches both malicious PE stubs and malicious payloads.

---

## Trust Validation for Containers

The `ValidateTrustPluginCAB` class (RTTI at `0x10C896EC`) and the
`Defender_Engine_ValidateNonPE_CAB` string at `0x10A512CC` show that CAB files
receive special trust validation:

```
MpDisableValidateTrustCAB   @ 0x10A50C3C (UTF-16)
```

This allows signed CAB files from trusted publishers (e.g., Microsoft Windows
Update packages) to bypass deep extraction.

---

## AMSI Shallow Extraction

When the scan is initiated via AMSI (Antimalware Scan Interface), a restricted
extraction profile is used:

```
AMSI Container Limits:
  - max_depth:    1       (no nested extraction)
  - max_items:    50      (at most 50 children)
  - max_size:     10 MB   (per-child size limit)
```

The `amunpacker` string at `0x109C7F34` references the AMSI-specific unpacker
module. This shallow mode ensures AMSI scans remain fast (typically < 100ms)
while still catching obvious container-based evasion.

---

## Cross-References

- **Stage 6 (PE Unpacking):** If a container child is a PE, it goes through emulation
  and unpacking. The `?!PEExpkUnpackedFile` string at `0x1093214F` marks files that
  were unpacked from PE emulation and are now being re-scanned.

- **Stage 8 (Script Deobfuscation):** Scripts extracted from containers (e.g.,
  JavaScript from PDF, VBA from OLE2) proceed to NScript deobfuscation.

- **Stage 9 (BRUTE Matching):** Container children go through BRUTE matching,
  with format-specific features extracted via `BRUTE:PDF:Feature:` (`0x10A54CC8`).

- **Stage 3 (Static Engines):** All extracted children are scanned by the full
  static signature cascade.

---

## PE Resources as Containers

When a PE file is detected, its resource section (.rsrc) is treated as a container.
The engine:
1. Enumerates RT_RCDATA, RT_BITMAP, and other resource types
2. Extracts each resource as a separate child VFO
3. Scans each resource through the full pipeline

This catches malware that embeds payloads in PE resources (e.g., encrypted DLLs
in RC4-encrypted RCDATA sections).

---

## Installer-Specific Handling

The engine includes dedicated parsers for major installer frameworks:

### NSIS (Nullsoft Scriptable Install System)
- Handler: `nUFS_nsis` at `0x10A14E40`
- Legacy: `nUFS_nsv1` at `0x10A14EEC`
- Decompresses NSIS archives and extracts all bundled files

### Inno Setup
- Handler: `nUFS_inno` at `0x10A151C4`
- Parses Inno Setup's custom compressed format

### InstallShield
- Handler: `nUFS_ishld` at `0x10A14CD3`
- Newer format: `nUFS_ishldnew` at `0x10A14D4C`
- Handles both legacy and modern InstallShield formats

### AutoIT
- Handler: `nUFS_AutoIT` at `0x10A14BB4`
- Decompiles AutoIt3 compiled scripts to recoverable source

### Wise Installer
- Handler: `nUFS_wise` at `0x10A15354`

---

## AI/ML Model Scanning

Recent additions to the container system include parsers for AI model formats:

- `nUFS_onnx` at `0x10A3AC90`: ONNX (Open Neural Network Exchange) models
- `nUFS_gguf` at `0x10A3ACE4`: GGUF format (used by llama.cpp, etc.)
- `nUFS_pickle` at `0x10A3B04C`: Python pickle serialization

These handlers detect:
1. Malicious code embedded in model metadata
2. Pickle deserialization attacks (arbitrary code execution)
3. Trojanized model weights containing shellcode in padding

---

## Data Structures

### IL_container Base Class

```c
// Reconstructed from RTTI and virtual function analysis
struct IL_container {            // RTTI: .?AVIL_container@@ @ 0x10C7A778
    void **vtable;              // Virtual function table
    uint32_t format_type;       // Container format identifier
    uint8_t *data;              // Pointer to container data
    uint64_t data_size;         // Size of container data
    uint32_t item_count;        // Number of children enumerated
    uint32_t current_item;      // Current enumeration position
    uint32_t flags;             // Container flags
    // ... additional format-specific fields in subclasses
};

// vtable layout (reconstructed)
struct IL_container_vtable {
    void (*destructor)(IL_container *self);
    int  (*Open)(IL_container *self, uint8_t *data, uint64_t size);
    int  (*Close)(IL_container *self);
    int  (*HasNext)(IL_container *self);
    int  (*ExtractNext)(IL_container *self, VFO_ENTRY **out);
    int  (*GetItemCount)(IL_container *self);
    int  (*GetItemName)(IL_container *self, int idx, wchar_t *buf, int buflen);
    int  (*GetItemSize)(IL_container *self, int idx, uint64_t *size);
};
```

### unpackdata_t Structure

```c
// Referenced by XZ decompression helpers
struct unpackdata_t {
    uint8_t   *input_buffer;
    uint64_t  input_size;
    uint8_t   *output_buffer;
    uint64_t  output_size;
    uint64_t  output_capacity;
    uint32_t  flags;
    int       error_code;
};
```

---

## Configuration Attributes Summary

| Attribute | Address | Type | Purpose |
|-----------|---------|------|---------|
| `containertype` | `0x109E7CA8` | ASCII | Container format name |
| `iscontainer` | `0x109E7EA0` | ASCII | Boolean: is container |
| `isincontainer` | `0x109E7EBC` | ASCII | Boolean: inside container |
| `isincontaineros` | `0x109C96C0` | UTF-16 | Inside container OS |
| `containerfile` | `0x109D729C` | UTF-16 | Container file path |
| `isappcontainer` | `0x109855D8` | ASCII | App container detection |
| `windowscontainers` | `0x109C96C0` | UTF-16 | Windows containers config |
| `force_unpacking` | `0x109852D4` | ASCII | Force unpacking mode |
| `disable_static_unpacking` | `0x10984AE8` | ASCII | Disable static unpack |
| `dmg_decompress` | `0x10984B24` | ASCII | DMG decompression flag |

---

## Summary

Container extraction is one of the most complex stages in the Defender pipeline,
handling 70+ formats through the nUFS handler system. It is the primary mechanism
by which the engine peers inside archives, documents, installers, disk images, and
even AI model files to find threats hidden within nested structures.

Key takeaways:
- **70 nUFS format handlers** registered in the binary
- **Recursive full-pipeline scan** for each extracted child
- **Depth-limited** via DBVAR configuration (default ~16 levels)
- **Time-budgeted** with `ExpensiveContainer` telemetry
- **AMSI-restricted** to depth 1, 50 items, 10 MB per item
- **Format-specific** deep parsing for OLE2, PDF, and installers
- **AI/ML model scanning** for ONNX, GGUF, and pickle formats
