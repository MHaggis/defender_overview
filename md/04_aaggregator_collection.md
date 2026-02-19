# Stage 4: AAGGREGATOR Attribute Collection

> How mpengine.dll accumulates detection attributes across all scan stages for later boolean evaluation by the AAGGREGATOR engine.
> All data from reverse engineering mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 4 is not a discrete pipeline phase that runs at a single point in time. Instead, it describes the **continuous attribute accumulation** mechanism that operates throughout the entire scan pipeline. As each engine in Stages 3-10 fires, it deposits string-valued attributes into a shared `HashSet<String>` on the `ScanContext`. These attributes are the "vocabulary" that the AAGGREGATOR boolean expression evaluator (Stage 11) later consumes.

The distinction between "collection" (Stage 4) and "evaluation" (Stage 11) is critical: collection happens everywhere, evaluation happens once at the end.

### Key Strings from the Binary

| String | Address | Section |
|--------|---------|---------|
| `SIGNATURE_TYPE_AAGGREGATOR` | `0x10986B3C` | `.rdata` |
| `SIGNATURE_TYPE_AAGGREGATOREX` | `0x10986E28` | `.rdata` |
| `aggregate_mpattribute` | `0x1097EC60` | `.rdata` |
| `set_mpattribute` | `0x1097EC28` | `.rdata` |
| `set_mpattributeex` | `0x1097EC38` | `.rdata` |
| `clear_mpattribute` | `0x1097EC4C` | `.rdata` |
| `get_mpattribute` | `0x1097EBC8` | `.rdata` |
| `get_mpattributevalue` | `0x1097EBD8` | `.rdata` |
| `get_mpattributesubstring` | `0x1097EBF0` | `.rdata` |
| `enum_mpattributesubstring` | `0x1097EC0C` | `.rdata` |

---

## Purpose and Role

The attribute collection system serves several purposes:

1. **Cross-engine communication** -- Engines that run early (e.g., PEHSTR, KCRCE) can signal properties to engines that run later (Lua, AAGGREGATOR) without requiring direct coupling.

2. **Infrastructure markers** -- Threat names prefixed with `!` are deposited as attributes but are **never returned as standalone detections**. They exist purely to feed the AAGGREGATOR evaluation.

3. **PE analysis attributes** -- Over 300 `pea_*` attributes describe structural properties of PE files (e.g., `pea_packed`, `pea_isdll`, `pea_no_relocs`).

4. **Behavioral attributes** -- Post-emulation attributes from FOP trace, TUNNEL analysis, and THREAD matching are accumulated for behavioral detection rules.

5. **Named attributes** -- Engines can set arbitrary named attributes via the `set_mpattribute` / `set_mpattributeex` internal functions, referenced at `0x1097EC28` and `0x1097EC38`.

---

## Architecture

### Attribute Set Data Structure

The attribute set is conceptually a `HashSet<String>` stored on the per-file `ScanContext`. Each attribute is a unique string key; some attributes also carry associated values (key=value pairs) accessible through `get_mpattributevalue` at `0x1097EBD8`.

```
ScanContext
├── attributes: HashSet<String>
│   ├── "HSTR:Win32/Emotet.A!dha"
│   ├── "!InfraOnly:Win32/Suspicious.Packer"
│   ├── "pea_packed"
│   ├── "pea_epscn_writable"
│   ├── "pea_lastscn_falign"
│   ├── "FOP:Trojan:Win32/Generic.D"
│   ├── "TUNNEL:Trojan:Win32/Tunnel.A"
│   └── ... (hundreds more)
├── namedattributes: HashMap<String, String>
│   ├── "peattributes" → serialized PE analysis flags
│   ├── "elfattributes" → serialized ELF analysis flags
│   ├── "machoattributes" → serialized Mach-O analysis flags
│   └── "variableattributes" → runtime-computed values
└── sigattrevents: Vec<SigAttrEvent>
    ├── sigattr_head (first N entries)
    └── sigattr_tail (last N entries)
```

### Attribute Namespaces

Attributes are namespaced by convention. The following prefixes are observed in the binary:

| Prefix | Source | Example |
|--------|--------|---------|
| `HSTR:` | PEHSTR engine (Stage 3) | `HSTR:Win32/Emotet.A!dha` |
| `pea_*` | PE analysis (302 attributes) | `pea_packed`, `pea_isdll` |
| `FOP:` | First Opcode Profile (Stage 5) | `FOP:Trojan:Win32/Generic` |
| `TUNNEL:` | Tunnel signature match (Stage 5) | `TUNNEL:Trojan:Win32/Tunnel.A` |
| `THREAD:` | Thread signature match (Stage 5) | `THREAD:Win32/Dropper` |
| `!` prefix | Infrastructure marker | `!InfraOnly:Win32/Suspicious` |
| `BRUTE:` | BRUTE engine match (Stage 9) | `BRUTE:PDF:Feature:JavaScript` |
| (no prefix) | Lua `mp.setattribute()` | `has_overlay`, `suspicious_imports` |

*(from RE of mpengine.dll -- attribute naming patterns from string analysis)*

---

## Attribute Sources and Flow

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ATTRIBUTE PRODUCERS                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Stage 3: Static Engine Cascade                                          │
│  ├── PEHSTR engine    ──▶  "HSTR:Win32/xxx" attributes                  │
│  ├── KCRCE engine     ──▶  CRC-based attributes                         │
│  ├── NID engine       ──▶  Named identifier attributes                  │
│  ├── STATIC engine    ──▶  Static detection attributes                  │
│  └── BM_STATIC engine ──▶  Byte-match attributes                        │
│                                                                          │
│  Stage 5: PE Emulation                                                   │
│  ├── PE structure     ──▶  302 "pea_*" attributes                       │
│  ├── FOP trace        ──▶  "FOP:xxx" first-opcode-profile attrs          │
│  ├── TUNNEL analysis  ──▶  "TUNNEL:xxx" code-pattern attrs               │
│  ├── THREAD analysis  ──▶  "THREAD:xxx" thread-behavior attrs            │
│  └── Emulator signals ──▶  behavioral indicator attributes               │
│                                                                          │
│  Stage 9: BRUTE Matching                                                 │
│  └── BRUTE engine     ──▶  "BRUTE:xxx" polymorphic-match attrs           │
│                                                                          │
│  Stage 10: Lua Script Engine                                             │
│  └── mp.setattribute()──▶  Arbitrary named attributes                    │
│      mp.set_mpattribute()                                                │
│                                                                          │
│  Infrastructure Markers (any engine)                                     │
│  └── "!ThreatName"    ──▶  Collected as attribute, never a detection     │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                 │                                        │
│                                 ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │              ScanContext.attributes : HashSet<String>              │   │
│  │                                                                    │   │
│  │  Accumulated across ALL scan stages. Each attribute is inserted   │   │
│  │  exactly once (set semantics). The set is never cleared during    │   │
│  │  a single file scan -- only grows monotonically.                  │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│                    ATTRIBUTE CONSUMERS                                    │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Stage 11: AAGGREGATOR Evaluation                                │    │
│  │  Boolean expression: "HSTR:xxx & pea_packed & !CleanTag"         │    │
│  │  Sig types: AAGGREGATOR @ 0x10986B3C, AAGGREGATOREX @ 0x10986E28│    │
│  └──────────────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Stage 10: Lua Scripts                                            │    │
│  │  mp.get_mpattribute() / mp.get_mpattributevalue()                │    │
│  │  Scripts read attributes to make detection decisions              │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Stage 12: MAPS Cloud                                             │    │
│  │  Selected attributes are serialized into the cloud query          │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Internal Functions

### set_mpattribute (BM/Lua API)

The `set_mpattribute` function (string at `0x1097EC28`) is the primary mechanism for engines and Lua scripts to deposit attributes.

```
Function: set_mpattribute
String:   "set_mpattribute" @ 0x1097EC28

Pseudocode:
──────────────────────────────────────────────────────
void set_mpattribute(ScanContext* ctx, const char* attr_name) {
    if (ctx == NULL || attr_name == NULL) return;
    if (ctx->attributes.count >= MAX_ATTRIBUTES) {
        // Silently drop -- no error raised
        return;
    }
    ctx->attributes.insert(attr_name);
}
```

### set_mpattributeex (Extended Attribute API)

The extended version at `0x1097EC38` allows setting an attribute with an associated value:

```
Function: set_mpattributeex
String:   "set_mpattributeex" @ 0x1097EC38

Pseudocode:
──────────────────────────────────────────────────────
void set_mpattributeex(ScanContext* ctx, const char* name, const char* value) {
    set_mpattribute(ctx, name);  // Insert into HashSet
    ctx->namedattributes.insert(name, value);  // Store value mapping
}
```

### aggregate_mpattribute (Bulk Deposit)

The `aggregate_mpattribute` function at `0x1097EC60` is used for bulk attribute deposits, typically when an engine match deposits multiple related attributes at once.

```
Function: aggregate_mpattribute
String:   "aggregate_mpattribute" @ 0x1097EC60

Error strings (from Lua binding):
  "lua_mp_aggregateattribute failed to get max MP attributes total size DC"
      @ 0x10B4BD60
  "lua_mp_aggregateattribute failed to get max MP attributes count DC"
      @ 0x10B4BDA8
```

### Attribute Query Functions

| Function | Address | Purpose |
|----------|---------|---------|
| `get_mpattribute` | `0x1097EBC8` | Check if attribute exists in set |
| `get_mpattributevalue` | `0x1097EBD8` | Retrieve value for a named attribute |
| `get_mpattributesubstring` | `0x1097EBF0` | Substring match on attribute name |
| `enum_mpattributesubstring` | `0x1097EC0C` | Enumerate attributes matching pattern |
| `clear_mpattribute` | `0x1097EC4C` | Remove a specific attribute from set |

*(from RE of mpengine.dll -- string references in .rdata section)*

---

## Attribute Categories in Detail

### PE Analysis Attributes (pea_*)

302 `pea_*` attributes are set during PE structure analysis. These describe the static structure of the PE file before emulation.

Selected attributes with addresses:

| Attribute | Address | Meaning |
|-----------|---------|---------|
| `pea_packed` | `0x10A10B1C` | PE appears to be packed |
| `pea_isdll` | `0x10A10B4C` | File is a DLL |
| `pea_isexe` | `0x10A10BD4` | File is an EXE |
| `pea_isdriver` | `0x10A10C24` | File is a kernel driver |
| `pea_no_relocs` | `0x10A10A44` | No relocation table |
| `pea_no_imports` | `0x10A10C34` | No import table |
| `pea_hasexports` | `0x10A10BAC` | Has export table |
| `pea_isdamaged` | `0x10A10C64` | PE structure is malformed |
| `pea_epscn_writable` | `0x10A10A30` | Entry point section is writable |
| `pea_lastscn_writable` | `0x10A109EC` | Last section is writable |
| `pea_epscn_falign` | `0x10A10A1C` | EP section file-aligned |
| `pea_lastscn_falign` | `0x10A109D8` | Last section file-aligned |
| `pea_epscn_valign` | `0x10A10AA4` | EP section virtual-aligned |
| `pea_lastscn_valign` | `0x10A10A54` | Last section virtual-aligned |
| `pea_epscn_islast` | `0x10A10A68` | Entry point is in last section |
| `pea_epscn_eqsizes` | `0x10A10A7C` | EP section raw == virtual size |
| `pea_lastscn_eqsizes` | `0x10A10A90` | Last section raw == virtual size |
| `pea_epatscnstart` | `0x10A10AB8` | EP at start of section |
| `pea_epcallnext` | `0x10A10ACC` | EP instruction is `call $+5` |
| `pea_firstsectwritable` | `0x10A10B04` | First section is writable |
| `pea_secmissize` | `0x10A10B28` | Section size mismatch |
| `pea_secmisaligned` | `0x10A10B38` | Section misaligned |
| `pea_epinfirstsect` | `0x10A10B58` | EP in first section |
| `pea_hasappendeddata` | `0x10A10BBC` | Data appended after last section |
| `pea_epoutofimage` | `0x10A10BD4` | EP points outside image |
| `pea_entrybyte55` | `0x10A10BE0` | EP starts with `0x55` (push ebp) |
| `pea_entrybyte90` | `0x10A10BF0` | EP starts with `0x90` (nop) |
| `pea_entrybyte60` | `0x10A10C00` | EP starts with `0x60` (pushad) |
| `pea_hasboundimports` | `0x10A10C10` | Has bound import directory |
| `pea_headerchecksum0` | `0x10A10C50` | Header checksum is zero |
| `pea_hasstandardentry` | `0x10A10C74` | Standard compiler entry point |
| `pea_requires9x` | `0x10A10C8C` | Requires Win9x subsystem |
| `pea_usesuninitializedregs` | `0x10A10C9C` | Uses uninitialized registers |
| `pea_isreported` | `0x10A10CB8` | Already reported by earlier scan |
| `pea_isgeneric` | `0x10A10CC8` | Generic detection applied |

*(from RE of mpengine.dll -- 302 `pea_*` strings in .rdata)*

### Emulation Control Attributes

Several `pea_*` attributes are not just informational but control emulation behavior:

| Attribute | Address | Effect |
|-----------|---------|--------|
| `pea_force_unpacking` | `0x10A11570` | Force dynamic unpacking |
| `pea_disable_static_unpacking` | `0x10A110B8` | Skip static unpackers |
| `pea_disable_dropper_rescan` | `0x10A11014` | Skip dropper rescan |
| `pea_dt_continue_after_unpacking` | `0x10A11A88` | Continue after unpack |
| `pea_dt_continue_after_unpacking_damaged` | `0x10A11B28` | Continue even if damaged |
| `pea_reads_vdll_code` | `0x10A11AF4` | Read VDLL code sections |
| `pea_verbose_vdll_reads` | `0x10A11B74` | Verbose VDLL read logging |
| `pea_dynmem_reads_vdll_code` | `0x10A11B8C` | Dynamic memory reads VDLL |

*(from RE of mpengine.dll -- emulation control pea_ strings)*

### Signature Attribute Log (sigattr)

The `sigattr` log maintains a chronological record of signature-triggered attribute events:

| String | Address | Purpose |
|--------|---------|---------|
| `sigattr_head` | `0x1097D710` | First N events in the log |
| `sigattr_tail` | `0x1097D720` | Last N events in the log |
| `this_sigattrlog` | `0x1097D74C` | Current sigattr log reference |
| `get_sigattr_event_count` | `0x1097F37C` | Number of sigattr events |
| `sigattrevents` | `0x109E27B0` | Signature attribute events list |

The sigattr log provides ordered access to attribute deposit events:

```
sigattr_head                    sigattr_tail
┌──────────────────┐           ┌──────────────────┐
│ First N events   │           │ Last N events    │
│ (earliest attrs) │    ...    │ (latest attrs)   │
└──────────────────┘           └──────────────────┘

Access functions:
  get_postemu_sigattr_log_head       @ 0x10981A28
  get_postemu_sigattr_log_head_size  @ 0x10981A04
  get_postemu_sigattr_log_tail       @ 0x10981A6C
  get_postemu_sigattr_log_tail_size  @ 0x10981A48
```

Error strings confirm log access patterns:

```
"sigattrlog: head is empty"                      @ 0x10B4F7C8
"sigattrlog: tail is empty"                      @ 0x10B4F774
"Invalid index in sigattr log: %d"               @ 0x10B4F6F8
"Invalid index in sigattr head log: %d (logsize = %d)" @ 0x10B4F790
"Invalid index in sigattr tail log: %d (logsize = %d)" @ 0x10B4F73C
"Invalid index (0) in sigattr log"               @ 0x10B4F7E4
"sigattrlog not available"                        @ 0x10B4F808
"this_sigattrlog not available"                   @ 0x10B4F71C
"Invalid sigattr_head index"                      @ 0x10B5214C
```

*(from RE of mpengine.dll -- sigattr-related strings in .rdata)*

---

## Infrastructure Markers

### The ! Prefix Convention

When an engine match produces a threat name prefixed with `!`, the name is treated as an **infrastructure marker**:

1. The threat name string is deposited as an attribute in the `HashSet<String>`.
2. The threat is **not** added to `ScanContext.threat_list`.
3. It exists solely for consumption by AAGGREGATOR rules and Lua scripts.

This allows Defender to build compound detections: an infrastructure marker like `!InfraOnly:Win32/Suspicious.Packer` might be one condition in an AAGGREGATOR rule that combines it with other evidence.

### Example: Multi-Signal Detection

```
Step 1: Static engine deposits attribute
    → "HSTR:Win32/Emotet.A!dha"

Step 2: PE analysis deposits attributes
    → "pea_packed"
    → "pea_epscn_writable"
    → "pea_lastscn_writable"

Step 3: Emulation deposits behavioral attribute
    → "!InfraOnly:Trojan:Win32/DynUnpack"

Step 4: AAGGREGATOR evaluates rule from VDM:
    Expression: "HSTR:Win32/Emotet.A!dha & pea_packed & !InfraOnly:Trojan:Win32/DynUnpack"
    Result: ALL attributes present → detection fires as "Trojan:Win32/Emotet.RPX!MTB"
```

---

## Attribute Type Categories

### Per-Format Attribute Collections

The binary contains separate attribute namespaces for different file formats:

| Attribute Collection | String Address | UTF-16 Address |
|---------------------|---------------|----------------|
| `peattributes` | `0x1097DC7C` | `0x109E12C0` |
| `elfattributes` | `0x109E2378` | `0x109E1F64` |
| `machoattributes` | `0x109E25F4` | `0x109E1FCC` |
| `namedattributes` | `0x109E2690` | `0x109E1310` |
| `variableattributes` | `0x109EC714` | `0x109EC658` |
| `attributelist` | `0x109E03C4` | `0x109DE3BC` |

*(from RE of mpengine.dll -- format-specific attribute collection strings)*

### Log Files

When verbose logging is enabled, attributes are written to log files:

| Log File | Address | Purpose |
|----------|---------|---------|
| `attributes.log` | `0x109C5F88` (UTF-16) | Main attribute dump |
| `attributes-%d.log` | `0x109C5F64` (UTF-16) | Per-scan attribute dump |
| `lowfis.log` | `0x109C5F4C` (UTF-16) | Low-fidelity detection log |
| `lowfis-%d.log` | `0x109C5F30` (UTF-16) | Per-scan lowfi log |

---

## Lua Attribute API

Lua scripts (Stage 10) have full read/write access to the attribute set through the `mp.*` API:

### Write Operations

```lua
-- Set a simple boolean attribute
mp.set_mpattribute("my_custom_indicator")

-- Set attribute with value
mp.set_mpattributeex("file_entropy", "7.92")

-- Aggregate multiple attributes from a detection match
mp.aggregate_mpattribute(detection_result)
```

### Read Operations

```lua
-- Check if attribute exists
local has_it = mp.get_mpattribute("pea_packed")

-- Get attribute value
local entropy = mp.get_mpattributevalue("file_entropy")

-- Substring search in attribute names
local match = mp.get_mpattributesubstring("HSTR:Win32/")

-- Enumerate matching attributes
mp.enum_mpattributesubstring("pea_", function(attr)
    -- callback for each matching attribute
end)
```

### Error Handling

Lua attribute functions report errors through the debug log:

```
"mp.get_sigattr_event_count() not called on a sigattr signature"
    @ 0x10B4DC24

"this_sigattrlog[\"alias\"].%s failed with 0x%x!"
    @ 0x10B4F558

"this_sigattrlog[\"alias\"].%s only available in BM sigattr or invalid field name!"
    @ 0x10B4F588

"bm.DisableSignature() not called on a sigattr signature"
    @ 0x10B536EC
```

*(from RE of mpengine.dll -- Lua error strings in .rdata)*

---

## SetAttributeForRegion

A specialized attribute API exists for the SMS (System Management Service) feature:

```
Function: SetAttributeForRegion
String:   "SetAttributeForRegion" @ 0x10B4F310

Error strings:
  "SMSSetAttributeForRegion failed"                              @ 0x10B4E2DC
  "Empty attribute name in SetAttributeForRegion"                @ 0x10B4E2FC
  "SetAttributeForRegion is only available for the SMS feature"  @ 0x10B4E32C
  "Scanned process info not available in SetAttributeForRegion"  @ 0x10B4E368
  "SCAN_REPLY not available in SetAttributeForRegion"            @ 0x10B4E3A4

Server-side attribute errors:
  "ServerStreamSetAttributeInvalidContext"       @ 0x109D7AEC
  "ServerStreamSetAttributeInvalidContextIndex"  @ 0x109D7AC0
```

*(from RE of mpengine.dll -- SetAttributeForRegion error paths)*

---

## Named Attribute Suppression

Attributes can suppress lowfi detections, preventing cloud lookup:

```
"Supressed lowfi per named attribute" @ 0x10A53FE8
```

This mechanism allows a trusted-software attribute to suppress what would otherwise trigger a cloud reputation query. The `namedattributes` collection at `0x109E2690` stores the suppression configuration.

---

## MpInternal Attribute Serialization

For cloud queries and internal debugging, attributes can be serialized:

```
"MpInternal_sigattrevents=" @ 0x10B76A58
"sigattrevents="            @ 0x10A545FC
"namedattributes="          @ 0x10A54580
"peattributes="             @ (implicit from "set_peattribute" @ 0x10981988)
"machoattributes=%s"        @ 0x10A54448
"elfattributes="            @ 0x10A2EC9C
"machoattributes="          @ 0x10A2DA08
```

*(from RE of mpengine.dll -- serialization format strings)*

---

## Cross-References

- **Previous stage**: [Stage 3 -- Static Engine Cascade](03_static_engine_cascade.md) (primary attribute producer)
- **PE analysis attributes**: [Stage 5 -- PE Emulation](05_pe_emulation.md) (produces 302 `pea_*` attributes)
- **Lua attribute API**: [Stage 10 -- Lua Scripts](10_lua_scripts.md) (reads and writes attributes)
- **Attribute evaluation**: [Stage 11 -- AAGGREGATOR Evaluation](11_aaggregator_evaluation.md) (consumes the attribute set)
- **Cloud serialization**: [Stage 12 -- MAPS Cloud Lookup](12_maps_cloud_lookup.md) (serializes attributes for cloud query)
- **Pipeline overview**: [Master Overview](00_overview.md)

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| PE analysis attributes (`pea_*`) | 302 |
| Attribute API functions | 8 (set, setex, get, getvalue, getsubstring, enumsubstring, clear, aggregate) |
| Signature types using attributes | 2 (AAGGREGATOR, AAGGREGATOREX) |
| Format-specific collections | 5 (PE, ELF, Mach-O, named, variable) |
| Sigattr log error strings | 9 |

---

*Generated from reverse engineering of mpengine.dll v1.1.24120.x*
