# Stage 10 — Lua Script Execution Engine

> Reverse engineering documentation for the Lua scripting subsystem inside `mpengine.dll`.
> All addresses, strings, and structures from RE of mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 10 is the Lua scripting engine — arguably the most powerful and flexible stage in the entire scan pipeline. After static engines, attribute collection, PE emulation, unpacking, container extraction, script deobfuscation, and BRUTE force matching have all run, the Lua stage executes up to **59,415 embedded Lua scripts** against the current scan context. Each script has full programmatic access to the file being scanned and can read bytes, check PE sections, inspect attributes set by prior stages, compute hashes, verify digital signatures, and ultimately fire detections or set new attributes for Stage 11 (AAGGREGATOR evaluation).

The Lua subsystem is built on an embedded **Lua 5.1** runtime compiled directly into mpengine.dll, extended with approximately **106 custom `mp.*` API functions** and **14 `MpCommon.*` library functions** that bridge Lua scripts into the engine's internal capabilities.

### Why Lua?

Lua scripts provide detection logic that is too complex for static byte-pattern signatures. They can implement multi-step decision trees, cross-reference multiple attributes, parse file structures programmatically, and apply heuristic scoring — all while being deliverable via VDM signature updates rather than requiring engine binary updates.

---

## Entry Conditions

Stage 10 executes after the BRUTE force engine (Stage 9) has completed. The Lua engine runs when:

1. **LUASTANDALONE signatures exist** in the loaded VDM database
2. **Trigger conditions are met** — scripts are associated with signature triggers (HSTR matches, attribute presence, file type, etc.)
3. **The scan context is not already terminated** (e.g., by a high-confidence detection in an earlier stage)

```
                    BRUTE Complete (Stage 9)
                            |
                            v
                +-----------------------+
                | Load LUASTANDALONE    |
                | scripts from VDM     |
                +-----------------------+
                            |
                            v
                +-----------------------+
                | For each triggered    |
                | Lua script:           |
                |   1. Create Lua state |
                |   2. Register mp.* API|
                |   3. Execute script   |
                |   4. Collect results  |
                +-----------------------+
                            |
                            v
                +-----------------------+
                | Attributes & threats  |
                | deposited into        |
                | ScanContext           |
                +-----------------------+
                            |
                            v
                    Stage 11 (AAGGREGATOR)
```

---

## Key Strings from mpengine.dll

All strings extracted from mpengine.dll:

### Core Engine Strings

| String | Address | Section | Description |
|--------|---------|---------|-------------|
| `Lua 5.1` | `0x1098C124` | .rdata | Lua runtime version identifier |
| `LuaStandalone` | `0x109C806C` | .rdata | VDM signature type name |
| `LuaScripts` | `0x109C5744` | .rdata | Script category identifier (UTF-16) |
| `Engine.Scan.LuaExecute` | `0x10A33930` | .rdata | ETW event trace for Lua execution |
| `ResorderLuaExecute` | `0x10A3391C` | .rdata | Resource ordering for Lua execute |
| `CLuaScriptAction` | `0x10A33968` | .rdata | Lua script action class name (UTF-16) |
| `BMLua` | `0x10A35A10` | .rdata | Behavior Monitoring Lua integration (UTF-16) |
| `Engine.Det.BMLuaSigattr` | `0x10A49468` | .rdata | BM Lua signature attribute detection event |
| `LuaCallSigattrBM` | `0x10A494B0` | .rdata | BM Lua sig attribute call marker |
| `!#AsimovBMLuaCall_` | `0x10A49480` | .rdata | Asimov BM Lua call prefix |
| `MpCommonLua` | `0x10B6E2CC` | .rdata | Common Lua library namespace (UTF-16) |
| `Engine.Lua.ScriptError` | `0x10B4B8C8` | .rdata | ETW event for script errors |
| `Engine.Lua.DynamicSigFailure` | `0x10B4BC90` | .rdata | Dynamic signature failure event |
| `Engine.Lua.DynamicSigIncludeFailure` | `0x10B4B9C8` | .rdata | Dynamic sig include failure event |
| `Engine.Det.LuaFolderLatent` | `0x10B6B598` | .rdata | Folder latent detection via Lua |
| `LuaTrigger` | `0x10A0FEC4` | .rdata | Lua trigger mechanism (UTF-16) |


### LuaRunner Infrastructure Strings

| String | Address | Description |
|--------|---------|-------------|
| `LuaRunnerPanicsRegistryName` | `0x10B6B414` | Registry key for panic handler |
| `LuaRunnerScriptNameRegistryName` | `0x10B6B430` | Registry key for current script name |
| `LuaRunnerInstructionsCountRegistryName` | `0x10B6B478` | Registry key for instruction counter |
| `SetLuaInstrLimit` | `0x10B6B4D0` | Instruction limit setter function name |
| `SetLuaInstrLimit exceeded the limit.` | `0x10B6B3EC` | Error when instruction limit hit |


### Resource Limit Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `MpLuaMaxAttributesCount` | `0x10B4B704` | UTF-16 | Max number of attributes a script can set |
| `MpLuaMaxAttributesTotalSize` | `0x10B4B6CC` | UTF-16 | Max total bytes across all attributes |
| `MpLuaMaxFileReadTotalSize` | `0x10B4B734` | UTF-16 | Max total bytes readable from files |
| `MpLuaMaxBufferSize` | `0x10B4B768` | UTF-16 | Max single buffer allocation |
| `MpLuaMaxVfoTotalSize` | `0x10B4B790` | UTF-16 | Max VFO (Virtual File Object) total size |
| `MpLuaMaxVfoNameLen` | `0x10B4B7BC` | UTF-16 | Max VFO name string length |
| `MpLuaMaxVfoCount` | `0x10B4B7E4` | UTF-16 | Max number of VFOs per script |
| `MpLuaMaxTableElements` | `0x10B4B898` | UTF-16 | Max Lua table elements |
| `MpLuaJsonMaxNestingDepth` | `0x10B6B230` | UTF-16 | Max JSON parsing nesting depth |
| `MpLuaJsonMaxDataSize` | `0x10B6B264` | UTF-16 | Max JSON data size |
| `MpLuaJsonMaxElementsPerLevel` | `0x10B6B290` | UTF-16 | Max JSON elements per nesting level |


### Performance Threshold Strings

| String | Address | Type |
|--------|---------|------|
| `MpExpensiveSignatureThresholdLua` | `0x10B4B688` | UTF-16 |
| `MpExpensiveSignatureThresholdIoBytesLua` | `0x10B4B5E0` | UTF-16 |
| `MpExpensiveSignatureThresholdTotalTimeLua` | `0x10B4B630` | UTF-16 |


### Error and Diagnostic Strings

| String | Address |
|--------|---------|
| `mp.readfile(): MpLuaMaxFileReadTotalSize(%lld) reached` | `0x10B4C050` |
| `mp.readfile(): MpLuaMaxBufferSize(%lld) reached` | `0x10B4C088` |
| `LoadOpaqueLuaScript failed` | `0x10B4B910` |
| `Failed to grow Lua stack` | `0x10B4BFAC` |
| `Failed to load MpCommon lib` | `0x10B4BA90` |
| `Lua function expected` | `0x10B547D8` |
| `LuaReadProcMem(addr=0x%llx, cb=%u) failed` | `0x10B4E110` |
| `HIPS Lua function type %d should not return a path` | `0x10A4A144` |
| `ERROR: BM Lua calling a SCAN_REPLY dependent API` | `0x10B4BCBB` |


---

## Lua 5.1 Runtime

mpengine.dll embeds a complete Lua 5.1 interpreter. The string `"Lua 5.1"` at address `0x1098C124` confirms the version. The runtime is compiled directly into the binary — not linked as a separate DLL.

### Why Lua 5.1?

Lua 5.1 is:
- Extremely lightweight (~200KB of C code)
- Fast to initialize (microseconds per state)
- Easy to sandbox (can remove dangerous functions)
- Supports coroutines for complex control flow
- Well-suited for embedding in C/C++ applications

### Instruction Limiting

The engine imposes hard instruction count limits on Lua scripts to prevent runaway execution. The `SetLuaInstrLimit` mechanism (string at `0x10B6B4D0`) hooks into Lua's debug hook system to count instructions and abort execution when limits are exceeded.

```
LuaRunner Architecture:
+---------------------------------------------------------------+
|  LuaRunner (per-script execution context)                     |
|                                                               |
|  Registry Keys:                                               |
|    LuaRunnerPanicsRegistryName     @ 0x10B6B414               |
|    LuaRunnerScriptNameRegistryName @ 0x10B6B430               |
|    LuaRunnerInstructionsCountRegistryName @ 0x10B6B478        |
|                                                               |
|  +------------------+  +------------------+  +--------------+ |
|  | Lua 5.1 State    |  | mp.* API Table   |  | MpCommon Lib | |
|  | (lua_State*)     |  | (106 functions)  |  | (14 funcs)   | |
|  +------------------+  +------------------+  +--------------+ |
|                                                               |
|  Limits:                                                      |
|    Instruction count  (SetLuaInstrLimit)                      |
|    Memory allocation  (custom allocator)                      |
|    File I/O budget    (MpLuaMaxFileReadTotalSize)             |
|    Attribute budget   (MpLuaMaxAttributesCount)               |
+---------------------------------------------------------------+
```

---

## SIGNATURE_TYPE_LUASTANDALONE

The VDM database stores Lua scripts under `SIGNATURE_TYPE_LUASTANDALONE` (string at `0x10987058`). Each LUASTANDALONE entry in the VDM contains:

```
LUASTANDALONE VDM Entry Structure:
+--------------------------------------------+
| Header                                     |
|   SigType:  0x5E (LUASTANDALONE)           |
|   SigId:    unique identifier              |
|   SigSeq:   sequence number                |
|   Trigger:  HSTR match / attribute / type  |
+--------------------------------------------+
| Body                                       |
|   Lua bytecode (compiled Lua 5.1)          |
|   or Lua source (plaintext .lua)           |
+--------------------------------------------+
```

### Script Count

The VDM database contains approximately **59,415** LUASTANDALONE entries. These scripts cover:

- File classification and heuristic detection
- PE structure analysis (section entropy, import table checking)
- Document format inspection (macro detection, OLE analysis)
- Script content analysis (obfuscation scoring)
- Behavioral pattern matching (combined attribute evaluation)
- Certificate and digital signature validation
- Fileless attack detection (in-memory patterns)

---

## CLuaStandaloneLibrary Templates

The binary contains multiple template instantiations of `CLuaStandaloneLibrary`, each providing a different set of native functions to Lua scripts. Extracted from the .data section RTTI type descriptors:

| Class | Address | Purpose |
|-------|---------|---------|
| `CLuaStandaloneLibrary<LsaMpCommonLib>` | `0x10C781D8` | MpCommon API access |
| `CLuaStandaloneLibrary<LsaVersioning>` | `0x10C78294` | Version information access |
| `CLuaStandaloneLibrary<LsaSysIoLib>` | `0x10C78490` | System I/O operations |
| `CLuaStandaloneLibrary<LsaCrypto>` | `0x10C784E0` | Cryptographic operations |
| `CLuaStandaloneLibrary<LuaHipsLib>` | `0x10C887A0` | HIPS (Host Intrusion Prevention) |
| `CLuaStandaloneLibrary<LsaMpDetectionLib>` | `0x10C92478` | Detection management |
| `CLuaStandaloneLibrary<CLsaFfrLib>` | `0x10C926AC` | File/folder remediation |
| `CLuaStandaloneLibrary<CLsaRemediationLib>` | `0x10C926FC` | Remediation actions |
| `CLuaStandaloneLibrary<LsaImageConfig>` | `0x10C9275C` | Image configuration |
| `ILuaStandaloneLibrary` (interface) | `0x10C78254` | Base interface for all libs |


---

## The mp.* Lua API

The `mp` namespace provides approximately **106 functions** that Lua scripts can call to interact with the scan engine. These are registered into the Lua state when the LuaRunner initializes.

### File I/O Functions

```lua
-- Read raw bytes from the scanned file
local data = mp.readfile(offset, size)
-- Error strings confirm these APIs:
--   "mp.readfile(): MpLuaMaxFileReadTotalSize(%lld) reached" @ 0x10B4C050
--   "mp.readfile(): MpLuaMaxBufferSize(%lld) reached"        @ 0x10B4C088

-- Read process memory (for behavioral/HIPS scripts)
local mem = mp.readprocmem(address, size)
-- Error: "LuaReadProcMem(addr=0x%llx, cb=%u) failed" @ 0x10B4E110
```

### Attribute Management

```lua
-- Set an attribute on the scan context (feeds into AAGGREGATOR)
mp.setattribute(name, value)
-- Logged: "Lua SetAttribute" @ 0x10B4BE74

-- Get attributes set by prior stages
local val = mp.getattribute(name)
```

### Digital Signature Verification

```lua
-- Check if a file is digitally signed
local signed = mp.issignedfile(path, check_trust, check_container)
-- Log: "Lua IsSignedFile(%ls, CheckTrust: %ls, CheckContainer: %ls) from 0x%016llx" @ 0x10B4CEA0

-- Check if a file is known-friendly (trusted publisher)
local friendly = mp.isknownfriendly(path, use_cache, slow_checks)
-- Log: "Lua IsKnownFriendly(%ls, UseCache: %ls, fSlowChecks: %ls) = %ls from 0x%016llx" @ 0x10B4D9A8
```

### Categorized API Summary

Based on string analysis and RTTI type information, the ~106 mp.* functions fall into these categories:

| Category | Approx Count | Example Functions |
|----------|-------------|-------------------|
| File I/O | ~12 | `mp.readfile`, `mp.getfilesize`, `mp.getfilename` |
| PE Analysis | ~15 | `mp.getpesection`, `mp.getpeheader`, `mp.getimports` |
| Attributes | ~8 | `mp.setattribute`, `mp.getattribute`, `mp.hasattribute` |
| Hashing | ~6 | `mp.gethash`, `mp.getsha256`, `mp.getmd5` |
| Bitwise Ops | ~6 | `mp.bitor`, `mp.bitand`, `mp.bitxor`, `mp.bitnot` |
| Signatures | ~8 | `mp.issignedfile`, `mp.isknownfriendly`, `mp.checkcert` |
| String Ops | ~10 | `mp.find`, `mp.match`, `mp.lower`, `mp.upper` |
| Detection | ~8 | `mp.fire`, `mp.setlowfi`, `mp.adddetection` |
| VFO (Virtual File Objects) | ~8 | `mp.createvfo`, `mp.writevfo`, `mp.closevfo` |
| Scan Control | ~6 | `mp.rescan`, `mp.getcontext`, `mp.getscanflags` |
| Process/Behavior | ~10 | `mp.readprocmem`, `mp.getprocessinfo`, `mp.getcommandline` |
| JSON Parsing | ~5 | `mp.jsonparse`, `mp.jsonget`, `mp.jsonarray` |
| Misc Utility | ~4 | `mp.sleep`, `mp.time`, `mp.log` |

---

## The MpCommon.* Library

The `MpCommonLua` library (string at `0x10B6E2CC`) provides approximately **14 higher-level functions**:

| Function | Evidence (string address) | Purpose |
|----------|--------------------------|---------|
| `MpCommon.BinaryRegExpSearch` | `0x10B6DCC4` → error string | Binary regex pattern matching |
| `MpCommon.ReportFilelessResource` | `0x10B6DD3C`-`0x10B6E268` | Report fileless attack resources |
| `MpCommon.AddBlockingFirewallRule` | `0x10B6E2E8`-`0x10B6E608` | Add firewall rules (remediation) |
| `MpCommon.GetIisInstallPaths` | `0x10B6E4AC` | Enumerate IIS installation paths |

Error strings from `MpCommon.ReportFilelessResource` at multiple addresses:
- `"MpCommon.ReportFilelessResource() GetResourceBuffer() failed"` @ `0x10B6DD3C`
- `"MpCommon.ReportFilelessResource() CreateTrackingId() failed"` @ `0x10B6DD7C`
- `"MpCommon.ReportFilelessResource() no global callback"` @ `0x10B6DDD8`
- `"MpCommon.ReportFilelessResource() Invalid ThreatId for NID_VNAME 0x%x"` @ `0x10B6E150`
- `"MpCommon.ReportFilelessResource() invalid NID_VNAME 0x%x"` @ `0x10B6E198`
- `"MpCommon.ReportFilelessResource() Invalid SigSeq for NID_VNAME 0x%x"` @ `0x10B6E1D8`
- `"MpCommon.ReportFilelessResource() Invalid SigId for NID_VNAME 0x%x"` @ `0x10B6E220`
- `"MpCommon.ReportFilelessResource() only bitsjob and uefi based schemas supported"` @ `0x10B6E268`

Error strings from `MpCommon.AddBlockingFirewallRule`:
- `"MpCommon.AddBlockingFirewallRule() error: at least one of the 6th and 7th parameter must be true"` @ `0x10B6E2E8`
- `"MpCommon.AddBlockingFirewallRule() error: 3rd parameter must be boolean"` @ `0x10B6E4E8`
- `"MpCommon.AddBlockingFirewallRule() error: invalid scenario"` @ `0x10B6E538`
- `"MpCommon.AddBlockingFirewallRule() error: 4th parameter must be boolean"` @ `0x10B6E578`
- `"MpCommon.AddBlockingFirewallRule() error: 6th parameter must be boolean"` @ `0x10B6E608`
- `"MpCommon.AddBlockingFirewallRule() error: 7th parameter must be boolean"` @ `0x10B6E5C0`


---

## BM Lua Integration

The Behavior Monitoring (BM) subsystem has its own Lua integration path, separate from the scan-time LUASTANDALONE execution:

```
BM Lua Flow:
+-----------------------+       +-------------------------+
| Real-time BM event    |       | BMLua dispatch          |
| (process create,      | ----> | "BMLua" @ 0x10A35A10   |
|  file write, etc.)    |       +-------------------------+
+-----------------------+              |
                                       v
                              +-------------------------+
                              | BM Lua script           |
                              | (matched via sigattr)   |
                              +-------------------------+
                                       |
                                       v
                              +-------------------------+
                              | Engine.Det.BMLuaSigattr |
                              | @ 0x10A49468            |
                              +-------------------------+
```

Key BM Lua strings:
- `"BMLua"` @ `0x10A35A10` — BM Lua dispatch identifier
- `"Engine.Det.BMLuaSigattr"` @ `0x10A49468` — ETW trace for BM Lua signature attribute
- `"!#AsimovBMLuaCall_"` @ `0x10A49480` — Asimov BM Lua call prefix
- `"LuaCallSigattrBM"` @ `0x10A494B0` — BM Lua sig attribute call marker
- `"ERROR: BM Lua calling a SCAN_REPLY dependent API"` @ `0x10B4BCBB` — Error when BM Lua tries to call scan-reply APIs
- `"HIPS Lua function type %d should not return a path"` @ `0x10A4A144` — HIPS Lua function type mismatch

---

## Resource Limits and Sandboxing

Lua scripts execute in a carefully sandboxed environment with hard limits on every resource they can consume. These limits are configurable via DBVAR signatures but have conservative defaults.

### Limit Architecture

```
+------------------------------------------------------------------+
|  Lua Sandbox Limits (all configurable via DBVAR)                 |
|                                                                  |
|  INSTRUCTIONS                                                    |
|    SetLuaInstrLimit           @ 0x10B6B4D0                       |
|    "exceeded the limit."      @ 0x10B6B3EC                       |
|                                                                  |
|  MEMORY                                                          |
|    MpLuaMaxBufferSize         @ 0x10B4B768  (single alloc)       |
|    MpLuaMaxTableElements      @ 0x10B4B898  (table size)         |
|                                                                  |
|  FILE I/O                                                        |
|    MpLuaMaxFileReadTotalSize  @ 0x10B4B734  (total reads)        |
|                                                                  |
|  ATTRIBUTES                                                      |
|    MpLuaMaxAttributesCount    @ 0x10B4B704  (max attrs)          |
|    MpLuaMaxAttributesTotalSize@ 0x10B4B6CC  (total attr bytes)   |
|                                                                  |
|  VFO (Virtual File Objects)                                      |
|    MpLuaMaxVfoCount           @ 0x10B4B7E4  (max VFOs)           |
|    MpLuaMaxVfoTotalSize       @ 0x10B4B790  (total VFO bytes)    |
|    MpLuaMaxVfoNameLen         @ 0x10B4B7BC  (VFO name length)    |
|                                                                  |
|  JSON PARSING                                                    |
|    MpLuaJsonMaxNestingDepth   @ 0x10B6B230  (nesting depth)      |
|    MpLuaJsonMaxDataSize       @ 0x10B6B264  (JSON data size)     |
|    MpLuaJsonMaxElementsPerLevel @ 0x10B6B290 (elements/level)    |
+------------------------------------------------------------------+
```

### Performance Monitoring

The engine tracks expensive Lua scripts using threshold counters:

- `MpExpensiveSignatureThresholdLua` @ `0x10B4B688` — General time threshold
- `MpExpensiveSignatureThresholdIoBytesLua` @ `0x10B4B5E0` — I/O byte threshold
- `MpExpensiveSignatureThresholdTotalTimeLua` @ `0x10B4B630` — Total time threshold

Scripts exceeding these thresholds are logged for performance telemetry, enabling Microsoft to identify and optimize slow scripts in VDM updates.

---

## Execution Flow Pseudocode

Based on decompilation analysis of the code around `Engine.Scan.LuaExecute` at `0x10A33930`:

```c
// Pseudocode
// Entry: Engine.Scan.LuaExecute @ 0x10A33930

void LuaExecute(ScanContext* ctx) {
    // ETW trace: "Engine.Scan.LuaExecute" @ 0x10A33930
    TraceEvent("Engine.Scan.LuaExecute");

    // Get list of triggered LUASTANDALONE scripts
    LuaStandaloneList* scripts = GetTriggeredLuaScripts(ctx);
    if (!scripts || scripts->count == 0) return;

    for (int i = 0; i < scripts->count; i++) {
        LuaScript* script = &scripts->entries[i];

        // Create a new Lua state
        lua_State* L = luaL_newstate();
        if (!L) continue;

        // Register panic handler
        // "LuaRunnerPanicsRegistryName" @ 0x10B6B414
        lua_pushcfunction(L, LuaPanicHandler);
        SetRegistryValue(L, "LuaRunnerPanicsRegistryName");

        // Set script name for debugging
        // "LuaRunnerScriptNameRegistryName" @ 0x10B6B430
        lua_pushstring(L, script->name);
        SetRegistryValue(L, "LuaRunnerScriptNameRegistryName");

        // Initialize instruction counter
        // "LuaRunnerInstructionsCountRegistryName" @ 0x10B6B478
        lua_pushinteger(L, 0);
        SetRegistryValue(L, "LuaRunnerInstructionsCountRegistryName");

        // Set instruction limit hook
        // "SetLuaInstrLimit" @ 0x10B6B4D0
        SetLuaInstrLimit(L, ctx->instr_limit);

        // Register mp.* API functions (106 functions)
        RegisterMpApi(L, ctx);

        // Load and register MpCommon library
        // "MpCommonLua" @ 0x10B6E2CC
        if (!LoadMpCommonLib(L)) {
            // "Failed to load MpCommon lib" @ 0x10B4BA90
            LogError("Failed to load MpCommon lib");
        }

        // Load the script bytecode
        int err = luaL_loadbuffer(L, script->bytecode, script->size, script->name);
        if (err != 0) {
            // "LoadOpaqueLuaScript failed" @ 0x10B4B910
            LogError("LoadOpaqueLuaScript failed");
            lua_close(L);
            continue;
        }

        // Execute the script
        err = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (err != 0) {
            // "Engine.Lua.ScriptError" @ 0x10B4B8C8
            const char* errmsg = lua_tostring(L, -1);
            TraceEvent("Engine.Lua.ScriptError", errmsg);

            if (err == LUA_ERRMEM) {
                // Instruction limit exceeded or OOM
                // "SetLuaInstrLimit exceeded the limit." @ 0x10B6B3EC
            }
        }

        // Collect results (attributes, detections, VFOs)
        CollectLuaResults(L, ctx);

        // Close the Lua state
        lua_close(L);
    }
}
```


---

## Script Triggering Mechanism

Not all 59,415 Lua scripts run on every file. Scripts are associated with trigger conditions that must be satisfied before execution:

```
Trigger Types:
+-----------------------------------------------+
| 1. HSTR Match Trigger                         |
|    Script runs only if a specific HSTR/PEHSTR |
|    pattern was matched in Stage 3             |
+-----------------------------------------------+
| 2. Attribute Trigger                          |
|    Script runs if a specific attribute was    |
|    set by any prior stage (SIGATTR, FOP, etc) |
+-----------------------------------------------+
| 3. File Type Trigger                          |
|    Script runs for specific content types     |
|    (PE, script, document, etc.)               |
+-----------------------------------------------+
| 4. BM Event Trigger                           |
|    BMLua scripts triggered by real-time       |
|    behavioral events                          |
|    "LuaTrigger" @ 0x10A0FEC4                  |
+-----------------------------------------------+
```

This trigger mechanism is critical for performance — without it, running 59K scripts per file would be prohibitively expensive. In practice, only a handful of scripts typically trigger per scan.

---

## Virtual File Objects (VFOs)

Lua scripts can create Virtual File Objects — temporary in-memory files that are recursively scanned by the pipeline:

```lua
-- Example: Script creates a VFO containing decoded content
local decoded = decode_base64(mp.readfile(offset, size))
local vfo = mp.createvfo("decoded_payload.bin", decoded)
-- The VFO will be recursively scanned through Stages 2-13
```

VFO limits:
- `MpLuaMaxVfoCount` @ `0x10B4B7E4` — Maximum number of VFOs a single script can create
- `MpLuaMaxVfoTotalSize` @ `0x10B4B790` — Maximum total bytes across all VFOs
- `MpLuaMaxVfoNameLen` @ `0x10B4B7BC` — Maximum VFO name string length

---

## Fileless Resource Reporting

The `MpCommon.ReportFilelessResource` function enables Lua scripts to report fileless attack resources — code patterns found in memory, UEFI firmware, or BITS transfer jobs that do not correspond to on-disk files.

```
Fileless Resource Reporting Flow:
+-------------------------------+
| Lua script detects pattern    |
| in memory / UEFI / BITSjob   |
+-------------------------------+
           |
           v
+-------------------------------+
| MpCommon.ReportFilelessResource()
| Validates:                    |
|   - ThreatId (NID_VNAME)     |
|   - SigSeq                   |
|   - SigId                    |
|   - Schema (bitsjob/uefi)    |
+-------------------------------+
           |
           v
+-------------------------------+
| Creates tracking ID          |
| Calls global callback to     |
| register the resource for    |
| remediation                  |
+-------------------------------+
```

Supported schemas (from error string at `0x10B6E268`):
- **bitsjob** — BITS (Background Intelligent Transfer Service) transfer jobs
- **uefi** — UEFI firmware variables

The `LsaMpCommonLib.EnumerateFirmwareEnvironmentVariables` function (string at `0x10B6E0B0`) enables UEFI firmware scanning.

---

## Firewall Rule Management

The `MpCommon.AddBlockingFirewallRule` function allows Lua scripts to add Windows Firewall rules as part of remediation. The function signature (reconstructed from error messages):

```lua
MpCommon.AddBlockingFirewallRule(
    rule_name,      -- string: firewall rule name
    program_path,   -- string: target program path
    is_inbound,     -- boolean (3rd param): inbound rule flag
    is_outbound,    -- boolean (4th param): outbound rule flag
    scenario,       -- string: scenario identifier
    block_tcp,      -- boolean (6th param): block TCP
    block_udp       -- boolean (7th param): block UDP
)
-- At least one of block_tcp or block_udp must be true
-- Error: @ 0x10B6E2E8
```

---

## Data Flow: Stage 10 to Stage 11

The primary output of Stage 10 feeds into Stage 11 (AAGGREGATOR evaluation):

```
Stage 10 Outputs:
+------------------------------------------+
| 1. New Attributes                        |
|    mp.setattribute("LuaDetected_X", 1)   |
|    -> Added to ScanContext.attributes     |
|    -> Evaluated in Stage 11 AAGGREGATOR  |
+------------------------------------------+
| 2. Direct Detections                     |
|    mp.fire("Trojan:Win32/FooBar")         |
|    -> Added to ScanContext.threat_list    |
|    -> Merged in Stage 13 Verdict         |
+------------------------------------------+
| 3. Lowfi Markers                         |
|    mp.setlowfi("SuspiciousPattern")       |
|    -> Triggers Stage 12 MAPS lookup      |
+------------------------------------------+
| 4. Virtual File Objects                  |
|    mp.createvfo("decoded.bin", data)      |
|    -> Recursively scanned (Stage 2-13)   |
+------------------------------------------+
```

---

## Cross-References

- **Stage 3 (Static Cascade)** — Provides HSTR/PEHSTR matches that trigger Lua scripts
- **Stage 4 (Attribute Collection)** — Provides initial attributes readable by `mp.getattribute()`
- **Stage 5 (PE Emulation)** — Provides FOP/TUNNEL attributes and unpacked content
- **Stage 9 (BRUTE)** — Provides additional pattern matches before Lua runs
- **Stage 11 (AAGGREGATOR)** — Evaluates boolean expressions over attributes set by Lua scripts
- **Stage 12 (MAPS Cloud)** — Triggered by lowfi markers set by Lua scripts
- **Stage 13 (Verdict)** — Merges detections fired directly by Lua scripts

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Lua runtime version | 5.1 (`0x1098C124`) |
| LUASTANDALONE scripts in VDM | ~59,415 |
| mp.* API functions | ~106 |
| MpCommon.* functions | ~14 |
| CLuaStandaloneLibrary templates | 9+ |
| Resource limit parameters | 12 |
| Performance threshold parameters | 3 |

