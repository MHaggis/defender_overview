# Stage 02 -- FRIENDLY_FILE: SHA-256/SHA-512 Whitelist

> Reverse engineering documentation for **mpengine.dll** v1.1.24120.x
> Source of truth: the actual binary at `engine/mpengine.dll`
---

## 1. Overview

The FRIENDLY_FILE check is the **first filter** in the scan pipeline after entry point
dispatch. It is a hash-based whitelist that allows known-good files to skip the entire
detection pipeline, returning "Clean" immediately.

The engine computes the SHA-256 (or SHA-512) hash of the file being scanned and compares
it against a database of trusted file hashes loaded from the VDM signature files. If a
match is found, the file is marked as "friendly" and **all subsequent scan stages are
bypassed**.

This stage exists for performance: trusted OS files, signed Microsoft binaries, and
other known-good content can skip the expensive static analysis, emulation, container
extraction, and cloud lookup stages entirely.

---

## 2. Entry Conditions

This stage fires when:

1. A scan buffer or file scan request has been dispatched from Stage 01.
2. The engine context is initialized (sentinel check passed).
3. The file/buffer is large enough to hash (not empty).
4. The `isfriendlyscan` configuration flag is enabled.

The stage is skipped when:

- AMSI scans for script content (no file hash available).
- The scan context has `friendlysuppressed` set (detection requires bypass).
- Container child scans where the parent already passed friendly check.

---

## 3. Signature Types

Two dedicated signature types carry the friendly-file hash database:

| Signature Type String                  | Address        | Hash Algorithm |
|----------------------------------------|----------------|----------------|
| `SIGNATURE_TYPE_FRIENDLYFILE_SHA256`   | `0x10986BE4`   | SHA-256        |
| `SIGNATURE_TYPE_FRIENDLYFILE_SHA512`   | `0x10986B74`   | SHA-512        |

These are loaded from the VDM during `MpBootStrap` and compiled into a hash set for
O(1) lookup during scans.

---

## 4. Relevant Strings from Binary

### 4.1 Configuration Flags

| Address        | String                            | Type    | Purpose                                     |
|----------------|-----------------------------------|---------|---------------------------------------------|
| `0x1097ECFC`   | `isfriendlyscan`                  | ASCII   | Boolean config: enable friendly check        |
| `0x1097ED0C`   | `istriggercloudyfriendlyscan`     | ASCII   | Boolean: trigger cloud for friendly matches  |

*(from RE of mpengine.dll @ 0x1097ECFC, 0x1097ED0C)*

### 4.2 Telemetry / Trace Properties

| Address        | String                            | Type     | Purpose                                     |
|----------------|-----------------------------------|----------|---------------------------------------------|
| `0x109E76A0`   | `friendlysigsha`                  | UTF-16LE | Telemetry: SHA hash of friendly match        |
| `0x109E7654`   | `friendlysigseq`                  | UTF-16LE | Telemetry: signature sequence number         |
| `0x109E76D4`   | `friendlysigseqstring`            | UTF-16LE | Telemetry: sequence as string                |
| `0x109E7988`   | `friendlysuppressedsigseq`        | UTF-16LE | Telemetry: suppressed sig sequence           |
| `0x109E79E0`   | `friendlysuppressedsigsha`        | UTF-16LE | Telemetry: suppressed sig hash               |
| `0x109E1DDC`   | `friendlysuppressed`              | UTF-16LE | Telemetry: was friendly check suppressed?    |
| `0x109E2308`   | `friendlyreason`                  | UTF-16LE | Telemetry: reason for friendly disposition   |

### 4.3 ASCII Telemetry Variants

| Address        | String                            | Purpose                                     |
|----------------|-----------------------------------|---------------------------------------------|
| `0x109E7D90`   | `friendlysigseq`                  | ASCII variant of sigseq telemetry            |
| `0x109E7DB4`   | `friendlysigsha`                  | ASCII variant of sigsha telemetry            |
| `0x109E7DC4`   | `friendlysigseqstring`            | ASCII variant of seqstring telemetry         |
| `0x109E7DDC`   | `friendlysuppressedsigsha`        | ASCII variant of suppressed SHA              |
| `0x109E7DF8`   | `friendlysuppressedsigseq`        | ASCII variant of suppressed seq              |
| `0x109E2528`   | `friendlysuppressed`              | ASCII variant of suppressed flag             |
| `0x109E253C`   | `friendlyreason`                  | ASCII variant of reason                      |

### 4.4 Format Strings

| Address        | String                                        | Purpose                             |
|----------------|-----------------------------------------------|-------------------------------------|
| `0x10A53AC8`   | `friendlysuppressedsigseq=%llu`               | Log format for suppressed sequence  |
| `0x10A53E1C`   | `friendlysuppressedsigsha=%ls`                | Log format for suppressed SHA       |

*(from RE of mpengine.dll @ 0x10A53AC8, 0x10A53E1C)*

### 4.5 BM / Real-Time Protection Strings

| Address        | String                                                    | Type     | Purpose                          |
|----------------|-----------------------------------------------------------|----------|----------------------------------|
| `0x109D48AC`   | `rtpproccessfriendly`                                     | UTF-16LE | RTP process-level friendly flag  |
| `0x109D48D4`   | `rtpprocessfriendly`                                      | UTF-16LE | RTP process friendly (corrected) |
| `0x109E49D8`   | `rtpprocessfriendly`                                      | ASCII    | ASCII variant                    |
| `0x109C8D74`   | `friendlyhelper`                                          | ASCII    | Helper function name trace       |
| `0x10A666C0`   | `BM detection suppressed due to friendlyness.`            | UTF-16LE | BM suppression log message       |
| `0x10A66798`   | `BM friendly suppression`                                 | UTF-16LE | BM suppression event name        |

### 4.6 Builtin Signature Names

| Address        | String                                     | Type     | Purpose                             |
|----------------|--------------------------------------------|----------|-------------------------------------|
| `0x10A4B284`   | `BUILTIN:FRIENDLYSHA256`                   | UTF-16LE | Built-in friendly SHA-256 check     |
| `0x10A4B4C0`   | `BUILTIN:STATIC_MATCH_REPORT_AS_FRIENDLY`  | UTF-16LE | Static match reports as friendly    |

### 4.7 Report Flags

| Address        | String                          | Purpose                                     |
|----------------|---------------------------------|---------------------------------------------|
| `0x10980BF0`   | `NID_REPORT_AS_FRIENDLY`        | NID flag to mark detection as friendly       |
| `0x10A0E338`   | `STREAM_ATTRIBUTE_TRUST_SCAN_UNFRIENDLY` | Unfriendly trust scan attribute    |

*(from RE of mpengine.dll @ 0x10980BF0, 0x10A0E338)*

---

## 5. Unfriendly Cache

The engine maintains an "unfriendly cache" to avoid re-scanning files that have been
determined to be non-friendly:

| Address        | String                          | Type     | Purpose                             |
|----------------|---------------------------------|----------|-------------------------------------|
| `0x10A64EC0`   | `MpDisableUnfriendlyCache`      | UTF-16LE | Config: disable unfriendly cache    |
| `0x10A6E0FC`   | `MpDisableUnfriendlyCache`      | ASCII    | ASCII variant of config flag        |
| `0x10A6E080`   | `Unfriendly`                    | UTF-16LE | Cache category label                |
| `0x10A54570`   | `MpNwUnfriendly`                | ASCII    | Network unfriendly flag             |

---

## 6. Trust and Friendly Interaction

The friendly file system interacts with the trust/signing verification subsystem:

| Address        | String                                                              | Purpose                          |
|----------------|---------------------------------------------------------------------|----------------------------------|
| `0x10A4C0C8`   | `%ls is trusted - %hs`                                             | Trusted file log                 |
| `0x10A4BF00`   | `%ls is NOT trusted. Checking Trust? %d`                           | Not trusted log                  |
| `0x10A4BF50`   | `%ls is a trusted file that might be an installer (allowing deeper analysis).` | Trusted installer path |
| `0x10A53670`   | `Detection supressed: %ls (%hs) (0x%llx) (file is trusted) (count=%d)` | Detection suppression       |
| `0x10A539E0`   | `%ls is trusted but could be an installer - performing deeper analysis (pefile)` | Deeper PE analysis |
| `0x10A4BD30`   | `File %ls is too large for the trusted check (container)`          | Size limit log                   |
| `0x10A4BDB0`   | `%ls is not trusted, because the certificate is revoked.`          | Revoked cert log                 |
| `0x10A4BB70`   | `%ls is not trusted, because the certificate is excluded`          | Excluded cert log                |
| `0x10A4BC80`   | `%ls is a trusted installer.`                                       | Trusted installer confirmation   |

### 6.1 Trust Attributes

| Address        | String                             | Purpose                          |
|----------------|------------------------------------|----------------------------------|
| `0x10981938`   | `istrusted_va`                     | Is trusted (virtual address)     |
| `0x10981948`   | `istrusted_rva`                    | Is trusted (relative VA)         |
| `0x109C8048`   | `trustedcontent`                   | Trusted content attribute        |
| `0x109EBA98`   | `trustedstate`                     | Trust state attribute (UTF-16LE) |
| `0x109EC2F0`   | `trustedstate`                     | Trust state attribute (ASCII)    |
| `0x109EB12C`   | `isprocessfriendly`                | Per-process friendly flag        |
| `0x109EAD7C`   | `isprocessfriendly`                | Per-process friendly (UTF-16LE)  |

*(from RE of mpengine.dll @ 0x10981938, 0x109C8048)*

---

## 7. Process-Level Friendly Cache

| Address        | String                             | Purpose                          |
|----------------|------------------------------------|----------------------------------|
| `0x10A65D28`   | `modulemightbefriendly`            | Module-level friendly hint       |

*(from RE of mpengine.dll @ 0x10A65D28)*

Beyond per-file hashing, the engine also caches friendliness at the process level.
When `isprocessfriendly` is set, subsequent file operations from that process may
receive expedited scanning. The `rtpprocessfriendly` attribute (@ `0x109D48D4`)
is set during real-time protection to propagate friendly status from parent process
scans to child operations.

---

## 8. SHA-256 Hashing Implementation

The engine includes a full SHA-256 implementation. The file hash database also
stores hashes in the FileHashes SQLite table:

```sql
-- From string at 0x10A5B4A0
CREATE TABLE FileHashes(
    ID INTEGER PRIMARY KEY NOT NULL,
    Key INTEGER NULL,
    VSN INTEGER NULL,
    FileID INTEGER NULL,
    USN INTEGER NULL,
    InstanceTimeStamp INTEGER NULL,
    SHA1 BLOB NULL,
    MD5 BLOB NULL,
    SHA256 BLOB NULL,
    LSHASH BLOB NULL,
    LSHASHS BLOB NULL,
    CTPH BLOB NULL,
    PartialCRC1 UNSIGNED INT NULL,
    PartialCRC2 UNSIGNED INT NULL,
    PartialCRC3 UNSIGNED INT NULL,
    KCRC1 UNSIGNED INT NULL,
    KCRC2 UNSIGNED INT NULL,
    KCRC3 UNSIGNED INT NULL,
    KCRC3n UNSIGNED INT NULL
);
```

*(from RE of mpengine.dll @ 0x10A5B4A0, embedded SQL string)*

The table stores multiple hash types per file: SHA-1, MD5, SHA-256, locality-sensitive
hashes (LSHASH), CTPH (context-triggered piecewise hashing / ssdeep), and multiple
partial CRC variants used by the KCRCE engine.

---

## 9. Friendly File Lookup Flow

```
                    ┌─────────────────────────┐
                    │  Scan request from       │
                    │  Stage 01 dispatch       │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  Check: isfriendlyscan   │
                    │  enabled? (@ 0x1097ECFC) │
                    └────────────┬────────────┘
                            ┌────┴────┐
                            │ No      │ Yes
                            │         ▼
                            │   ┌──────────────┐
                            │   │ Compute       │
                            │   │ SHA-256 hash  │
                            │   │ of file data  │
                            │   └──────┬───────┘
                            │          │
                            │   ┌──────┴──────────────────┐
                            │   │ Lookup in FRIENDLYFILE   │
                            │   │ SHA256 database          │
                            │   │ (SIGNATURE_TYPE @        │
                            │   │  0x10986BE4)             │
                            │   └──────┬──────────────────┘
                            │     ┌────┴────┐
                            │     │ Found?  │
                            │     └────┬────┘
                            │    No    │   Yes
                            │    │     │
                            │    │     ▼
                            │    │  ┌────────────────────┐
                            │    │  │ Log: friendlysigsha│
                            │    │  │   friendlysigseq   │
                            │    │  │ Set friendly flag   │
                            │    │  │ RETURN CLEAN        │
                            │    │  └────────────────────┘
                            │    │
                            │    ▼
                    ┌───────┴────────────────────┐
                    │  Optionally check SHA-512   │
                    │  (SIGNATURE_TYPE @          │
                    │   0x10986B74)               │
                    └────────────┬───────────────┘
                            ┌────┴────┐
                            │ Found?  │
                            └────┬────┘
                        No ──┘       └── Yes
                        │                 │
                        ▼                 ▼
               ┌─────────────┐    ┌────────────────┐
               │ Continue to  │    │ RETURN CLEAN   │
               │ Stage 03:    │    │ (skip pipeline)│
               │ Static       │    └────────────────┘
               │ Engines      │
               └─────────────┘
```

---

## 10. Friendly Suppression

In some cases, even when a file matches the friendly hash database, the friendly
disposition can be **suppressed** to force full scanning:

1. **Cloud-triggered rescan**: When `istriggercloudyfriendlyscan` is set, a cloud
   service can request that friendly files be re-scanned.
2. **Detection override**: When a signature explicitly targets a previously-friendly
   file (e.g., supply chain compromise), the `friendlysuppressed` attribute is set
   and the telemetry records `friendlysuppressedsigseq` and `friendlysuppressedsigsha`.
3. **BM behavioral detection**: The behavior monitoring engine can suppress friendly
   status if runtime behavior is suspicious, logged as:
   `"BM detection suppressed due to friendlyness."` (@ `0x10A666C0`)

---

## 11. Data Structures

### 11.1 FriendlyFileEntry (Reconstructed)

```c
// Reconstructed from hash lookup code paths
struct FriendlyFileEntry {
    uint8_t  hash[32];        // SHA-256 digest (or 64 bytes for SHA-512)
    uint64_t sig_sequence;    // Signature sequence number
    uint32_t flags;           // Entry flags (trusted publisher, etc.)
};
```

### 11.2 FriendlyScanResult (Reconstructed)

```c
// Reconstructed from telemetry attribute writes
struct FriendlyScanResult {
    bool     is_friendly;         // matched hash database
    bool     is_suppressed;       // friendly status suppressed
    uint64_t matched_sig_seq;     // friendlysigseq value
    wchar_t  matched_sig_sha[65]; // friendlysigsha value (hex string)
    uint32_t friendly_reason;     // friendlyreason code
    bool     trigger_cloud;       // istriggercloudyfriendlyscan
};
```

---

## 12. Performance Impact

The FRIENDLY_FILE check is intentionally the first filter in the pipeline because:

1. **Hash computation is fast**: SHA-256 of a typical file is microseconds.
2. **Lookup is O(1)**: The hash database is compiled into a hash set at boot time.
3. **Skip is maximum**: A friendly match skips ALL remaining stages (3-13).
4. **Hit rate is high**: Most OS files, Microsoft binaries, and common applications
   are in the friendly database, so a large percentage of real-time protection events
   resolve here without any signature matching.

---

## 13. Cross-References

- **Previous stage**: [01 -- Entry Point & Command Dispatch](01_entry_point.md)
- **Next stage**: [03 -- Static Engine Cascade](03_static_engine_cascade.md)
- **Pipeline overview**: [00 -- Master Overview](00_overview.md)

---

*All addresses are from the actual binary image base 0x10001000.*
