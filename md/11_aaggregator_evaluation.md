# Stage 11 — AAGGREGATOR Boolean Expression Evaluation

> Reverse engineering documentation for the AAGGREGATOR evaluation stage inside `mpengine.dll`.
> All addresses, strings, and structures from RE of mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 11 is the **AAGGREGATOR evaluation engine** — the culmination of all attribute collection from prior stages. Where earlier stages detect individual byte patterns, emulation behaviors, or script-level indicators, the AAGGREGATOR takes the complete set of attributes accumulated across Stages 3-10 and evaluates **boolean expressions** over them to produce composite detections.

The AAGGREGATOR is conceptually simple but enormously powerful: it takes a set of named attributes (strings) and evaluates boolean AND/OR/NOT expressions that combine them. This enables detection logic like "if the file has suspicious imports AND high entropy AND was packed AND is not signed, then fire detection X."

Two signature types implement this:

| Signature Type | Address | Description |
|----------------|---------|-------------|
| `SIGNATURE_TYPE_AAGGREGATOR` | `0x10986B3C` | Standard boolean expression evaluator |
| `SIGNATURE_TYPE_AAGGREGATOREX` | `0x10986E28` | Extended version with additional capabilities |

---

## Entry Conditions

Stage 11 executes after all attribute-producing stages (3-10) have completed:

```
              All Prior Stages Complete
                       |
                       v
        +-------------------------------+
        | Collect all attributes from:  |
        |   Stage 3:  HSTR, PEHSTR     |
        |   Stage 4:  SIGATTR          |
        |   Stage 5:  FOP, TUNNEL      |
        |   Stage 8:  Script patterns  |
        |   Stage 9:  BRUTE matches    |
        |   Stage 10: mp.setattribute()|
        +-------------------------------+
                       |
                       v
        +-------------------------------+
        | Load AAGGREGATOR sigs         |
        | from VDM database             |
        +-------------------------------+
                       |
                       v
        +-------------------------------+
        | For each AAGGREGATOR sig:     |
        |   Parse boolean expression    |
        |   Evaluate against attr set   |
        |   If TRUE -> fire detection   |
        +-------------------------------+
                       |
                       v
        +-------------------------------+
        | Detections added to           |
        | ScanContext.threat_list        |
        +-------------------------------+
                       |
                       v
               Stage 12 (MAPS Cloud)
```

---

## Key Strings from mpengine.dll

| String | Address | Section | Type |
|--------|---------|---------|------|
| `SIGNATURE_TYPE_AAGGREGATOR` | `0x10986B3C` | .rdata | ASCII |
| `SIGNATURE_TYPE_AAGGREGATOREX` | `0x10986E28` | .rdata | ASCII |
| `Boolean` | `0x10982CD4` | .rdata | ASCII |
| `Boolean:` | `0x109332AC` | .rdata | ASCII (with space — format prefix) |

---

## Boolean Expression Language

AAGGREGATOR signatures contain boolean expressions that reference attribute names collected during the scan. The expression language is intentionally minimal:

### Operators

| Operator | Symbol | Precedence | Description |
|----------|--------|------------|-------------|
| AND | `&` | 2 | Both operands must be present |
| OR | `\|` | 1 (lowest) | At least one operand must be present |
| NOT | `!` | 3 (highest) | Operand must NOT be present (or: is infra marker) |
| Grouping | `( )` | N/A | Override precedence |

### Operand Types

Operands are attribute names — strings that were deposited into the scan context by prior stages:

```
Operand Types:
+--------------------------------------------------------+
| HSTR:PatternName      - Hash string match (Stage 3)   |
| PEHSTR:PatternName    - PE hash string match (Stage 3)|
| SIGATTR:AttrName      - Signature attribute (Stage 4) |
| FOP:BehaviorName      - Emulation behavior (Stage 5)  |
| TUNNEL:ApiName        - API tunnel call (Stage 5)     |
| BRUTE:PatternName     - BRUTE match (Stage 9)         |
| LuaAttr:CustomName    - Lua-set attribute (Stage 10)  |
| !InfraMarkerName      - Infrastructure marker         |
+--------------------------------------------------------+
```

### Expression Examples

```
Simple AND expression:
    HSTR:SuspiciousImport & HSTR:HighEntropy
    → True if BOTH hash strings matched

OR expression:
    FOP:VirtualAlloc | FOP:VirtualProtect
    → True if EITHER emulation behavior was seen

Complex nested expression:
    (HSTR:PackedUPX | HSTR:PackedASPack) & SIGATTR:NotSigned & !InfraMarkerCleaner
    → True if packed AND not signed, minus known-clean infra marker

Infrastructure marker usage:
    !InfraA & !InfraB & HSTR:SuspiciousPattern
    → Fire detection only when BOTH infrastructure markers are present
      AND the suspicious pattern matched
```

---

## Infrastructure Markers

Infrastructure markers are a critical concept unique to the AAGGREGATOR. They are threat names prefixed with `!` that are **never returned to the user as final detections**. Instead, they serve as **building blocks** for more complex boolean expressions.

```
Infrastructure Marker Flow:
+-------------------------------------------+
| Stage 3-10: Static/Dynamic Analysis       |
|                                           |
| Some detections produce !-prefixed names: |
|   !InfraA → sets attribute "!InfraA"     |
|   !InfraB → sets attribute "!InfraB"     |
|   !InfraC → sets attribute "!InfraC"     |
|                                           |
| These are NOT real threats — they are     |
| intermediate building blocks              |
+-------------------------------------------+
              |
              v
+-------------------------------------------+
| Stage 11: AAGGREGATOR Evaluation          |
|                                           |
| Expression:                               |
|   !InfraA & !InfraB & HSTR:Pattern        |
|   → Evaluates to TRUE                     |
|   → Fires: Trojan:Win32/Composite.A       |
|                                           |
| The final detection name has NO ! prefix  |
| — it is a real threat returned to user    |
+-------------------------------------------+
              |
              v
+-------------------------------------------+
| Stage 13: Verdict Resolution              |
|                                           |
| !InfraA, !InfraB, !InfraC are FILTERED   |
| Only "Trojan:Win32/Composite.A" survives  |
| as a reportable detection                 |
+-------------------------------------------+
```

### Why Infrastructure Markers?

The `!` prefix pattern solves a fundamental detection engineering challenge: how do you build complex multi-factor detections without every intermediate signal being treated as a standalone threat?

Example scenario:
- `!SuspiciousImports` — File imports VirtualAlloc + WriteProcessMemory + CreateRemoteThread
- `!HighEntropy` — File has entropy > 7.5 in .text section
- `!NotSignedByTrustedPublisher` — File is not signed by a known publisher
- `!SmallPEFile` — PE file is under 500KB

Individually, none of these is sufficient to declare a file malicious. But the AAGGREGATOR can combine them:

```
!SuspiciousImports & !HighEntropy & !NotSignedByTrustedPublisher & !SmallPEFile
→ Trojan:Win32/Injector.Gen!MTB
```

This fires a real detection only when ALL four conditions are present simultaneously.

---

## AAGGREGATOR vs AAGGREGATOREX

The VDM contains two related signature types:

### SIGNATURE_TYPE_AAGGREGATOR (0x10986B3C)

The standard AAGGREGATOR evaluates simple boolean expressions over the attribute set. The expression format is a flat string with `&`, `|`, `!`, and parentheses.

```
Standard AAGGREGATOR Signature:
+-----------------------------------------------+
| Header                                        |
|   SigType:     SIGNATURE_TYPE_AAGGREGATOR     |
|   SigId:       unique identifier              |
|   ThreatName:  "Trojan:Win32/Example.A"       |
+-----------------------------------------------+
| Body                                          |
|   Expression:  "!InfraA & !InfraB & HSTR:X"  |
+-----------------------------------------------+
```

### SIGNATURE_TYPE_AAGGREGATOREX (0x10986E28)

The extended AAGGREGATOREX adds additional capabilities beyond simple boolean evaluation:

```
Extended AAGGREGATOREX Signature:
+-----------------------------------------------+
| Header                                        |
|   SigType:     SIGNATURE_TYPE_AAGGREGATOREX   |
|   SigId:       unique identifier              |
|   ThreatName:  "Trojan:Win32/Example.B"       |
+-----------------------------------------------+
| Body                                          |
|   Expression:  extended boolean expression    |
|   + Additional evaluation context             |
|   + Weighted scoring capability               |
|   + Threshold-based firing                    |
+-----------------------------------------------+
```

The AAGGREGATOREX likely supports:
- **Weighted attributes** — each attribute contributes a score rather than a boolean
- **Threshold firing** — fire only when accumulated score exceeds a threshold
- **Contextual evaluation** — different behavior based on scan context (file type, scan source, etc.)

---

## Expression Parser Pseudocode

Based on decompilation analysis:

```c
// AAGGREGATOR expression evaluator

typedef struct {
    const char* expr;       // Expression string
    int         pos;        // Current parse position
    HashSet*    attributes; // Attribute set from ScanContext
} AaggContext;

// Evaluate a complete expression
bool EvaluateAaggExpression(const char* expr, HashSet* attrs) {
    AaggContext ctx = { expr, 0, attrs };
    bool result = ParseOrExpr(&ctx);
    return result;
}

// OR has lowest precedence
bool ParseOrExpr(AaggContext* ctx) {
    bool left = ParseAndExpr(ctx);
    while (PeekChar(ctx) == '|') {
        AdvanceChar(ctx); // consume '|'
        bool right = ParseAndExpr(ctx);
        left = left || right;
    }
    return left;
}

// AND has higher precedence than OR
bool ParseAndExpr(AaggContext* ctx) {
    bool left = ParsePrimary(ctx);
    while (PeekChar(ctx) == '&') {
        AdvanceChar(ctx); // consume '&'
        bool right = ParsePrimary(ctx);
        left = left && right;
    }
    return left;
}

// Primary: parenthesized expression, NOT, or attribute name
bool ParsePrimary(AaggContext* ctx) {
    SkipWhitespace(ctx);

    if (PeekChar(ctx) == '(') {
        AdvanceChar(ctx); // consume '('
        bool result = ParseOrExpr(ctx);
        ExpectChar(ctx, ')');
        return result;
    }

    if (PeekChar(ctx) == '!') {
        AdvanceChar(ctx); // consume '!'
        // Read the attribute name (including the ! prefix)
        char* name = ParseAttributeName(ctx);

        // NOTE: ! in front of an infra marker means "this infra
        // marker IS present" — it's the marker's own name
        // Attribute names starting with ! are infra markers
        char full_name[256];
        snprintf(full_name, sizeof(full_name), "!%s", name);
        return HashSet_Contains(ctx->attributes, full_name);
    }

    // Plain attribute name
    char* name = ParseAttributeName(ctx);
    return HashSet_Contains(ctx->attributes, name);
}
```


---

## Attribute Sources and Their Prefixes

The AAGGREGATOR evaluates attributes from all prior stages. Here is a comprehensive list of attribute sources and their naming conventions:

```
+------------------+----------------------------------+-------------------+
| Source Stage     | Attribute Format                 | Example           |
+------------------+----------------------------------+-------------------+
| Stage 3 (HSTR)  | HSTR:<pattern_name>              | HSTR:SusImport    |
| Stage 3 (PEHSTR)| PEHSTR:<pattern_name>            | PEHSTR:UPXHeader  |
| Stage 3 (Static)| PESTATIC:<check_name>            | PESTATIC:NoReloc  |
| Stage 4 (SIGATTR)| SIGATTR:<attr_name>             | SIGATTR:IsDropper |
| Stage 5 (FOP)   | FOP:<behavior_name>              | FOP:VirtualAlloc  |
| Stage 5 (TUNNEL)| TUNNEL:<api_name>                | TUNNEL:NtWrite    |
| Stage 5 (THREAD)| THREAD:<observation>             | THREAD:Injection  |
| Stage 8 (Script)| NSCRIPT:<pattern>                | NSCRIPT:ObfBase64 |
| Stage 9 (BRUTE) | BRUTE:<pattern_name>             | BRUTE:Polymorphic |
| Stage 10 (Lua)  | <custom_name>                    | LuaDetected_X     |
| Infra Markers   | !<marker_name>                   | !TrojanBehavior   |
+------------------+----------------------------------+-------------------+
```

---

## Evaluation Data Structures

```c
// AAGGREGATOR signature as loaded from VDM
struct AaggregatorSig {
    uint32_t sig_type;      // SIGNATURE_TYPE_AAGGREGATOR (0x41)
    uint64_t sig_id;        // Unique signature identifier
    uint64_t sig_seq;       // Signature sequence number
    uint32_t threat_id;     // Associated threat ID
    char*    threat_name;   // Associated threat name
    uint8_t  severity;      // Threat severity (1-5)
    uint8_t  category;      // Threat category
    char*    expression;    // Boolean expression string
    uint32_t flags;         // Evaluation flags
};

// AAGGREGATOREX adds extended fields
struct AaggregatorExSig {
    AaggregatorSig base;    // Inherits standard fields
    uint32_t eval_mode;     // Extended evaluation mode
    uint32_t threshold;     // Score threshold for firing
    // Additional context-dependent fields
};

// Attribute set (from ScanContext)
// Implemented as a hash set for O(1) lookup
struct AttributeSet {
    HashTable* table;       // Hash table of attribute strings
    uint32_t   count;       // Number of attributes
    uint32_t   capacity;    // Table capacity
};
```


---

## Expression Complexity Analysis

The AAGGREGATOR expression language, while simple, can encode sophisticated detection logic:

### Depth of Composition

```
Level 0 (Single Attribute):
    HSTR:SuspiciousString
    → Simple byte-pattern match

Level 1 (Simple Combination):
    HSTR:SuspiciousString & SIGATTR:NotSigned
    → Pattern + context

Level 2 (Multi-Factor):
    (HSTR:SusImport | FOP:SusApi) & SIGATTR:NotSigned & !HighEntropy
    → Multiple evidence types combined

Level 3 (Complex Heuristic):
    (!PESusImports & !PEHighEntropy & !PENoReloc) |
    (!ScriptObfuscated & !ScriptEval & !ScriptDynamic) |
    (!DocMacroPresent & !DocAutoOpen & !DocCallsShell)
    → Three independent detection paths OR'd together
```

### Performance Characteristics

Expression evaluation is extremely fast because:
1. The attribute set is a hash table — O(1) lookup per attribute
2. Expressions use short-circuit evaluation — AND stops at first FALSE, OR stops at first TRUE
3. Expression parsing is single-pass — no backtracking
4. Typical expressions reference 2-8 attributes

Even with thousands of AAGGREGATOR signatures, evaluation completes in microseconds.

---

## Relationship to Other Stages

### Inputs (Stages 3-10)

```
                  +-----------+
                  | Stage 3   |
                  | HSTR      |----> HSTR:PatternA
                  +-----------+      HSTR:PatternB
                                          |
                  +-----------+           |
                  | Stage 4   |           |
                  | SIGATTR   |----> SIGATTR:X     All attrs
                  +-----------+           |      collected in
                                          |    --> HashSet<String>
                  +-----------+           |           |
                  | Stage 5   |           |           |
                  | FOP/TUNNEL|----> FOP:Behavior     |
                  +-----------+           |           |
                                          |           |
                  +-----------+           |           v
                  | Stage 10  |           |    +-----------+
                  | Lua       |----> Attr:X    | Stage 11  |
                  +-----------+    -------->   | AAGGREGATOR|
                                               | Evaluate  |
                                               +-----------+
                                                     |
                                                     v
                                               Detections
```

### Outputs (Stages 12-13)

- **Detections** are added to `ScanContext.threat_list`
- **Infrastructure marker detections** (! prefix) are added but flagged as `is_infra = true`
- Lowfi detections from AAGGREGATOR can trigger **Stage 12 MAPS cloud lookup**
- All detections are merged in **Stage 13 Verdict Resolution**

---

## AAGGREGATOR in the Detection Engineering Workflow

From Microsoft's perspective, the AAGGREGATOR is a powerful tool for detection engineers:

```
Detection Engineering Workflow:
+-----------------------------------------------+
| 1. Analyst identifies malware family           |
| 2. Identifies N behavioral indicators:         |
|    - Suspicious API imports                    |
|    - High entropy sections                     |
|    - Known packer signatures                   |
|    - Unsigned binary                           |
| 3. Creates infrastructure markers for each:    |
|    !MalFamily_SusImports                       |
|    !MalFamily_HighEntropy                      |
|    !MalFamily_PackerSig                        |
|    !MalFamily_Unsigned                         |
| 4. Creates AAGGREGATOR expression:             |
|    !MalFamily_SusImports &                     |
|    !MalFamily_HighEntropy &                    |
|    (!MalFamily_PackerSig | !MalFamily_Unsigned)|
|    → Trojan:Win32/MalFamily.Gen!MTB            |
| 5. Ships via VDM update (no engine change)     |
+-----------------------------------------------+
```

This workflow means new composite detections can be created and deployed entirely through signature database updates, without modifying `mpengine.dll` itself. The turnaround time from sample analysis to global deployment is measured in hours.

---

## Error Handling

When expression evaluation fails:

1. **Parse Error** — Malformed expression syntax → skip signature, log error
2. **Missing Attribute Reference** — Attribute name not in set → evaluates to FALSE (no error)
3. **Expression Too Long** — Possible stack overflow during recursive parsing → abort with error
4. **Memory Allocation Failure** — OOM during evaluation → abort scan stage

The engine is defensive: a malformed AAGGREGATOR expression cannot crash the scan — it simply evaluates to FALSE and the detection does not fire.

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Signature type (standard) | `SIGNATURE_TYPE_AAGGREGATOR` @ `0x10986B3C` |
| Signature type (extended) | `SIGNATURE_TYPE_AAGGREGATOREX` @ `0x10986E28` |
| Operators supported | AND (`&`), OR (`\|`), NOT (`!`), Parentheses |
| Attribute sources | 10+ stages |
| Evaluation complexity | O(n) per expression, O(1) per attribute lookup |
| Infrastructure marker prefix | `!` (exclamation mark) |


---

## Cross-References

- **Stage 3 (Static Cascade)** — HSTR/PEHSTR patterns produce attributes for AAGGREGATOR
- **Stage 4 (Attribute Collection)** — SIGATTR values consumed by AAGGREGATOR
- **Stage 5 (PE Emulation)** — FOP/TUNNEL/THREAD attributes consumed by AAGGREGATOR
- **Stage 9 (BRUTE)** — BRUTE pattern matches produce attributes
- **Stage 10 (Lua Scripts)** — `mp.setattribute()` deposits custom attributes
- **Stage 12 (MAPS Cloud)** — Lowfi AAGGREGATOR results trigger cloud lookup
- **Stage 13 (Verdict Resolution)** — AAGGREGATOR detections merged into final verdict; infra markers filtered
