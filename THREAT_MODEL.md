# GitForensics — Threat Model & Security Posture

**Document Purpose:** Security analysis, trust boundary definitions, adversarial repository mitigations, and residual risks for the GitForensics engine.

---

## 1. System Overview & Trust Boundaries

GitForensics operates as an air-gapped, read-only forensic analysis tool.

```text
[ UNTRUSTED INPUT ] 
  - Arbitrary .git directories
  - Malformed loose objects
  - Malicious packfiles / deltas
  - Path traversal attempts
          |
          v  (Read-Only Filesystem Access)
+-------------------------------------------------------+
|  GitForensics Core Engine (TRUST BOUNDARY)            |
|  - Zero Network Calls                                 |
|  - Zero Subprocess Invocations (No os/exec)           |
|  - Memory & Recursion Circuit Breakers                |
|  - Centralized Redaction Engine                       |
+-------------------------------------------------------+
          |
          v  (Sanitized stdout / stderr)
[ SAFE USER-FACING OUTPUT ]
  - Terminal Report (Redacted Tokens, Zero Private Keys)
  - Atomic JSON Report (Strict Schema Stability)
```

---

## 2. Threat Scenarios & Mitigations

### 2.1 Malicious / Adversarial Repositories
- **Threat:** Attacker provides a crafted Git repository designed to exploit parser vulnerabilities (buffer overflows, path traversal, integer wraps).
- **Mitigations:**
  - **Memory-Safe Language:** Built in pure Go with automatic bounds checking and zero Cgo/unsafe dependencies.
  - **Path Traversal Defense:** Repository discovery and object loading resolve paths through `filepath.Clean` and reject directory traversal escapes.
  - **Read-Only Enforcement:** All files are opened with `os.O_RDONLY`. The engine cannot modify, corrupt, or delete target repository files.

### 2.2 Decompression Bombs & Resource Exhaustion
- **Threat:** Crafted zlib streams or pack entries declaring small compressed sizes that inflate to gigabytes of memory.
- **Mitigations:**
  - **Strict Size Limits:** Zlib inflators are bounded by `io.LimitReader(r, maxObjectSize+1)` (default 64 MiB).
  - **Oversize Blob Protection:** Blobs exceeding 10 MiB are recorded as `skippedOversizeBlob` coverage gaps rather than scanned in memory.
  - **Continuation Byte Caps:** Variable-length headers enforce maximum continuation lengths ($\le 9$ bytes for entry headers, $\le 10$ for OFS offsets).

### 2.3 Cyclic DAGs & Recursion Exhaustion
- **Threat:** Malformed commits, trees, symbolic refs, or delta chains structured cyclically to cause stack overflow panics.
- **Mitigations:**
  - **Symbolic Ref Cycles:** Tracked with `visitedRefs` map and capped at depth 10 (`ErrSymbolicRefCycle`).
  - **Tag Peeling Cycles:** Tracked with `visitedTags` set and capped at depth 10 (`ErrTagPeelCycle`).
  - **Tree Traversal Limit:** Tree recursion depth is strictly bounded to 1000 levels (`ErrMaxTreeDepthExceeded`).
  - **OFS_DELTA Cycles:** In-flight delta offsets are tracked in a `resolving` set (`ErrDeltaChainCycleDetected`) and bounded to depth 50 (`ErrMaxDeltaDepthExceeded`).

### 2.4 Credential & Information Leakage
- **Threat:** Scanner accidentally reveals raw secrets, sensitive tokens, or private keys in logs, terminal stdout, or JSON reports.
- **Mitigations:**
  - **Centralized Redaction Engine:** High-entropy candidates and API tokens are masked (e.g. `AKIA****************`).
  - **PEM Zero-Reveal Guarantee:** Private key blocks are unconditionally replaced with `[REDACTED PRIVATE KEY]`, exposing 0 bytes of key material.
  - **Diagnostic Stream Isolation:** Informational logs go strictly to `stderr`. `stdout` contains only sanitized human reports or pure JSON.

### 2.5 Accidental Subprocess Execution / Remote Code Execution
- **Threat:** Exploiting Git hooks (`.git/hooks/*`), gitlinks (`160000`), or config files (`.git/config`) to execute arbitrary code.
- **Mitigations:**
  - **Subprocess Prohibition:** The engine contains **0 occurrences** of `os/exec`, `exec.Command`, or shell invocations.
  - **Gitlink Non-Recursion:** Mode `160000` entries are treated as opaque boundaries without filesystem traversal or remote submodule cloning.
  - **Hook & Config Ignorance:** GitForensics does not execute hooks or evaluate executable directives in `.git/config`.

---

## 3. Residual Risks & Operational Assumptions

1. **Local Access Trust:** GitForensics assumes the executing user has appropriate local permissions to read the target repository files.
2. **Unsupported Pack Features:** `OBJ_REF_DELTA` pack entries and SHA-256 repositories are recognized as coverage gaps rather than fully decompressed.
3. **Forensic State Interpretation:** A finding indicates that a secret was physically present in object storage; it does not determine whether the credential has been revoked externally.
