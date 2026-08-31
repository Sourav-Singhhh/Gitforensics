# Security Policy for GitForensics

## Overview

GitForensics is an air-gapped, read-only Git forensic scanner designed for analyzing repository history and detecting secrets. This document describes the security scope, vulnerability reporting process, and documented limitations.

---

## Supported Security Scope

GitForensics implements defenses against:

1. **Malicious or adversarial Git repositories**
   - Crafted loose objects, malformed packfiles, and OFS_DELTA cycles
   - Path traversal attempts via `filepath.Clean` path resolution
   - Out-of-bounds reads and decompression bombs via size limits

2. **Parser robustness**
   - Memory-safe bounds checking (pure Go, no unsafe code)
   - Circuit breakers on recursion:
     - Tree traversal: depth ≤ 1000
     - Delta chains: depth ≤ 50
     - Symbolic ref cycles: depth ≤ 10
     - Tag peel cycles: depth ≤ 10
   - Object size limits (default 64 MiB per object; blob scan limit 10 MiB)

3. **Credential leakage prevention**
   - Centralized redaction: secret tokens masked as `PREFIX...SUFFIX` (e.g., `AKIA...CDEF`)
   - PEM private keys replaced with `[REDACTED PRIVATE KEY]`
   - Diagnostic data isolated to `stderr`; `stdout` contains only sanitized reports or JSON

4. **Operational isolation**
   - **Read-only filesystem operations:** All repository files opened with read-only flags; no mutations to target repositories
   - **Zero network calls from GitForensics process:** No HTTP, DNS, cloud telemetry, or remote API invocations within GitForensics itself
   - **Zero subprocess invocations:** No `os/exec`, no git CLI calls, no shell commands

---

## Documented Limitations

### What GitForensics Does NOT Do

- **Not a secret revocation engine:** Proves a secret exists in Git storage; does not verify if the credential is revoked with the provider (e.g., AWS, GitHub)
- **Not a universal secret detector:** Uses regex patterns, entropy analysis, and path context heuristics—false positives and false negatives are possible
- **Not a cryptographic validator:** Identifies high-entropy tokens and patterns; cannot verify key validity or authenticity
- **Not a forensic timeline authority:** Timestamps depend on commit metadata, which can be forged or modified

### Unsupported Features (Recorded as Coverage Gaps)

- **OBJ_REF_DELTA packfile entries** — flagged as `unresolvedPackOnly`
- **SHA-256 object format** — supports standard SHA-1 repositories only
- **Reflog inspection** — `.git/logs/` is outside formal DAG reachability
- **Blobs exceeding 10 MiB** — recorded as `skippedOversizeBlob`, not scanned in memory
- **Packfiles exceeding 512 MiB** — recorded as coverage gaps without processing

### Operational Assumptions

- Local read access to the target repository's `.git` directory
- Correct interpretation of Git object format (PACK v2, loose zlib streams)
- Single-worktree analysis in the context of the target worktree's `HEAD`

---

## How to Report a Vulnerability

**For security issues, use GitHub Security Advisories (primary channel):**

1. Navigate to [Security Advisories](https://github.com/Sourav-Singhhh/Gitforensics/security/advisories) in the repository
2. Click "Report a vulnerability"
3. Complete the form with the details below

**Do NOT** file public issues for active security vulnerabilities.

### Required Information

Please include:

- **Description:** What security property is violated?
- **Affected version(s):** Which release, commit hash, or branch?
- **Steps to reproduce:** Minimal repository structure, file contents, or code snippet
- **Impact:** Does this lead to information disclosure, code execution, denial of service, or bypass of a documented runtime property?
- **Proof-of-concept:** If possible, a crafted `.git` directory or patch demonstrating the flaw

---

## Expected Response Process

Vulnerability reports submitted via GitHub Security Advisories are reviewed by the repository maintainer. Response timelines depend on issue severity and maintainer availability—no SLA is guaranteed.

**Expected process:**

1. **Report received:** Vulnerability is assessed for validity
2. **Investigation:** Impact scope and affected components are analyzed
3. **Fix development:** If confirmed, a patch is prepared
4. **Release:** Patch is merged to the main branch; advisory is published

---

## Runtime Properties & Guarantees

### Read-Only & Air-Gapped Operations

GitForensics runtime properties:

✓ **All repository files opened read-only** — no write operations to `.git` or working tree  
✓ **Zero network activity from GitForensics process** — no HTTP, DNS, cloud APIs, or telemetry calls  
✓ **Zero subprocess invocations** — pure Go, no git CLI, no shell execution  

**What this does NOT guarantee:**

✗ Does not prevent the user from using GitForensics output maliciously  
✗ Does not prevent host-level artifacts (logs, memory dumps, swap) from being analyzed  
✗ Does not guarantee filesystem timing side-channels are absent  
✗ Does not restrict what downstream tools or infrastructure do with forensic output  

### Redaction Properties

✓ Standard tokens are redacted (e.g., `AKIA...CDEF`)  
✓ PEM private keys are replaced with `[REDACTED PRIVATE KEY]`  
✓ Raw secret material is not output to `stdout` or JSON reports  

**What this does NOT guarantee:**

✗ Redaction is not cryptographic proof of secret deletion  
✗ Users are responsible for secure handling of forensic output  
✗ JSON schema changes may affect redaction format in future versions  

---

## Version Coverage

- **Current status:** Pre-release (0.1.0-dev)
- **Supported versions:** Latest main branch only
- **Security patches:** Applied to main branch; no backport guarantee to tags

---

## Legal Disclaimers

- GitForensics is licensed under the MIT License
- Provided as-is with no warranty of merchantability or fitness for a particular purpose
- Users are solely responsible for compliance with applicable laws when analyzing repositories
- Do not use to inspect repositories without legal authorization

---

## References

- [THREAT_MODEL.md](THREAT_MODEL.md) — Detailed threat scenarios, mitigations, and residual risks
- [README.md](README.md) — Architecture, coverage gaps, and operational scope
- [GitHub Security Advisories](https://github.com/Sourav-Singhhh/Gitforensics/security/advisories)

---

*Last Updated: 2026-08-31*  
*Status: Pre-Release*
