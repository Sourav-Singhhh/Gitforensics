# GitForensics

**A zero-dependency, read-only Git history forensic scanner that inspects raw object storage to find committed, deleted, rewritten, or orphaned secrets and proves their physical recoverability.**

[![Go Standard Library Only](https://img.shields.io/badge/Dependencies-0%20External-brightgreen.svg)](#)
[![Zero Network](https://img.shields.io/badge/Network-0%20Calls%20(Airgapped)-blue.svg)](#)
[![Subprocess Policy](https://img.shields.io/badge/Git%20Subprocess-0%20(Pure%20Go)-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 1. One-Line Pitch

GitForensics analyzes raw Git object storage without invoking the Git CLI or third-party libraries, determining whether secrets that were committed, deleted, or rewritten in a repository physically persist on disk and remain recoverable.

---

## 2. Problem Statement

Standard secret scanning tools (such as pre-commit hooks or checkout scanners) only inspect the working tree at the current commit (`HEAD`). When a developer commits a secret and later attempts to "delete" it (via a new commit, `git rm`, `git commit --amend`, or `git rebase`), standard tools report the repository as clean.

However, in Git's object model:
- Historical commits reachable via other branches, tags, or remotes retain the secret in the DAG.
- "Deleted" or amended commits create orphan loose or packed objects that physically persist on disk in `.git/objects/` until Git garbage collection runs (`git gc --prune=now`).
- Anyone with read access to the repository files or `.git` directory can extract unreferenced credentials directly from object storage.

GitForensics solves this by performing deep graph traversal and independent physical object discovery across loose and packfile storage to classify the exact exposure state of every secret.

---

## 3. Core Capabilities

- **Zero-Dependency Pure Go:** Built strictly with the Go standard library (no `go-git`, `libgit2`, or external modules).
- **Zero Subprocess Execution:** Never invokes `git` or external executables via `os/exec`.
- **Read-Only / Air-Gapped:** Performs zero filesystem writes and zero network requests.
- **Physical Object Recovery:** Scans loose objects (`.git/objects/??/*`) and PACK v2 files (`.git/objects/pack/*.pack`) independently from graph reachability.
- **Exposure Classification:** Categorizes every finding into `ACTIVE`, `HISTORICAL`, or `ZOMBIE` states.
- **Multi-Signal Detector:** Combines high-precision regex patterns, Shannon entropy calculation, path context weighting, and false-positive penalty heuristics.
- **Strict Safe Redaction:** Centralized redaction ensures raw secret material and private keys (`[REDACTED PRIVATE KEY]`) never leak to `stdout`, `stderr`, or JSON reports.
- **Forensic History Mapping:** Tracks reachable commit ancestry, author metadata, and file path evolution across linear and merge histories.
- **Explain Subcommand:** Provides state-specific forensic explanation and recovery context for any finding ID.

---

## 4. Architecture

```text
                       +-------------------------+
                       |    GitForensics CLI     |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       |  Repository Discovery   |
                       | (Linked Worktrees/Refs) |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       | ObjectStore Abstraction |
                       +------------+------------+
                                    |
                  +-----------------+-----------------+
                  |                                   |
                  v                                   v
       +--------------------+               +--------------------+
       |  Loose ObjectStore |               |  Pack ObjectStore  |
       |  (zlib + SHA-1)    |               |  (PACK v2/OFS_DELTA|
       +----------+---------+               +---------+----------+
                  |                                   |
                  +-----------------+-----------------+
                                    |
                                    v
                       +-------------------------+
                       |    Normalized Object    |
                       | (Commit / Tree / Blob)  |
                       +------------+------------+
                                    |
                  +-----------------+-----------------+
                  |                                   |
                  v                                   v
       +--------------------+               +--------------------+
       | Reachable Traversal|               | Physical Discovery |
       | (HEAD vs All Refs) |               | (Disk & Pack Scan) |
       +----------+---------+               +---------+----------+
                  |                                   |
                  +-----------------+-----------------+
                                    |
                                    v
                       +-------------------------+
                       | Exposure Classification |
                       | (ACTIVE/HISTORICAL/ZOM) |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       | Secret Detection Engine |
                       | (Patterns/Entropy/Path) |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       | Forensic Report / JSON  |
                       +-------------------------+
```

---

## 5. Phase 1–5 Implementation Foundation

GitForensics is built upon a modular, specification-driven foundation:
- **Phase 1 (Object Layer):** Zero-dependency loose object decoder, zlib inflator, SHA-1 envelope verification, and decompression bomb protection.
- **Phase 2 (Parser Layer):** Canonical commit, tree, and tag parsers with multi-line continuation, merge-commit tracking, and symlink/gitlink boundary safety.
- **Phase 3 (Graph Integration):** Repository discovery, linked-worktree administrative resolution, reference peeling, reachability graph traversal, and loose dangling discovery.
- **Phase 4 (Forensics & CLI):** Shannon entropy engine, context/path scoring, finding assembly, forensic history timeline mapping, explain command, and JSON reporting.
- **Phase 5 (Packfile Storage):** PACK v2 container parser, non-delta extraction, recursive OFS_DELTA reconstruction with Git's `+1` continuation rule, and combined storage abstraction.

---

## 6. Exposure Classification States

Every detected secret candidate is assigned exactly one exposure state:

1. **`ACTIVE` (Current HEAD DAG Exposure):**
   The secret blob is reachable from the repository's current `HEAD` commit through its commit ancestry DAG. It may or may not be checked out in the current working-tree snapshot.
2. **`HISTORICAL` (Other Ref/Branch Exposure):**
   The secret blob is not reachable from current `HEAD`, but remains reachable from another current Git reference such as a branch, tag, remote, or custom reference (`refs/**`). Anyone cloning the repository with full refs will receive this object.
3. **`ZOMBIE` (Dangling/Orphan Exposure):**
   The secret blob is physically present on disk (in loose `.git/objects/` or supported packfiles) but is completely unreferenced by any current Git branch, tag, or ref. It is invisible to `git log` but directly recoverable from local storage by reading the object until `git gc --prune=now` deletes it. *(Note: Because zombie objects are unreferenced by any commit DAG or tree, `"occurrences": null` and `"timeline": null` in JSON output, as there are no reachable commit pointers or file paths to attach.)*
4. **`UNRESOLVED_PACK_ONLY` (Coverage Gap):**
   The object is referenced in the Git DAG but its payload could not be extracted (e.g. unsupported `REF_DELTA` or truncated pack). Unresolved objects are recorded as coverage gaps and are **never** classified as `ZOMBIE`.

---

## 7. Secret Detection Methodology

GitForensics uses a calibrated, multi-signal detection engine:
- **Strong Pattern Matching:** High-confidence regular expressions for AWS Access Keys (`AKIA...`), AWS Temporary Keys (`ASIA...`), GitHub Tokens (`ghp_...`, `gho_...`), Slack Tokens (`xoxb-...`), and Private Key Headers (RSA, OPENSSH, EC, DSA, PGP).
- **Shannon Entropy Analysis:** Calculates information entropy over byte distributions to identify high-randomness tokens while filtering out structured text and repetitive data.
- **Context Window Evaluation:** Inspects adjacent tokens, assignment keywords (`password = `, `token: `, `api_key`), and variable names within configurable byte windows.
- **Path Context Scoring:** Weighs file extensions and path segments (boosting `.env`, `credentials.json`, `id_rsa`; penalizing vendor dirs, test fixtures, documentation).
- **False-Positive Penalties:** Penalizes obvious placeholder tokens (`EXAMPLE`, `REDACTED`, `DUMMY`, `12345678`).

---

## 8. Repository Discovery and Linked Worktrees

- **Discovery:** `Discover(path)` walks directory hierarchies upward until `.git` is found.
- **Linked Worktrees:** Correctly differentiates between `.git/` directories and `.git` files containing `gitdir: <path>`. Resolves shared administrative objects in `commonDir` while isolating worktree-specific `HEAD` state.
- **Reference Peeling:** Resolves loose refs, `packed-refs`, and nested annotated tags with visited-set cycle detection and depth limits.

---

## 9. Loose and Packed Storage

- **Unified Abstraction:** Higher layers interact solely with `repository.ObjectStore`. Traversal, classification, and detection code remain agnostic to whether an object originates from loose files or pack containers.
- **Precedence:** Loose objects take precedence over packed objects during object lookup.
- **Deterministic Enumeration:** Discovers packfiles lexicographically by filename from `commonDir/objects/pack/*.pack`.

---

## 10. PACK and OFS_DELTA Specifications & Safety Limits

- **PACK v2 Support:** Parses 12-byte header (`PACK`, version 2, entry count), reads declared entries sequentially, and verifies trailing 20-byte SHA-1 checksum.
- **OFS_DELTA Implementation:** Implements Git's exact multi-byte offset decoding algorithm:
  $$\text{offset} = ((\text{offset} + 1) \ll 7) \mid (b \ \& \ 0\text{x}7\text{F})$$
- **COPY Size-Zero Rule:** Assembled COPY instruction size of `0` strictly maps to `65536` (`0x10000`).
- **Safety Circuit Breakers:**
  - Max tree recursion depth: 1000
  - Max symbolic ref / tag peel depth: 10
  - Max delta chain depth: 50
  - Max object size: 64 MiB
  - Max blob scan limit: 10 MiB (larger blobs flagged as coverage gaps)

---

## 11. Coverage Gaps and Structural Anomalies

GitForensics maintains radical transparency by never hiding incomplete data:
- **`coverageGaps`:** Explicitly records uninspected or skipped items (e.g. `unresolvedPackOnly`, `skippedOversizeBlob`).
- **`structuralAnomalies`:** Records malformed repository structures (e.g. `malformedCommitTimestamp`, `symbolicRefCycle`, `packChecksumMismatch`) without aborting whole-repository analysis.

---

## 12. Read-Only and Air-Gapped Security Guarantees

- **No Write Operations:** Opens all repository files with read-only flags (`os.O_RDONLY`). Never mutates, creates, or deletes repository files.
- **Zero Network Activity:** Contains zero networking code, HTTP clients, cloud telemetry, or remote API invocations.
- **Zero Subprocess Invocations:** Does not call `os/exec` or spawn child processes.

---

## 13. CLI Commands and Flags

### Usage
```bash
gitforensics scan [<repo-path>] [flags]
gitforensics explain <finding-id> [--repo <path>] [flags]
gitforensics version
```

### Flags
- `--json`: Output report as a single, valid JSON document on `stdout`.
- `--no-color`: Disable ANSI terminal escape colors.
- `--quiet`: Suppress diagnostic messages and progress logs on `stderr`.
- `--min-confidence <tier>`: Filter displayed findings (`low`, `medium`, `high`, `critical`).
- `--repo <path>`: Explicit target repository path.

### Exit Codes
- `0`: Scan completed successfully; zero findings discovered.
- `1`: Findings discovered in repository, or `explain` target finding not found.
- `2`: Invalid command arguments, non-existent repository, or malformed finding ID.
- `3`: Genuinely unexpected internal I/O or system failure.

---

## 14. JSON Contract

When `--json` is specified, `stdout` produces a machine-readable document adhering to `schemaVersion: "1.0"`. All field names below exactly match the implementation:

```json
{
  "schemaVersion": "1.0",
  "tool": {
    "name": "gitforensics",
    "version": "0.1.0-dev"
  },
  "repository": {
    "path": "/path/to/repo",
    "gitDir": "/path/to/repo/.git",
    "commonDir": "/path/to/repo/.git",
    "isBare": false,
    "headResolved": "0123456789abcdef0123456789abcdef01234567"
  },
  "scan": {
    "startTime": "2026-08-29T22:00:00Z",
    "durationMs": 42,
    "minConfidence": "LOW"
  },
  "summary": {
    "totalBlobsScanned": 42,
    "activeBlobsCount": 3,
    "historicalBlobsCount": 1,
    "zombieBlobsCount": 0,
    "totalFindingsCount": 1,
    "displayedFindingsCount": 1,
    "criticalFindingsCount": 1,
    "highFindingsCount": 0,
    "mediumFindingsCount": 0,
    "lowFindingsCount": 0
  },
  "findings": [
    {
      "id": "a1b2c3d4e5f60718",
      "fullDigest": "a1b2c3d4e5f607180123456789abcdef0123456789abcdef0123456789abcdef",
      "blobId": "9f8e7d6c5b4a39281701928374655647382910ab",
      "fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "exposureState": "ACTIVE",
      "patternName": "AWS Access Key",
      "category": "aws",
      "confidenceScore": 95,
      "confidenceTier": "CRITICAL",
      "redacted": "AKIA...CDEF",
      "lineNumber": 12,
      "byteOffset": 347,
      "isBinary": false,
      "occurrences": [
        {
          "commitSha": "1234567890abcdef1234567890abcdef12345678",
          "commitTimestamp": 1788000000,
          "commitDate": "2026-01-01T12:00:00Z",
          "author": "Developer <dev@example.com>",
          "path": "config/aws.env"
        }
      ],
      "timeline": {
        "earliestObservedCommit": "1234567890abcdef1234567890abcdef12345678",
        "earliestObservedDate": "2026-01-01T12:00:00Z",
        "earliestObservedAuthor": "Developer <dev@example.com>",
        "evidenceNote": "Secret remains active and reachable from current HEAD."
      },
      "evidenceSignals": [
        { "rule": "Strong Pattern Match", "score": 45, "detail": "Matched AWS Access Key (aws)" },
        { "rule": "Shannon Entropy Analysis", "score": 25, "detail": "Entropy: 5.1 bits/byte" },
        { "rule": "Context Keywords", "score": 20, "detail": "Nearby keywords: [secret]" },
        { "rule": "Path Sensitivity", "score": 10, "detail": "Path signal score: 10" }
      ]
    }
  ],
  "coverageGaps": [],
  "structuralAnomalies": [],
  "fatalError": null
}
```

> **ZOMBIE Findings Semantics:** For `ZOMBIE` findings, `"occurrences": null` and `"timeline": null` in the JSON report. Because zombie blobs are unreferenced by any reference-rooted commit graph or tree structure, there are no reachable commit SHAs, author identities, or file paths associated with the object. The blob is physically present in `.git/objects/` on disk and is forensic evidence directly addressable by `blobId`.

> **Field notes:**
> - `timeline` is `null` (not an empty object) when the commit timestamp is malformed and no timeline data can be derived.
> - `coverageGaps` and `structuralAnomalies` are always present as arrays (never omitted), even when empty.
> - `fatalError` is `null` on a successful scan; a string message on a fatal scan failure.
> - `confidenceTier` values: `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`.
> - `exposureState` values: `"ACTIVE"`, `"HISTORICAL"`, `"ZOMBIE"`.

---

## 15. Verification, Build, and Testing

### Build

**Linux / macOS (with `make`):**
```bash
make build
# Binary output: bin/gitforensics
```

**Windows (PowerShell) or any platform without `make`:**
```powershell
go build -o bin/gitforensics ./cmd/gitforensics
# Binary output: bin/gitforensics (Windows also accepts this path)
```

### Run Test Suite

**Linux / macOS:**
```bash
make test
```

**Windows / direct Go:**
```powershell
go test -count=1 -v ./...
```

### Reproducible Build Verification

**Linux / macOS:**
```bash
make reproducible-build
# Compiles twice with CGO_ENABLED=0 GOFLAGS=-trimpath and verifies identical SHA-256 hashes
```

**Windows (PowerShell):**
```powershell
$env:CGO_ENABLED = "0"; $env:GOFLAGS = "-trimpath"
go build -o bin/gitforensics_1.exe ./cmd/gitforensics
go build -o bin/gitforensics_2.exe ./cmd/gitforensics
$h1 = (Get-FileHash bin/gitforensics_1.exe -Algorithm SHA256).Hash
$h2 = (Get-FileHash bin/gitforensics_2.exe -Algorithm SHA256).Hash
Write-Host "Build 1: $h1"; Write-Host "Build 2: $h2"
if ($h1 -eq $h2) { Write-Host "Reproducible build: SUCCESS" } else { Write-Host "Reproducible build: FAILED"; exit 1 }
```

---

## 16. Honest Limitations & Operational Scope

- **Not a Secret Revocation Engine:** GitForensics proves whether a secret exists and is recoverable in Git storage; it does not check with remote SaaS providers whether the credential is currently active or revoked.
- **Reflog Boundary:** Reflog files located in `.git/logs/**` are transient local client logs outside the formal Git DAG reachability model. GitForensics models reachability strictly through canonical references (`refs/**` and `HEAD`). Objects referenced solely by reflogs are accurately identified as `ZOMBIE` objects because they physically persist on disk without being reachable in repository history.
- **REF_DELTA Support:** `OBJ_REF_DELTA` (type 7) pack entries are flagged as coverage gaps (`unresolvedPackOnly`) rather than resolved.
- **Packfile Size Limit:** Single packfile safety ceiling is set to 512 MiB; oversized packs are recorded as coverage gaps without crashing.
- **SHA-256 Object Format:** GitForensics currently supports standard SHA-1 Git repositories.
- **Single-Worktree Scope:** Analyzes the target worktree specified. Linked worktrees sharing object storage are traversed in the context of the target worktree's `HEAD`.
- **Heuristic Boundaries:** Entropy and context scoring minimize false positives, but cannot substitute for cryptographic proof of key validity.

---

## 17. Quick Start & Demo Walkthrough

Follow these steps to demonstrate GitForensics on a repository in under 2 minutes:

### 1. Build the Binary

**Linux / macOS:**
```bash
make build
```

**Windows (PowerShell) or without `make`:**
```powershell
go build -o bin/gitforensics ./cmd/gitforensics
```

The compiled standalone binary is placed at `bin/gitforensics` (or `bin\gitforensics.exe` on Windows when using the default output name).

### 2. Run a Full Forensic Scan
```bash
./bin/gitforensics scan /path/to/target-repository
```
GitForensics will discover the repository, parse loose and packfile storage, compute reachability, detect secrets, and present an ANSI-formatted exposure table.

### 3. Output Machine-Readable JSON
```bash
./bin/gitforensics scan /path/to/target-repository --json
```
Produces an atomic, schema-compliant JSON document on `stdout` suitable for CI/CD pipelines and SIEM ingestion.

### 4. Explain a Specific Finding
```bash
./bin/gitforensics explain <finding-id> --repo /path/to/target-repository
```
Resolves the finding by 16-hex short ID or 64-hex SHA-256 digest, providing immediate forensic context and remediation instructions based on whether the credential is `ACTIVE`, `HISTORICAL`, or `ZOMBIE`.

### 5. Filter by Minimum Confidence Tier
```bash
./bin/gitforensics scan /path/to/target-repository --min-confidence high
```
Displays only `high` and `critical` confidence findings while preserving exit code `1` if any secrets were identified.
