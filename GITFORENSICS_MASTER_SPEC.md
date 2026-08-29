# GitForensics — Master Specification

**Hackathon:** Zero Dependency | 72-Hour Hackathon
**Track:** E — Security & Crypto Utilities
**Language:** Go 1.27
**Runtime dependencies:** 0 third-party packages
**Status:** Pre-kickoff planning specification — no project implementation code

---

## 0. Mission

GitForensics is a read-only Git history forensic scanner that finds secrets committed, deleted, rewritten, or orphaned in a repository and explains whether the underlying Git object remains recoverable.

> **One-line pitch:** GitForensics finds secrets that were committed, deleted, rewritten, or orphaned in a Git repository — and proves, from the raw object storage itself, whether they're still recoverable.

Primary product distinction:

- not a Git replacement
- not a generic checkout-only secret scanner
- not an AI security product
- not a web application
- not a Git client
- read-only forensic analysis of Git object storage

Headline user-facing states:

- **ACTIVE** — matching blob is reachable from the supplied worktree's current HEAD.
- **HISTORICAL** — matching blob is no longer in current HEAD, but is reachable from another current ref.
- **ZOMBIE** — matching blob is physically present in object storage but unreachable from current refs.

Additional internal coverage state:

- **UNRESOLVED PACK-ONLY** — referenced object cannot currently be inspected because pack support is missing/unsupported/failed. This is never classified as ZOMBIE.

---

## 1. Hackathon Rulebook Constraints

The official event context says:

- runtime dependency manifest must be empty
- Go means standard library only; no third-party runtime modules
- no vendored third-party source used to fake an empty manifest
- project code must be written during the 72-hour hackathon
- planning, research, documentation reading, fixture design, and AI prompt preparation are allowed beforehand
- public GitHub repository required at submission
- one-command build required
- README.md required
- STDLIB.md required
- tests required
- dependency proof required
- 5-minute demo required
- AI coding assistants are allowed and expected

The project must never invoke the Git executable at runtime.

Forbidden runtime dependencies include:

- go-git
- libgit2 or bindings
- Git subprocesses through os/exec
- cloud APIs
- LLM APIs
- any third-party Go module
- copied/vendored external library source

A local Git executable may be used **only as a development-time oracle for generating trusted test fixtures**, never by GitForensics itself. The final test suite must run without Git installed.

---

## 2. Product Architecture

```text
GitForensics CLI
       |
       v
Repository Discovery
       |
       v
HEAD + Ref Resolution
       |
       v
Object Store Abstraction
   /                  \
  v                    v
Loose Reader       Pack Reader
(zlib + SHA-1)     (Tier 1/2)
  \                    /
   \                  /
    -------> Object <---------
              |
       Commit / Tree / Blob
              |
              v
    Reachability + Dangling
              |
              v
       Secret Detection
              |
              v
   Exposure Classification
              |
              v
      Finding Assembly
              |
              v
         CLI / JSON
```

### Canonical abstraction boundary

Everything above the object-store layer consumes one normalized object representation, conceptually:

```text
Object {
    Type
    Size
    Payload
    ID
}
```

Traversal, classification, detection, and reporting must not know whether the object came from a loose file or a packfile.

Pack-specific fields such as pack offset, delta depth, or base offset must not leak above the object-store boundary.

---

## 3. Scope Tiers

### P0 — Guaranteed MVP

Must work regardless of packfile progress:

1. repository discovery
2. `.git` directory and linked-worktree `.git` file handling
3. HEAD resolution
4. generic `refs/**` enumeration
5. packed-refs parsing
6. loose object reading
7. zlib decompression
8. Git object envelope parsing
9. SHA-1 verification
10. commit parsing
11. tree parsing
12. blob extraction
13. minimal tag peeling
14. reachable traversal
15. independent dangling-object enumeration
16. ACTIVE/HISTORICAL/ZOMBIE classification
17. secret pattern detection
18. entropy scoring
19. context scoring
20. path scoring
21. false-positive penalties
22. deterministic finding IDs
23. safe redaction
24. CLI
25. JSON output
26. explain command
27. tests and labeled fixtures
28. README.md
29. STDLIB.md
30. dependency-proof.txt
31. THREAT_MODEL.md

### P1 — Competitive Target

Only after P0 passes the hour-40 checkpoint:

1. pack header parsing
2. pack entry header decoding
3. non-delta packed object extraction
4. OFS_DELTA reconstruction
5. recursive OFS_DELTA chains
6. pack checksum verification
7. corruption/truncation handling
8. pack-aware dangling discovery
9. real packed-repository integration tests
10. `objects` introspection subcommand (optional CLI surface, per the original hackathon brief — not required for the P0 MVP; see §13)

### P2 / dangerous / explicitly excluded

Do not spend core sprint time on:

- REF_DELTA
- thin-pack support
- SHA-256 repositories
- pack writing
- Git clone/fetch/push
- Git writes
- GPG signature verification
- full Git porcelain
- full diff engine
- submodule recursion
- web UI/TUI
- secret revocation APIs
- LLM/AI runtime integration
- multi-worktree analysis in one invocation
- heuristic pack resynchronization

---

## 4. Repository Discovery and References

### Discovery

`Discover(path)` walks upward looking for `.git`.

Support:

- `.git/` directory
- `.git` file containing `gitdir: ...` for linked worktrees

For a linked worktree, resolve the correct per-worktree administrative directory so the supplied worktree's HEAD is not confused with another worktree's HEAD.

### Root set

```text
RootSet = { resolve(HEAD) } ∪ { resolve(r) : r ∈ all refs under refs/** }
```

Walk the entire `refs/**` namespace generically rather than allowlisting branches/tags. This naturally includes stash, remotes, custom namespaces, etc.

Reflogs are **not** root-set inputs. They may enrich a later ZOMBIE finding but never affect classification.

### HEAD

Supported forms:

- `ref: refs/...`
- detached 40-hex object ID
- unborn branch (valid, no root contribution)

Use bounded symbolic-ref resolution with a visited-ref set and a maximum depth of 10.

Malformed HEAD is a structural anomaly, not a whole-scan fatal error.

### Loose refs

Each ref contains either:

- a 40-hex OID
- a symbolic `ref: ...`

Malformed individual refs are recorded and skipped without aborting other refs.

### packed-refs

Support:

- comment lines
- `<oid> <refname>` entries
- optional `^<peeled-oid>` lines
- loose ref takes precedence over stale packed entry
- malformed individual lines are recorded and skipped

### Tags

Full tag semantic parsing is out of scope.

Minimal carve-out:

- if a ref points at a tag object, inspect only its first `object <oid>` line
- follow tag-to-tag references with the same depth/cycle guard
- no tagger/message/signature verification

---

## 5. Loose Git Objects

### Path

```text
.git/objects/<first 2 hex chars>/<remaining 38 hex chars>
```

Validate OIDs before path construction:

- exactly 40 lowercase hex characters
- no uppercase
- no non-hex
- no wrong length

Object-store enumeration ignores unrelated names such as `info` and `pack`.

### Compression

Loose objects are zlib streams.

Use `compress/zlib`.

Do not use raw `compress/flate` as the outer format.

### Envelope

After decompression:

```text
<type> SP <ascii-decimal-size> NUL <payload>
```

Types:

- blob
- tree
- commit
- tag

The envelope parser recognizes `tag` as valid even though full tag semantics are out of scope.

### Size rules

- ASCII decimal digits only
- no sign
- no leading `+`
- `0` is canonical; `00`, `000`, etc. are malformed
- bounded integer parsing with explicit overflow error
- declared size must equal payload length exactly

Named errors:

- `ErrInvalidZlibStream`
- `ErrTruncatedZlibStream`
- `ErrZlibChecksumFailed`
- `ErrMissingHeaderTerminator`
- `ErrUnknownObjectType`
- `ErrMalformedSize`
- `ErrTruncatedPayload`
- `ErrTrailingPayloadData`
- `ErrObjectTooLarge`

### Trailing file bytes after zlib EOF

**LOCKED POLICY: lenient + recorded.**

A valid zlib stream followed by extra file bytes does not invalidate the object. Record the exact trailing-byte count as metadata/anomaly information.

Do not determine the boundary using naive `bytes.Reader.Len()` after decompression. Use a reader design that tracks exact zlib consumption.

### SHA-1 verification

OID calculation is:

```text
SHA1("<type> <size>\0" + payload)
```

Hash the entire decompressed envelope, not only payload.

On mismatch:

- do not crash the scan
- retain object data
- set `IntegrityMismatch`
- retain expected and computed hashes
- let higher layers report it as structural/forensic metadata

### Object reader design

Use a minimal custom reader that can precisely account for bytes consumed by the zlib stream. The current planning choice is single-byte delivery to guarantee exact boundary tracking.

This deliberately favors correctness over loose-object throughput and must be documented honestly.

---

## 6. Tree Parsing

Tree payload is binary:

```text
<mode-ascii> SP <name-bytes> NUL <20 raw OID bytes>
```

repeated to exact payload exhaustion.

**Invariant:** the 20-byte OID following each entry's NUL is always raw binary. It must never be parsed, compared, or logged as text — hex-encode only at display time. Treating it as a string anywhere upstream is a realistic bug class, not a style nit, and is worth its own defensive test.

### Mode handling

- `40000` → subtree
- `100644` → regular file
- `100755` → executable file
- `120000` → symlink
- `160000` → gitlink/submodule

**Note:** `40000` is written with no leading zero, even though its conceptual octal value is `040000`. This is a genuine Git-format quirk, not a typo to "fix" to 6 digits — implementations and reviewers should treat 5-character mode fields as expected, not suspicious.

Unknown numeric modes are structurally parseable and are flagged semantically as `UnknownMode`.

### Names

Treat names as opaque bytes; do not assume UTF-8.

Structural parseability and semantic path safety are separate.

Unsafe names such as:

- empty
- `.`
- `..`
- names containing `/`

are retained as parsed entries and marked with `NameSafetyFlag` rather than discarded.

Traversal must never use those unsafe names to construct filesystem paths.

**Invariant:** `NameSafetyFlag` affects path construction only. The entry's OID is still included in reachable/dangling traversal exactly like any other entry — refusing to traverse into it would create a reachability blind spot, which is a worse outcome than refusing to build a path string from an unsafe name.

### Symlinks

Never dereference or follow.

Scan symlink blob bytes as opaque content when applicable.

### Gitlinks

Never recurse into the referenced external repository.

Record the referenced SHA as a boundary marker if useful.

No filesystem/network access for submodule traversal.

### Canonical ordering

Parser does not reject out-of-order or duplicate names. Record `IsCanonicallySorted` and let the semantic layer flag anomalies.

### Hard parse failures

- missing mode/name framing
- malformed mode field
- incomplete name framing
- fewer than 20 raw SHA bytes remaining

Relevant errors:

- `ErrTreeEntryMissingSeparator`
- `ErrTruncatedTreeEntry`
- `ErrTreeEntryMalformedMode`

---

## 7. Commit Parsing

Header structure:

```text
tree <40-hex>
parent <40-hex>            # zero or more
...
author <name> <email> <ts> <tz>
committer <name> <email> <ts> <tz>
<other headers>

<opaque message bytes>
```

### Rules

- `tree` must exist and be first
- parent count can be zero, one, or many
- merge and octopus commits are first-class
- author and committer each appear exactly once
- parse identity from right-side timestamp/timezone boundaries
- timezone must be `+HHMM` or `-HHMM`
- generic continuation lines begin with one leading space
- continuation handling is generic, not `gpgsig`-specific
- capture other headers opaquely
- no GPG signature verification
- message bytes remain opaque

### Timestamp rule

**LOCKED: hard-fail.**

Malformed or overflowed author/committer timestamp:

```text
ErrCommitMalformedTimestamp
```

No default/zero substitution.

Higher layers may preserve the malformed commit as a structural anomaly, but no timeline data may be derived from it.

### Commit errors

Relevant errors include:

- `ErrCommitMissingTree`
- `ErrCommitMalformedTreeRef`
- `ErrCommitMalformedParentRef`
- `ErrCommitMissingAuthor`
- `ErrCommitMissingCommitter`
- `ErrCommitDuplicateAuthor`
- `ErrCommitDuplicateCommitter`
- `ErrCommitMalformedAuthorLine`
- `ErrCommitMalformedCommitterLine`
- `ErrCommitMalformedTimestamp`
- `ErrCommitMalformedTimezone`
- `ErrCommitMissingMessageSeparator`
- `ErrCommitMalformedHeaderLine`

---

## 8. Reachability and Dangling Discovery

These are **two separate algorithms**.

### Reachable traversal

Start from:

- supplied worktree HEAD
- every ref under `refs/**`

Walk:

```text
commit → parents
commit → tree
 tree → subtree
 tree → blob
```

Use independent visited sets:

- `visitedCommits`
- `visitedTrees`
- `visitedBlobs`

**Invariant:** these visited sets are a correctness requirement, not a performance optimization. A well-formed Merkle DAG cannot contain a true cycle, but §5's locked lenient hash-mismatch handling (an object is returned by its path-derived ID even when its computed hash does not match) means this project's object store is not cryptographically pinned to content. A corrupted or hostile repository could therefore present an engineered cycle that would be structurally impossible in an honest store. Memoized visited-sets are what actually prevent an infinite loop in that case, independent of any performance benefit they also provide.

Malformed objects stop only the affected branch and are recorded as structural anomalies.

A malformed tree still contributes the parent commit to the reachable set, but nothing below the malformed tree is invented or silently traversed.

### Deterministic traversal

- refs sorted lexicographically
- commit parents kept in stored order
- tree entries kept in stored order
- final sets sorted by OID before JSON serialization

### Dangling discovery

Enumerate all physically discoverable objects from storage, independently from reachability.

```text
Dangling = AllOnDiskObjects - Reachable
```

A malformed dangling object remains visible as an on-disk anomaly rather than disappearing from reporting.

### Worktree scope

**LOCKED: one worktree per invocation.**

Multi-worktree analysis is a documented limitation.

### Reflog

Not part of classification.

Optional P1 enrichment only.

---

## 9. Classification

Build three distinguished blob sets:

```text
HeadReachableBlobs
AllReachableBlobs
AllOnDiskBlobs
```

Then:

```text
ACTIVE     = HeadReachableBlobs
HISTORICAL = AllReachableBlobs - HeadReachableBlobs
ZOMBIE     = AllOnDiskBlobs - AllReachableBlobs
```

Only scanned/resolved blobs participate.

Pack-only unresolved objects never become ZOMBIE.

### Critical unresolved state

If a referenced object exists only in an unsupported/unreadable pack:

```text
UNRESOLVED PACK-ONLY
```

It is neither reachable nor dangling in the classification output until it can actually be resolved.

---

## 10. Secret Detection

### Pipeline

```text
1. Blob selection
2. Candidate extraction
3. Strong pattern layer
4. Signal layer
5. Suppression
6. Finding assembly
```

**Invariant:** exposure state (ACTIVE/HISTORICAL/ZOMBIE/UnresolvedPackOnly) is computed entirely by the reachability/classification layer (§9) and is read-only input to Finding Assembly. No stage of the detection pipeline recomputes, overrides, or is otherwise influenced by classification — the two layers are joined only at the final finding lookup.

### Blob selection

Do not scan unresolved pack-only blobs.

For binary detection:

- use a cheap bounded heuristic
- text blobs use line/token candidates
- binary blobs skip line-oriented extraction
- binary blobs still receive strong raw-byte pattern scanning

Oversize blobs are skipped visibly, never silently.

The size ceiling is a documented tunable constant.

### Candidate extraction

Track:

- absolute byte offset
- 1-indexed line number
- candidate bytes

Invalid UTF-8 must not disable ASCII pattern matching or byte-level entropy analysis.

### Strong patterns

Initial patterns:

- AWS-style access key
- GitHub token prefixes
- Slack token forms
- PEM/private-key headers

Each pattern is individually named and tested.

Do not create one giant unmaintainable alternation.

### Entropy

Use Shannon entropy over bytes, per extracted token.

Initial thresholds are **provisional** and must be tuned against the labeled fixture corpus.

Do not present them as empirically validated before measurement.

### Context

Bounded local window around the candidate.

Initial keywords:

- `api_key`
- `secret`
- `token`
- `password`
- `authorization`
- `private_key`

Use word-ish boundaries.

Context contribution is +20 once per candidate; multiple nearby keywords do not stack.

### Path signals

Sensitive filename bonus: +10.

Test/fixture/example path penalty: -30.

Match full path components, not substrings.

### Confidence

Initial score:

```text
strong pattern        +40 to +45
entropy               +10 / +18 / +25   (provisional)
context               +20
sensitive filename    +10
test/example path     -30
```

Clamp 0–100.

Tiers are locked:

```text
0–39    LOW
40–69   MEDIUM
70–89   HIGH
90–100  CRITICAL
```

Multiple strong-pattern matches on one candidate use the maximum applicable strong-pattern contribution rather than summing repeatedly.

### False positives / evaluation

Maintain a labeled fixture corpus with ground truth.

Measure:

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
```

Report tier-specific precision/recall where useful.

Do not claim external generalization from a self-built corpus.

---

## 11. Finding Identity, Deduplication, and Redaction

### Finding identity

Conceptually:

```text
findingID = first16hex(
    SHA-256(
        blobID || 0x00 || byteOffset || 0x00 || patternOrSignalName
    )
)
```

A full digest may be stored in JSON if useful for automation.

### Dedup rules

- same blob ID + same candidate identity → one finding
- same literal secret in different blob IDs → separate findings
- same blob referenced under multiple paths → one finding with all occurrences preserved
- multiple candidate secrets in one blob → separate findings

### Fingerprint

Use SHA-256 of matched candidate bytes as the secret fingerprint.

Never confuse secret fingerprint with Git object ID.

### Redaction

Raw secret material must never appear in:

- CLI
- JSON
- explain output
- logs
- cache files
- generated artifacts

Normal tokens may use a fixed-mask prefix/suffix representation.

Private-key/PEM findings use **zero-reveal** redaction:

```text
[REDACTED PRIVATE KEY]
```

Do not claim Go securely erases secret bytes from memory. Correct claim:

> Secrets are never intentionally persisted or serialized; candidate data exists transiently during analysis.

Centralize all display redaction through one shared function.

---

## 12. Timeline

The timeline answers:

- earliest observed commit
- removal/no-longer-present point where safely derivable

Use cautious terminology:

- “earliest observed”
- “evidence indicates removal from this lineage”

Never claim:

- global non-existence
- developer intent
- complete remediation
- external exposure did/did not occur

A hard-failed commit timestamp yields no timeline data.

---

## 13. CLI Contract

Required MVP commands:

```bash
gitforensics scan <repo-path>
gitforensics explain <finding-id> --repo <repo-path>
gitforensics version
```

Optional / P1 command (not required for MVP submission):

```bash
gitforensics objects <repo-path>
```

### Flags

```text
--json
--no-color
--quiet
--min-confidence low|medium|high|critical
--repo <path>   # alternative to positional repo path
```

Unknown commands/arguments → exit 2 + usage to stderr.

### Exit codes

```text
0 = successful scan, zero findings
1 = findings present / explain not-found
2 = invalid arguments, invalid repository, malformed finding ID
3 = genuinely unexpected internal/I/O failure
```

A structural anomaly does **not** by itself cause exit 3.

### stdout/stderr

```text
stdout → exactly one final human report OR one complete JSON document
stderr → progress, warnings, diagnostics
```

`--json` stdout must never contain progress text.

Buffer JSON fully before writing so a mid-scan internal failure cannot leave a syntactically truncated document.

### Confidence filtering

Maintain separate concepts:

```text
totalFindingCount
displayedFindingCount
```

`--min-confidence` only changes displayed/serialized findings.

Exit code is based on total findings and is unaffected by display filtering.

---

## 14. JSON Contract

Top-level object:

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "gitforensics", "version": "<semver>" },
  "repository": {},
  "scan": {},
  "summary": {},
  "findings": [],
  "coverageGaps": [],
  "structuralAnomalies": [],
  "fatalError": null
}
```

### Stability

`schemaVersion` uses MAJOR.MINOR semantics.

Within a major version:

- additive optional fields permitted
- field removals/type changes require a major bump

Preserve the distinction between:

- field absent
- `null`
- empty array

### Findings

Must include, as applicable:

- finding ID
- confidence score/tier
- pattern/signal
- exposure state
- blob ID
- redacted representation
- fingerprint
- all path/commit occurrences
- timeline
- evidence signals

### Coverage gaps

Always present.

Examples:

```json
{"type":"unresolvedPackOnly", ...}
{"type":"skippedOversizeBlob", ...}
```

### Structural anomalies

Always present.

Examples:

```json
{"type":"malformedCommitTimestamp", ...}
{"type":"symbolicRefCycle", ...}
{"type":"malformedTree", ...}
```

Never hide incomplete verification behind a clean result.

---

## 15. Explain Command

Stateless MVP design:

```bash
gitforensics explain <finding-id> --repo <path>
```

The command reruns the deterministic scan against the current repository state.

No persistent cache/database in MVP.

If the repository changed and the finding cannot be reproduced:

- clear not-found message
- exit 1
- no crash

`explain` must accept both the truncated (16-character) and full finding ID forms. This is a firm requirement, not an optional convenience.

---

## 16. Packfiles

Pack support is P1 and must never be required for the P0 MVP.

### Tier 1

Support:

- `PACK` magic
- version 2
- object count
- entry header type/size decoding
- non-delta objects
- zlib extraction
- object-ID reconstruction from canonical loose envelope

Version 3/unknown versions become visible coverage gaps, not whole-scan fatal failures.

### Tier 2

Support:

- OFS_DELTA
- recursive/chained OFS_DELTA
- delta source/target sizes
- copy operations
- insert operations
- exact bounds checks
- memoized base resolution
- chain depth limits

### Explicitly excluded

- REF_DELTA
- thin packs
- `.idx` parsing
- SHA-256 pack/object support
- pack writing
- heuristic resynchronization

### OFS_DELTA warning

The offset encoding is Git-specific.

For continuation bytes:

```text
value = first & 0x7f
while continuation:
    value = value + 1
    next = read byte
    value = (value << 7) | (next & 0x7f)
```

The base location is:

```text
baseEntryOffset = currentEntryHeaderStart - decodedOffset
```

Do not derive this from generic LEB128 intuition.

### Delta instructions

- size fields use standard 7-bit continuation encoding
- copy instruction uses flag-controlled little-endian offset/size bytes
- insert instruction copies literal bytes
- zero assembled copy size means `65536`
- output size must exactly equal target size
- out-of-bounds copies are errors
- an instruction byte value of `0x00` is invalid/reserved (it would encode an insert of zero literal bytes, which the format never produces) → `ErrInvalidDeltaInstruction`; the delta becomes unresolvable, not a pack-wide halt

### Integrity

Report independently:

```text
Object SHA: VERIFIED / FAILED
Pack integrity: VERIFIED / FAILED / N/A
```

A pack checksum failure does not erase already decoded valid objects, but it must remain visible.

### Named pack errors

| Case | Error | Recoverability |
|---|---|---|
| Bad magic | `ErrNotAPackFile` | Whole-file rejection |
| Unsupported/unknown version | `ErrUnsupportedPackVersion` | Whole-pack coverage gap, other packs/loose objects unaffected |
| Declared object count does not match walkable entries | `PackCountMismatch` | Anomaly, not fatal |
| Type value outside 1–7 (excluding 5) | `ErrInvalidPackEntryType` | Pack-wide halt |
| Entry-header size continuation exceeds safety ceiling | `ErrPackEntrySizeTooLarge` | Pack-wide halt |
| Entry header runs off end of file mid-continuation | `ErrTruncatedPackEntry` | Pack-wide halt |
| Inflated size does not match entry header's declared size | `ErrPackObjectSizeMismatch` | Per-entry recoverable |
| OFS_DELTA offset continuation runs off end of entry/file | `ErrTruncatedOfsDeltaOffset` | Per-entry recoverable |
| OFS_DELTA offset resolves forward, at/past itself, or before pack header | `ErrInvalidOfsDeltaOffset` | Per-entry recoverable → `unresolvedPackOnly`, reason `malformedDeltaBase` |
| Delta base-size field does not match resolved base's actual length | `ErrDeltaBaseSizeMismatch` | Per-entry recoverable → `unresolvedPackOnly`, reason `deltaBaseSizeMismatch` |
| Delta copy offset+size exceeds base object bounds | `ErrDeltaCopyOutOfBounds` | Per-entry recoverable |
| Delta instruction byte is `0x00` (reserved) | `ErrInvalidDeltaInstruction` | Per-entry recoverable |
| Reconstructed object length does not equal declared target size | `ErrDeltaReconstructionSizeMismatch` | Per-entry recoverable |
| Delta stream ends mid-instruction | `ErrTruncatedDeltaInstruction` | Per-entry recoverable |
| Delta stream has leftover bytes after target size reached | `ErrDeltaTrailingInstructionData` | Anomaly, not necessarily fatal |
| Delta chain re-enters an offset already being resolved | `ErrDeltaChainCycleDetected` | Per-entry recoverable |
| Delta chain exceeds configured max depth (§19) | chain-depth-ceiling error | Per-entry recoverable |
| Whole-pack trailing SHA-1 does not match computed checksum | `ErrPackChecksumMismatch` | Pack-level anomaly; already-decoded objects remain valid |
| Invalid type/header destroys ability to locate subsequent entries | `PackTruncatedOrCorrupted` (byte offset recorded) | Pack-wide halt |

### Corruption model

Pack-wide halt:

- invalid type/header that destroys frame alignment
- entry-header truncation

Per-entry recoverable:

- object size mismatch
- delta base mismatch
- delta bounds failure
- delta instruction failure
- unsupported REF_DELTA

Already-decoded objects remain usable.

---

## 17. Deterministic Ordering

- refs: lexicographic
- commit parents: stored order
- tree entries: stored order
- pack files: filename lexicographic
- pack objects: ascending file offset
- findings: confidence tier descending, then ID ascending
- occurrences: commit date ascending, then path
- coverage gaps/anomalies: stable object ID ordering
- serialized object sets: OID ascending

No filesystem enumeration order may leak into user-facing deterministic output.

---

## 18. Testing and Fixtures

### Pre-kickoff fixture preparation (planning-phase only — no GitForensics implementation code)

Before the 72-hour window opens, prepare the following as fixture bytes and expected values only, consistent with the hackathon's own pre-kickoff allowances (planning, research, and fixture design are permitted; project code is not):

- The canonical loose-object and tree hash vectors listed under "Loose-object envelope test vectors" and "Tree/commit test vectors" below — these are well-known constants, safe to record now.
- At least one real, dev-time-Git-oracle-generated pack containing a **multi-byte OFS_DELTA offset** (Pack fixture 9, below). Capture the exact raw bytes, the expected decoded offset (computed independently by hand using the locked `+1`-per-continuation-byte algorithm in §16), and the expected reconstructed object IDs via `git cat-file`. This is the single highest-value test in the packfile spec and must be ready in advance — not generated for the first time during hour 40–52 pack work under time pressure.
- Any other oracle-derived tree/commit hashes needed for Tree/commit tests 9–10 below.

No project code is written during this phase — only fixture bytes and expected values, captured and ready to hardcode into the test suite once kickoff begins.

### Fixture policy

Do not commit nested `.git` repositories as fixtures.

Generate deterministic fixture objects programmatically where practical.

A local Git installation is allowed as a **dev-time oracle only** to produce trusted hashes/raw bytes/known-good packed examples before implementation tests are frozen.

Final test execution must not require Git.

### Loose-object envelope test vectors

Unit-level envelope tests, independent of the higher-level P0 fixture scenarios below.

1. Canonical empty blob (`blob 0\0`, zero-length payload) — computed SHA-1 must equal `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`.
2. Known non-empty blob (`blob 13\0test content\n`) — computed SHA-1 must equal `d670460b4b4aece5915caf5c68d12f560a9fe3e4` (published Pro Git reference value).
3. Missing NUL terminator → `ErrMissingHeaderTerminator`.
4. Non-numeric size field (`blob abc\0hello`) → `ErrMalformedSize`.
5. Size mismatch, both directions, as two separate subtests: declared > actual → `ErrTruncatedPayload`; declared < actual → `ErrTrailingPayloadData`.
6. Unknown type token (`widget 4\0data`) and a near-miss (`blobb 4\0data`) → both `ErrUnknownObjectType`; confirms exact-match, not prefix-match.
7. Corrupted zlib stream: bit-flip mid-stream → `ErrInvalidZlibStream`/`ErrZlibChecksumFailed`; separately, truncated mid-stream → `ErrTruncatedZlibStream`. Distinguished, not merged into one assertion.
8. Path/hash mismatch → object still returned, `IntegrityMismatch = true`, both expected and computed hashes populated, no error raised.
9. Size-field overflow (40-digit decimal) → `ErrMalformedSize`; explicitly assert no panic.
10. Trailing bytes after valid zlib end → parse succeeds, object returned, trailing-byte count recorded as metadata (lenient+recorded policy).
11. `blob 0\0` — canonical empty payload, standalone assertion (`Type == blob`, `Size == 0`, `len(Payload) == 0`).
12. `blob 0\0x` → `ErrTrailingPayloadData` (size declared 0, one stray payload byte present).
13. `blob 1\0` → `ErrTruncatedPayload` (size declared 1, zero payload bytes present).
14. `blob 00\0` → `ErrMalformedSize` (non-canonical leading-zero size encoding; must not be silently treated as size 0).

### Tree/commit test vectors

**Tree:**

1. Single-entry tree (`100644` mode) — correct mode/name/raw-OID parsed.
2. Multi-type tree (`100644`, `100755`, `40000`, `120000`, `160000` entries in one payload) — all five parse correctly; gitlink entry triggers zero filesystem/network calls (assert via mock).
3. Truncated mid-name (no NUL before payload ends) → `ErrTruncatedTreeEntry`.
4. Truncated with fewer than 20 bytes remaining after NUL → `ErrTruncatedTreeEntry`.
5. Entry name containing `/` → parse succeeds, entry present, `NameSafetyFlag == EmbeddedSlash` — not an error (see §6 Names).
6. Empty mode field (SP as first byte) → `ErrTreeEntryMalformedMode`.
7. Canonical empty tree (zero-length payload) — zero entries, no error; computed hash must equal `4b825dc642cb6eb9a060e54bf8d69288fbee4904`.
8. Deliberately out-of-order entries — parse succeeds, `IsCanonicallySorted == false`, no error.

**Commit:**

9. Minimal root commit (tree + author + committer + blank line + message, zero parents) — `ParentSHAs` is an empty, non-nil slice; hash captured via the dev-time Git oracle for exact-value assertion.
10. Merge commit, two parent lines — both captured, in stored order.
11. Commit missing `tree` header (starts with `author`) → `ErrCommitMissingTree`.
12. `gpgsig` header spanning two lines via leading-space continuation, followed by normal `author`/`committer` — multi-line value reconstructs correctly, header parsing resumes normally afterward.
13. Headers present but no blank-line separator before payload ends → `ErrCommitMissingMessageSeparator`.
14. Malformed (non-numeric) timestamp in the author line → `ErrCommitMalformedTimestamp`, and the entire commit parse fails, not just that one field (locked hard-fail rule).

### Mandatory P0 fixture scenarios

1. clean repo
2. active secret
3. historical secret
4. zombie/dangling secret
5. merge history
6. packed refs
7. symbolic-ref cycle
8. malformed object branch
9. gitlink boundary
10. unsafe tree name
11. shared tree/blob dedup
12. unresolved pack-only object
13. decoy secrets
14. binary blob with strong secret pattern
15. oversize blob

### Detection fixtures

- real AWS-shaped candidate
- PEM private key
- historical rotated credential
- fixture-path false positive
- benign high-entropy data
- context-window boundary
- word-boundary case
- duplicate blob/multiple paths
- same text/different blob IDs
- redaction corpus-wide guarantee

### Output contract tests

1. Exit code 0 on a clean repo — `findings: []`; coverage-gaps/anomalies sections present and explicitly empty.
2. Exit code 1 regardless of `--min-confidence` filtering — a repo with one LOW finding, run with `--min-confidence critical` (which hides it from display), still exits 1. Highest-priority exit-code test.
3. stdout/stderr purity under `--json` — stdout parses as exactly one well-formed JSON document; progress output (if not `--quiet`) appears only on stderr.
4. Atomic JSON on a simulated fatal error — stdout is either empty or one complete, valid JSON document with `fatalError` populated; never a truncated/invalid fragment.
5. Deterministic finding ID across repeated scans of an unmodified repo — identical `id` values across runs.
6. `explain` round-trip — a finding ID extracted from `scan --json` resolves via `explain --json` to a field-for-field identical Finding object.
7. `explain` with a malformed ID → exit 2, clear stderr message, no stdout JSON attempt.
8. `explain` after repo mutation — either the finding still resolves (content-addressed, untouched object) or the documented "not found in current state" message is returned, exit 1, no crash.
9. Raw secret never appears in any rendered output, corpus-wide — run the full labeled fixture corpus through `scan --json`, `scan` (human), and `explain`; assert the raw matched secret substring appears in none of the captured output.
10. PEM zero-reveal enforced specifically — rendered form is exactly `[REDACTED PRIVATE KEY]` with zero characters of the original key material present, in both human and JSON output.
11. Coverage gaps and anomalies always present — a fully clean, fully resolvable repo still shows both sections/arrays, explicitly empty, never omitted.
12. Deterministic ordering, cross-run — `findings` array and `occurrences` within each finding are in byte-identical order across repeated runs.
13. Field-presence discipline — a commit with a hard-failed timestamp produces a finding whose `timeline` field is explicitly `null` in JSON, not an object with null sub-fields, not omitted.

### Pack fixtures

1. valid PACK v2
2. bad magic
3. unsupported version
4. count mismatch
5. non-delta packed blob
6. corrupted type/header
7. per-entry size mismatch
8. single-byte OFS offset
9. multi-byte OFS offset with `+1` quirk
10. invalid base offset
11. zero-size copy => 65536
12. insert boundaries 1 and 127
13. invalid delta instruction
14. copy out-of-bounds
15. recursive OFS chain
16. cycle defense
17. chain depth ceiling
18. valid pack checksum
19. corrupted checksum
20. REF_DELTA presence
21. multiple-pack deterministic enumeration
22. unresolved pack-only not classified as ZOMBIE

---

## 19. Safety / Performance Circuit Breakers

All values are **provisional safety constants until exercised by tests**.

Initial candidates:

- symbolic-ref/tag peel depth: 10
- tree recursion depth: 1000
- max pack entry-header continuation length: ~9
- max OFS continuation length: ~10
- max delta chain depth: ~50
- max object/blob size: documented shared ceiling
- max objects scanned: documented configurable ceiling
- max pack file size: documented configurable ceiling

If a circuit breaker trips:

- stop the affected branch/work unit safely
- record a visible anomaly/coverage gap
- never hang
- never silently classify incomplete data as clean

---

## 20. Documentation Deliverables

### README.md

Sections:

1. one-line pitch
2. problem statement
3. why GitForensics is different
4. architecture
5. supported formats
6. ACTIVE/HISTORICAL/ZOMBIE explanation
7. coverage gaps
8. read-only guarantee
9. worktree limitation
10. reflog boundary
11. packfile limitations
12. honest limitations
13. build/test/verification commands
14. reproducible build procedure
15. claims we do not make
16. demo instructions

### STDLIB.md

Only real substitutions from shipped code.

Potential categories:

- Git object parsing replacing Git libraries
- zlib
- SHA-1/SHA-256 primitives
- CLI
- logging
- JSON
- binary decoding
- entropy calculation
- file traversal
- testing
- ANSI output

Also document:

- dev-only Git oracle
- trailing-byte interpretation
- design trade-offs
- performance trade-offs

### dependency-proof.txt

Generated fresh at submission.

Include:

```bash
cat go.mod
go list -m all
go list -deps ./...
go vet ./...
go build ./...
go mod verify
```

Do not hand-invent the output.

### THREAT_MODEL.md

Cover:

- intended protection scope
- out-of-scope exposure channels
- trust boundary
- no network calls
- adversarial repository parsing
- resource limits
- redaction
- false-positive/negative posture
- internal fixture-corpus limitations

---

## 21. Build and Reproducibility

Single documented build:

```bash
make build
```

Produce:

```text
./bin/gitforensics
```

Tests:

```bash
make test
```

If pursuing the +5 reproducible-build bonus:

```bash
CGO_ENABLED=0 GOFLAGS=-trimpath go build -o bin/gitforensics ./cmd/gitforensics
```

Build twice and compare SHA-256 hashes.

Only claim reproducibility after empirical verification.

---

## 22. Bonus Strategy

Priority:

1. STDLIB Log +3 — likely easy if implementation naturally contains 10+ real substitutions
2. Package Killer +3 — frame GitForensics as a focused alternative to the Git-library layer for historical exposure analysis, without claiming to replace entire security platforms
3. Reproducible Build +5 — pursue if it does not disturb core functionality
4. Single File +5 — pursue only if it falls out naturally; never damage code quality to achieve it

Never sacrifice P0/P1 reliability for bonuses.

---

## 23. Demo Strategy

Opening line:

> **The repository is clean. The credential isn't.**

Five-minute sequence:

### 0:00–0:30
Show clean current working tree / HEAD.

### 0:30–1:20
Run:

```bash
gitforensics scan ./demo-repo
```

### 1:20–2:45
Highlight a ZOMBIE finding:

- exposure state
- path-at-time-of-reference
- earliest observed commit
- removal point
- confidence/evidence

### 2:45–3:30
Show raw Git object bytes / decoded object evidence.

### 3:30–4:15
Show explainable score breakdown and redaction.

### 4:15–4:40
Show JSON/CI usage.

### 4:40–5:00
Show:

- empty go.mod
- dependency proof
- tests
- STDLIB.md

Do not waste the five minutes on generic slides.

---

## 24. Explicit Non-Claims

Never claim:

- detects all secrets
- 100% precision/recall
- global non-existence of a secret
- complete remediation from deletion
- complete Git pack support
- support for all Git repositories
- complete SHA-256 Git support
- memory zeroization guarantees
- replacement of all Git security products
- knowledge of developer intent

Use evidence-based language such as:

- earliest observed
- evidence indicates
- recoverable from this object store
- unsupported coverage

---

## 25. Hour-40 Gate

At hour 40, the following must work:

```text
✓ repository discovery
✓ HEAD/ref resolution
✓ loose objects
✓ zlib
✓ SHA-1 verification
✓ commit parsing
✓ tree parsing
✓ blob extraction
✓ reachable traversal
✓ dangling discovery
✓ ACTIVE/HISTORICAL/ZOMBIE
✓ secret detection
✓ explain
✓ JSON
✓ tests
```

### If all pass

Begin/continue P1 packfile work.

### If any critical P0 item is still unstable

Stop packfile work.

Stabilize P0, tests, docs, and demo.

This gate is absolute.

---

## 26. 72-Hour Execution Plan

### Day 1 — Storage/Core

**0–2h**
- scaffold
- build/test baseline
- repo discovery

**2–6h**
- loose reader
- zlib
- OID verification

**6–10h**
- tree parser
- blob handling

**10–14h**
- commit parser
- ref resolution

**14–18h**
- packed-refs
- tag peeling

**18–21h**
- reachable traversal
- dedup/cycle safeguards

**21–23h**
- independent dangling-object discovery (separate enumeration pass, per §8 — must not be implemented as a byproduct of reachable traversal)

**23–24h**
- first end-to-end fixture scan

### Day 2 — Forensics/Core MVP

**24–28h**
- secret patterns

**28–32h**
- entropy/context/path scoring

**32–36h**
- ACTIVE/HISTORICAL/ZOMBIE
- timeline

**36–40h**
- CLI
- JSON
- explain
- redaction
- tests

### HARD CHECKPOINT — HOUR 40

P0 must be solid.

### Day 2/3 — Competitive Layer

**40–46h**
- PACK header
- entry headers
- non-delta objects

**46–52h**
- OFS_DELTA
- delta reconstruction

**52–56h**
- recursive chains
- memoization
- corruption handling

### Day 3 — Freeze and Package

**56h**
- hard scope freeze

**56–60h**
- integration
- performance
- final tests

**60–64h**
- README
- STDLIB
- threat model
- dependency proof

**64–68h**
- demo fixture
- rehearsal

**68–70h**
- record demo

**70–72h**
- clean build
- dependency audit
- final tests
- public repo
- submission

---

## 27. AUDIT Checklist

### Rule compliance

- [ ] zero third-party runtime modules
- [ ] no vendored external source
- [ ] no Git subprocess
- [ ] no cloud/LLM runtime dependency
- [ ] code committed only after kickoff
- [ ] one-command build
- [ ] public repository
- [ ] OSI-approved license

### Parser correctness

- [ ] full-envelope SHA-1
- [ ] exact tree raw-SHA handling
- [ ] commit timestamp hard-fail
- [ ] generic header continuation
- [ ] merge commit support
- [ ] symlink safety
- [ ] gitlink safety
- [ ] malformed-input resilience

### Forensics correctness

- [ ] reachable/dangling algorithms remain separate
- [ ] unresolved pack-only != ZOMBIE
- [ ] ACTIVE/HISTORICAL/ZOMBIE sets disjoint
- [ ] path occurrences preserved
- [ ] finding IDs deterministic
- [ ] timeline uses cautious wording
- [ ] shared object storage never causes cross-worktree HEAD attribution (linked-worktree `.git` file resolves to its own admin directory, not another worktree's)

### Secret safety

- [ ] raw secret never serialized
- [ ] centralized redaction
- [ ] PEM zero-reveal
- [ ] entropy thresholds tested
- [ ] precision/recall measured on labeled fixtures
- [ ] same blob ID = one finding
- [ ] different blob IDs = separate findings, even if literal secret text is identical
- [ ] unresolved pack-only blobs are never scanned by the detection layer (distinct from never being classified ZOMBIE)
- [ ] entropy alone cannot produce a MEDIUM+ score unless the validated (post-fixture) scoring model demonstrably proves otherwise

### Pack correctness

- [ ] pack object canonical OID reconstruction
- [ ] OFS_DELTA `+1` quirk tested
- [ ] 65536 copy special case tested
- [ ] delta bounds checked
- [ ] recursion bounded
- [ ] memoization present
- [ ] pack checksum independently reported

### Output correctness

- [ ] stdout/stderr separation
- [ ] JSON always syntactically complete
- [ ] deterministic ordering
- [ ] total vs displayed findings separated
- [ ] coverage gaps always visible
- [ ] structural anomalies always visible

---

## 28. Implementation Governance

Every implementation change made during the hackathon must reference the relevant master-spec section and/or named invariant it implements (e.g. a commit message or code comment citing "§7, commit timestamp hard-fail" or "Invariant: unsafe tree-entry names still traversed, §6").

If an implementation decision must deliberately deviate from this document — because a constraint was discovered that planning didn't anticipate, or because time pressure forces a documented trade-off — the deviation must be **explicitly recorded** (in STDLIB.md, README.md's honest-limitations section, or a dated note in this document) rather than silently diverging from what's written here. A silent deviation makes this document actively misleading rather than merely incomplete, which is worse than not having written it down at all.

This document is the source of truth unless and until a recorded deviation says otherwise.

---

## 29. Final Scope Contract

If a feature is not listed in P0 or P1, it is not part of the required submission.

If a new feature threatens a P0/P1 milestone, cut the new feature.

If the choice is between:

```text
more features
```

and:

```text
correctness + tests + honest limitations + strong demo
```

choose the second.

**The objective is not to implement all of Git. The objective is to implement enough of Git's read-only object model to make historical secret exposure forensics real, provable, and zero-dependency.**
