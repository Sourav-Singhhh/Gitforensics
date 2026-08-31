# GitForensics — Standard Library Substitution Ledger

**Document Purpose:** Complete accounting of how GitForensics implements a focused Git history forensic analysis engine within the supported Git object-format scope with **zero third-party runtime dependencies**, relying exclusively on the Go standard library.

---

## 1. Zero-Dependency Architectural Summary

| Functional Subsystem | Traditional Third-Party Package | Go Standard Library Replacement | Implementation File(s) |
| :--- | :--- | :--- | :--- |
| **Git Object Decoding** | `github.com/go-git/go-git/v5` / `libgit2` | `bytes`, `compress/zlib`, `crypto/sha1`, `fmt`, `io` | [`pkg/object/loose.go`](pkg/object/loose.go) |
| **Git Tree Parsing** | `github.com/go-git/go-git/v5` | `bytes`, `encoding/hex`, `fmt`, `strconv` | [`pkg/parser/tree.go`](pkg/parser/tree.go) |
| **Git Commit Parsing** | `github.com/go-git/go-git/v5` | `bytes`, `fmt`, `strconv`, `strings`, `time` | [`pkg/parser/commit.go`](pkg/parser/commit.go) |
| **PACK v2 Container Parsing** | `github.com/go-git/go-git/v5/plumbing/format/packfile` | `bytes`, `compress/zlib`, `crypto/sha1`, `encoding/binary`, `encoding/hex`, `io` | [`pkg/repository/pack.go`](pkg/repository/pack.go) |
| **OFS_DELTA Reconstruction** | `github.com/go-git/go-git/v5` | `bytes`, `encoding/binary`, `fmt`, `io` | [`pkg/repository/pack.go`](pkg/repository/pack.go) |
| **Graph Reachability & DAG** | `gonum.org/v1/gonum/graph` | Native Go `map[string]bool` visited sets, recursion bounding | [`pkg/traversal/reachability.go`](pkg/traversal/reachability.go) |
| **Physical Dangling Discovery** | External `git fsck` / `git rev-list --lost-found` | `path/filepath`, `os.ReadDir`, `bytes` | [`pkg/traversal/dangling.go`](pkg/traversal/dangling.go) |
| **Secret Pattern Matching** | `github.com/trufflesecurity/trufflehog` / `gitleaks` | `regexp`, `strings`, `bytes` | [`pkg/detect/detector.go`](pkg/detect/detector.go) |
| **Shannon Entropy Calculation**| `github.com/montanaflynn/stats` | `math.Log2`, native byte frequency arrays | [`pkg/detect/entropy.go`](pkg/detect/entropy.go) |
| **CLI Argument Parsing** | `github.com/spf13/cobra` / `github.com/urfave/cli` | Custom state-machine parser in pure Go | [`cmd/gitforensics/main.go`](cmd/gitforensics/main.go) |
| **JSON Serialization** | `github.com/json-iterator/go` | `encoding/json` with indented formatting | [`pkg/forensics/json.go`](pkg/forensics/json.go) |
| **Terminal Formatting** | `github.com/fatih/color` / `github.com/olekukonko/tablewriter` | Native ANSI escape sequences, `fmt.Fprintf` column alignment | [`pkg/forensics/human.go`](pkg/forensics/human.go) |
| **Cryptographic Hashing** | `golang.org/x/crypto` | `crypto/sha1`, `crypto/sha256`, `encoding/hex` | [`pkg/object/loose.go`](pkg/object/loose.go), [`pkg/forensics/finding.go`](pkg/forensics/finding.go) |
| **Fuzz & Contract Testing** | `github.com/stretchr/testify` | Native `testing`, `testing.F` fuzz engines | [`pkg/object/loose_test.go`](pkg/object/loose_test.go), [`cmd/gitforensics/contract_test.go`](cmd/gitforensics/contract_test.go) |

---

## 2. Deep Dive: Key Standard Library Substitutions

### 2.1 Git Object Envelope & Loose Storage (`pkg/object`)
- **Third-Party Avoided:** `go-git/plumbing`, `libgit2` bindings.
- **Go Stdlib Used:** `compress/zlib`, `crypto/sha1`, `bytes`, `io`.
- **Implementation:** Custom decoder reads the `<type> <size>\x00<payload>` envelope directly from zlib streams. Verifies that the computed SHA-1 hash strictly matches the path-derived 40-hex object ID.
- **Safety Mitigation:** Enforces `DefaultMaxObjectSize` (64 MiB) via `io.LimitReader` to defend against decompression bombs.

### 2.2 PACK v2 Container & Delta Engine (`pkg/repository`)
- **Third-Party Avoided:** C-based `libgit2` pack decoders.
- **Go Stdlib Used:** `encoding/binary`, `compress/zlib`, `crypto/sha1`, `bytes`, `io`.
- **Implementation:** Parses 12-byte PACK v2 header, variable-length LEB128 entry headers, and zlib-inflated byte streams. Tracks exact stream boundaries with a custom `countingByteReader`. Reconstructs chained `OFS_DELTA` objects using Git's exact `((offset + 1) << 7) | (b & 0x7F)` continuation formula and `COPY` instruction size $0 \rightarrow 65536$ rule.
- **Safety Mitigation:** Recursive chain evaluation tracks in-flight offsets in a visited set (`ErrDeltaChainCycleDetected`) and bounds recursion depth to 50 (`ErrMaxDeltaDepthExceeded`).

### 2.3 Graph Reachability & Three-Way Classification (`pkg/traversal`)
- **Third-Party Avoided:** Complex graph database libraries or `gonum/graph`.
- **Go Stdlib Used:** `sort`, standard Go `map[string]bool` sets, slices.
- **Implementation:** Traverses commit histories and tree hierarchies using three strictly isolated visited sets (`HeadReachable`, `AllReachable`, `AllOnDisk`). Evaluates set differences to produce deterministic `ACTIVE`, `HISTORICAL`, and `ZOMBIE` partitions in $O(N)$ time. For `ZOMBIE` loose objects that have no connecting commit in reachable reference graphs, findings explicitly set `"occurrences": null` and `"timeline": null` in accordance with the JSON specification.

### 2.4 Multi-Signal Secret Detection Engine (`pkg/detect`)
- **Third-Party Avoided:** `trufflehog`, `gitleaks`, third-party rule engines.
- **Go Stdlib Used:** `regexp`, `math`, `bytes`, `strings`.
- **Implementation:** Pre-compiled standard `regexp.Regexp` patterns combined with a custom Shannon entropy calculator:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
  Evaluates adjacent context windows (80 bytes) and weighted file path segments without dynamic Cgo dependencies.

### 2.5 Centralized Redaction & Output Discipline (`pkg/forensics`)
- **Third-Party Avoided:** Third-party sanitization libraries.
- **Go Stdlib Used:** `bytes`, `strings`, `encoding/json`, `fmt`.
- **Implementation:** Masks high-entropy tokens and enforces a strict zero-reveal policy for private keys (`[REDACTED PRIVATE KEY]`), guaranteeing that raw credentials never appear in user-facing logs, terminal output, or serialized JSON reports.

---

## 3. Development vs. Runtime Separation

- **Production Code:** 100% pure Go standard library. Zero external dependencies. Zero subprocess invocations.
- **Test Suite:** Uses only native Go standard library testing frameworks (`testing`, `testing.F`).
- **Development-Time Git Oracle:** During development, Git CLI was used strictly as an external oracle to generate trusted binary fixtures. At runtime and during test execution, Git is never required or invoked.

---

## 4. Architectural Trade-offs

1. **Memory vs. Disk Streaming:** By holding decoded object envelopes in memory up to safety limits (64 MiB), GitForensics achieves near-instant graph traversal without intermediate disk I/O.
2. **Selective Pack Support (Tier 1 + Tier 2):** Implementing PACK v2 and OFS_DELTA in pure Go covers the vast majority of real-world Git repositories, while transparently flagging unsupported features (e.g. `REF_DELTA`) as coverage gaps rather than failing silently.
3. **Deterministic State:** Implementing custom deterministic sorting across all maps, slices, and finding IDs ensures reproducible forensic audit trails.
