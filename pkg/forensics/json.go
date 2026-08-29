package forensics

import (
	"encoding/json"
	"fmt"
	"gitforensics/pkg/traversal"
)

// FormatJSON produces a fully buffered, atomic JSON serialization of the ScanReport (§14).
// Invariants enforced:
// 1. `findings`, `coverageGaps`, and `structuralAnomalies` are always JSON arrays (empty `[]` if none, never omitted or null).
// 2. Output is buffered in memory before writing, ensuring no half-formed JSON document is emitted.
// 3. Raw secrets are never included.
func FormatJSON(report *ScanReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("cannot format nil scan report")
	}

	if report.Findings == nil {
		report.Findings = make([]Finding, 0)
	}
	if report.CoverageGaps == nil {
		report.CoverageGaps = make([]CoverageGap, 0)
	}
	if report.StructuralAnomalies == nil {
		report.StructuralAnomalies = make([]traversal.StructuralAnomaly, 0)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	// Add trailing newline
	data = append(data, '\n')
	return data, nil
}
