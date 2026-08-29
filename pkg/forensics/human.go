package forensics

import (
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/traversal"
	"io"
)

// ANSI color codes
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
)

// FormatHuman outputs a readable terminal report to w (§13).
func FormatHuman(w io.Writer, report *ScanReport, noColor bool) {
	color := func(code, text string) string {
		if noColor {
			return text
		}
		return code + text + ansiReset
	}

	fmt.Fprintln(w, color(ansiBold+ansiCyan, "=== GitForensics Forensic Scan Report ==="))
	fmt.Fprintf(w, "Repository: %s\n", report.Repository.Path)
	if report.Repository.HeadResolved != "" {
		fmt.Fprintf(w, "HEAD Commit: %s\n", report.Repository.HeadResolved)
	}
	fmt.Fprintf(w, "Scan Duration: %d ms | Blobs Scanned: %d\n\n", report.Scan.DurationMs, report.Summary.TotalBlobsScanned)

	fmt.Fprintln(w, color(ansiBold, "--- Summary ---"))
	fmt.Fprintf(w, "Total Findings: %d (Displayed: %d)\n", report.Summary.TotalFindingsCount, report.Summary.DisplayedFindingCount)
	fmt.Fprintf(w, "  [CRITICAL: %d] [HIGH: %d] [MEDIUM: %d] [LOW: %d]\n\n",
		report.Summary.CriticalFindingsCount,
		report.Summary.HighFindingsCount,
		report.Summary.MediumFindingsCount,
		report.Summary.LowFindingsCount,
	)

	if len(report.Findings) == 0 {
		fmt.Fprintln(w, color(ansiGreen, "No findings detected matching current filters."))
	} else {
		fmt.Fprintln(w, color(ansiBold, "--- Findings ---"))
		for i, f := range report.Findings {
			var stateColor string
			switch f.Exposure {
			case traversal.StateActive:
				stateColor = ansiRed
			case traversal.StateHistorical:
				stateColor = ansiYellow
			case traversal.StateZombie:
				stateColor = ansiMagenta
			default:
				stateColor = ansiBlue
			}

			var tierColor string
			switch f.ConfidenceTier {
			case detect.TierCritical:
				tierColor = ansiRed
			case detect.TierHigh:
				tierColor = ansiYellow
			case detect.TierMedium:
				tierColor = ansiBlue
			default:
				tierColor = ansiReset
			}

			fmt.Fprintf(w, "[%d] Finding ID: %s\n", i+1, color(ansiBold, f.ID))
			fmt.Fprintf(w, "    Exposure:   %s\n", color(stateColor+ansiBold, string(f.Exposure)))
			fmt.Fprintf(w, "    Confidence: %s (%d/100)\n", color(tierColor+ansiBold, string(f.ConfidenceTier)), f.ConfidenceScore)
			fmt.Fprintf(w, "    Pattern:    %s (%s)\n", f.PatternName, f.Category)
			fmt.Fprintf(w, "    Blob OID:   %s\n", f.BlobID)
			fmt.Fprintf(w, "    Redacted:   %s\n", color(ansiBold, f.Redacted))
			if !f.IsBinary {
				fmt.Fprintf(w, "    Location:   Line %d (byte offset %d)\n", f.LineNumber, f.ByteOffset)
			} else {
				fmt.Fprintf(w, "    Location:   Binary data (byte offset %d)\n", f.ByteOffset)
			}

			if len(f.Occurrences) > 0 {
				fmt.Fprintln(w, "    Occurrences:")
				for _, occ := range f.Occurrences {
					fmt.Fprintf(w, "      - %s (commit %s, %s)\n", occ.Path, occ.CommitSHA[:8], occ.DateString)
				}
			}

			if f.Timeline != nil {
				fmt.Fprintf(w, "    Timeline:   %s\n", f.Timeline.EvidenceNote)
				fmt.Fprintf(w, "                Earliest observed: commit %s (%s)\n", f.Timeline.EarliestObservedCommit[:8], f.Timeline.EarliestObservedDate)
			}

			fmt.Fprintln(w)
		}
	}

	if len(report.CoverageGaps) > 0 {
		fmt.Fprintln(w, color(ansiYellow+ansiBold, "--- Coverage Gaps ---"))
		for _, gap := range report.CoverageGaps {
			fmt.Fprintf(w, "  [%s] %s: %s\n", gap.Type, gap.Target, gap.Description)
		}
		fmt.Fprintln(w)
	}

	if len(report.StructuralAnomalies) > 0 {
		fmt.Fprintln(w, color(ansiYellow+ansiBold, "--- Structural Anomalies ---"))
		for _, anom := range report.StructuralAnomalies {
			fmt.Fprintf(w, "  [%s] %s: %s\n", anom.Type, anom.Location, anom.Description)
		}
		fmt.Fprintln(w)
	}
}

// FormatHumanExplain outputs a detailed explain report to w (§15).
func FormatHumanExplain(w io.Writer, res *ExplainResult, noColor bool) {
	color := func(code, text string) string {
		if noColor {
			return text
		}
		return code + text + ansiReset
	}

	f := res.Finding
	fmt.Fprintln(w, color(ansiBold+ansiCyan, "=== GitForensics Finding Explanation ==="))
	fmt.Fprintf(w, "Finding ID:      %s (Full Digest: %s)\n", color(ansiBold, f.ID), f.FullDigest)
	fmt.Fprintf(w, "Secret Category: %s (%s)\n", f.Category, f.PatternName)
	fmt.Fprintf(w, "Blob OID:        %s\n", f.BlobID)
	fmt.Fprintf(w, "Fingerprint:     %s\n", f.Fingerprint)
	fmt.Fprintf(w, "Redacted:        %s\n", color(ansiBold, f.Redacted))
	fmt.Fprintf(w, "Confidence:      %s (%d/100)\n\n", color(ansiBold, string(f.ConfidenceTier)), f.ConfidenceScore)

	fmt.Fprintln(w, color(ansiBold, "--- Exposure & Forensics ---"))
	fmt.Fprintf(w, "%s\n\n", res.RecoveryExplanation)

	fmt.Fprintln(w, color(ansiBold, "--- Evidence Signals ---"))
	for _, sig := range f.EvidenceSignals {
		fmt.Fprintf(w, "  * [%+d] %s: %s\n", sig.Score, sig.Rule, sig.Detail)
	}
	fmt.Fprintln(w)

	if len(f.Occurrences) > 0 {
		fmt.Fprintln(w, color(ansiBold, "--- Historical Occurrences ---"))
		for _, occ := range f.Occurrences {
			fmt.Fprintf(w, "  * %s in commit %s by %s on %s\n", occ.Path, occ.CommitSHA, occ.Author, occ.DateString)
		}
		fmt.Fprintln(w)
	}

	if f.Timeline != nil {
		fmt.Fprintln(w, color(ansiBold, "--- Timeline ---"))
		fmt.Fprintf(w, "  %s\n", f.Timeline.EvidenceNote)
		fmt.Fprintf(w, "  Earliest observed: commit %s by %s on %s\n", f.Timeline.EarliestObservedCommit, f.Timeline.EarliestObservedAuthor, f.Timeline.EarliestObservedDate)
		if f.Timeline.RemovalObservedCommit != "" {
			fmt.Fprintf(w, "  Removal reference: commit %s on %s\n", f.Timeline.RemovalObservedCommit, f.Timeline.RemovalObservedDate)
		}
		fmt.Fprintln(w)
	}
}
