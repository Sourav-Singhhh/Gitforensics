package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/forensics"
	"gitforensics/pkg/object"
	"gitforensics/pkg/traversal"
	"io"
	"os"
	"strings"
)

func isHexOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isInvalidRepoError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, object.ErrRepositoryNotFound) || os.IsNotExist(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "repository not found") || strings.Contains(msg, "not a git repository") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file or directory")
}

const (
	Version = "0.1.0-dev"
	Usage   = `gitforensics - read-only forensic Git object scanner

Usage:
  gitforensics scan [<repo-path>] [flags]
  gitforensics explain <finding-id> [--repo <path>] [flags]
  gitforensics version

Flags:
  --json                       Output results in structured JSON format
  --no-color                   Disable ANSI color output
  --quiet                      Suppress diagnostic output on stderr
  --min-confidence <tier>      Filter displayed findings (low, medium, high, critical)
  --repo <path>                Target repository path
`
)

type cliConfig struct {
	command       string
	repoPath      string
	findingID     string
	jsonOutput    bool
	noColor       bool
	quiet         bool
	minConfidence detect.ConfidenceTier
}

func parseCLIArgs(args []string) (*cliConfig, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command provided")
	}

	cfg := &cliConfig{
		repoPath:      ".",
		minConfidence: detect.TierLow,
	}

	cmd := args[0]
	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		cfg.command = "version"
		return cfg, nil
	}
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		cfg.command = "help"
		return cfg, nil
	}

	if cmd != "scan" && cmd != "explain" {
		return nil, fmt.Errorf("unknown command %q", cmd)
	}
	cfg.command = cmd

	i := 1
	var positional []string

	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "--json":
			cfg.jsonOutput = true
			i++
		case arg == "--no-color":
			cfg.noColor = true
			i++
		case arg == "--quiet":
			cfg.quiet = true
			i++
		case arg == "--repo":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--repo requires a path argument")
			}
			cfg.repoPath = args[i+1]
			i += 2
		case strings.HasPrefix(arg, "--repo="):
			cfg.repoPath = strings.TrimPrefix(arg, "--repo=")
			i++
		case arg == "--min-confidence":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--min-confidence requires a tier argument (low, medium, high, critical)")
			}
			tier, ok := detect.ParseConfidenceTier(args[i+1])
			if !ok {
				return nil, fmt.Errorf("invalid confidence tier %q; expected low, medium, high, or critical", args[i+1])
			}
			cfg.minConfidence = tier
			i += 2
		case strings.HasPrefix(arg, "--min-confidence="):
			val := strings.TrimPrefix(arg, "--min-confidence=")
			tier, ok := detect.ParseConfidenceTier(val)
			if !ok {
				return nil, fmt.Errorf("invalid confidence tier %q; expected low, medium, high, or critical", val)
			}
			cfg.minConfidence = tier
			i++
		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
			i++
		}
	}

	if cfg.command == "scan" {
		if len(positional) > 1 {
			return nil, fmt.Errorf("scan accepts at most one positional repository path")
		}
		if len(positional) == 1 {
			cfg.repoPath = positional[0]
		}
	} else if cfg.command == "explain" {
		if len(positional) == 0 {
			return nil, fmt.Errorf("explain requires a finding ID argument")
		}
		if len(positional) > 1 {
			return nil, fmt.Errorf("explain accepts at most one positional finding ID")
		}
		cfg.findingID = positional[0]
	}

	return cfg, nil
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, Usage)
		return 2
	}

	cfg, err := parseCLIArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n\n%s", err, Usage)
		return 2
	}

	switch cfg.command {
	case "version":
		fmt.Fprintf(stdout, "gitforensics %s\n", Version)
		return 0

	case "help":
		fmt.Fprint(stdout, Usage)
		return 0

	case "scan":
		opts := forensics.ScanOptions{
			RepoPath:      cfg.repoPath,
			MinConfidence: cfg.minConfidence,
		}

		if !cfg.quiet && !cfg.jsonOutput {
			fmt.Fprintf(stderr, "Scanning repository at %s...\n", cfg.repoPath)
		}

		report, scanErr := forensics.RunScan(opts)
		if scanErr != nil {
			if cfg.jsonOutput {
				fatalMsg := scanErr.Error()
				errReport := forensics.ScanReport{
					SchemaVersion: forensics.SchemaVersion,
					Tool: forensics.ToolMetadata{
						Name:    "gitforensics",
						Version: forensics.ToolVersion,
					},
					Repository: forensics.RepositoryMetadata{
						Path: cfg.repoPath,
					},
					Findings:            make([]forensics.Finding, 0),
					CoverageGaps:        make([]forensics.CoverageGap, 0),
					StructuralAnomalies: make([]traversal.StructuralAnomaly, 0),
					FatalError:          &fatalMsg,
				}
				jsonBytes, _ := forensics.FormatJSON(&errReport)
				stdout.Write(jsonBytes)
			} else {
				fmt.Fprintf(stderr, "Fatal scan error: %v\n", scanErr)
			}
			if isInvalidRepoError(scanErr) {
				return 2
			}
			return 3
		}

		if cfg.jsonOutput {
			jsonBytes, jsonErr := forensics.FormatJSON(report)
			if jsonErr != nil {
				fmt.Fprintf(stderr, "JSON formatting error: %v\n", jsonErr)
				return 3
			}
			stdout.Write(jsonBytes)
		} else {
			forensics.FormatHuman(stdout, report, cfg.noColor)
		}

		// Exit code semantics (§13):
		// 0 = zero total findings
		// 1 = total findings > 0 (even if filtered from display)
		if report.Summary.TotalFindingsCount > 0 {
			return 1
		}
		return 0

	case "explain":
		if (len(cfg.findingID) != 16 && len(cfg.findingID) != 64) || !isHexOnly(cfg.findingID) {
			fmt.Fprintf(stderr, "Error: invalid finding ID %q; expected 16 or 64 hex characters\n", cfg.findingID)
			return 2
		}

		res, explainErr := forensics.ExplainFinding(cfg.repoPath, cfg.findingID)
		if explainErr != nil {
			if errors.Is(explainErr, forensics.ErrMalformedFindingID) || isInvalidRepoError(explainErr) {
				if cfg.jsonOutput {
					errMap := map[string]string{
						"error": explainErr.Error(),
						"id":    cfg.findingID,
					}
					b, _ := json.MarshalIndent(errMap, "", "  ")
					fmt.Fprintln(stdout, string(b))
				} else {
					fmt.Fprintf(stderr, "Error: %v\n", explainErr)
				}
				return 2
			}

			if cfg.jsonOutput {
				errMap := map[string]string{
					"error": explainErr.Error(),
					"id":    cfg.findingID,
				}
				b, _ := json.MarshalIndent(errMap, "", "  ")
				fmt.Fprintln(stdout, string(b))
			} else {
				fmt.Fprintf(stderr, "Explain error: %v\n", explainErr)
			}
			// Explain not-found returns exit 1 per §13
			return 1
		}

		if cfg.jsonOutput {
			b, _ := json.MarshalIndent(res, "", "  ")
			fmt.Fprintln(stdout, string(b))
		} else {
			forensics.FormatHumanExplain(stdout, res, cfg.noColor)
		}
		return 0
	}

	return 2
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}
