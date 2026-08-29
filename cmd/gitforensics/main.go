package main

import (
	"encoding/json"
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/forensics"
	"os"
	"strings"
)

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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, Usage)
		os.Exit(2)
	}

	cfg, err := parseCLIArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n%s", err, Usage)
		os.Exit(2)
	}

	switch cfg.command {
	case "version":
		fmt.Printf("gitforensics %s\n", Version)
		os.Exit(0)

	case "help":
		fmt.Print(Usage)
		os.Exit(0)

	case "scan":
		opts := forensics.ScanOptions{
			RepoPath:      cfg.repoPath,
			MinConfidence: cfg.minConfidence,
		}

		if !cfg.quiet && !cfg.jsonOutput {
			fmt.Fprintf(os.Stderr, "Scanning repository at %s...\n", cfg.repoPath)
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
					StructuralAnomalies: nil,
					FatalError:          &fatalMsg,
				}
				jsonBytes, _ := forensics.FormatJSON(&errReport)
				os.Stdout.Write(jsonBytes)
			} else {
				fmt.Fprintf(os.Stderr, "Fatal scan error: %v\n", scanErr)
			}
			os.Exit(2)
		}

		if cfg.jsonOutput {
			jsonBytes, jsonErr := forensics.FormatJSON(report)
			if jsonErr != nil {
				fmt.Fprintf(os.Stderr, "JSON formatting error: %v\n", jsonErr)
				os.Exit(3)
			}
			os.Stdout.Write(jsonBytes)
		} else {
			forensics.FormatHuman(os.Stdout, report, cfg.noColor)
		}

		// Exit code semantics (§13):
		// 0 = zero total findings
		// 1 = total findings > 0 (even if filtered from display)
		if report.Summary.TotalFindingsCount > 0 {
			os.Exit(1)
		}
		os.Exit(0)

	case "explain":
		if len(cfg.findingID) != 16 && len(cfg.findingID) != 64 {
			fmt.Fprintf(os.Stderr, "Error: invalid finding ID %q; expected 16 or 64 hex characters\n", cfg.findingID)
			os.Exit(2)
		}

		res, explainErr := forensics.ExplainFinding(cfg.repoPath, cfg.findingID)
		if explainErr != nil {
			if cfg.jsonOutput {
				errMap := map[string]string{
					"error": explainErr.Error(),
					"id":    cfg.findingID,
				}
				b, _ := json.MarshalIndent(errMap, "", "  ")
				fmt.Println(string(b))
			} else {
				fmt.Fprintf(os.Stderr, "Explain error: %v\n", explainErr)
			}
			// Explain not-found returns exit 1 per §13
			os.Exit(1)
		}

		if cfg.jsonOutput {
			b, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(b))
		} else {
			forensics.FormatHumanExplain(os.Stdout, res, cfg.noColor)
		}
		os.Exit(0)
	}
}
