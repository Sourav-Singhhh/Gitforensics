package detect

import (
	"testing"
)

func TestStrongPatterns(t *testing.T) {
	// Construct deterministic synthetic test tokens using string concatenation
	// so static scanners on public repositories do not flag test fixtures.
	syntheticAKIA := "AKIA" + "0123456789ABCDEF"
	syntheticASIA := "ASIA" + "0123456789ABCDEF"
	syntheticGHP := "ghp_" + "0123456789ABCDEFGHIJKLMNOPQRSTUV" + "WXYZ"
	syntheticGHO := "gho_" + "0123456789ABCDEFGHIJKLMNOPQRSTUV" + "WXYZ"
	syntheticSlack := "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "abcdefABCDEF"

	tests := []struct {
		name          string
		input         string
		expectedName  string
		expectedMatch string
	}{
		{
			name:          "AWS AKIA standard",
			input:         "export AWS_KEY=" + syntheticAKIA + "\n",
			expectedName:  "AWS Access Key",
			expectedMatch: syntheticAKIA,
		},
		{
			name:          "AWS ASIA temporary",
			input:         "aws_access_key_id = " + syntheticASIA,
			expectedName:  "AWS Access Key",
			expectedMatch: syntheticASIA,
		},
		{
			name:          "GitHub Personal Access Token",
			input:         "token: " + syntheticGHP + "\n",
			expectedName:  "GitHub Token",
			expectedMatch: syntheticGHP,
		},
		{
			name:          "GitHub OAuth Token",
			input:         "oauth = " + syntheticGHO,
			expectedName:  "GitHub Token",
			expectedMatch: syntheticGHO,
		},
		{
			name:          "Slack Bot Token",
			input:         "slack_api_token = \"" + syntheticSlack + "\"",
			expectedName:  "Slack Token",
			expectedMatch: syntheticSlack,
		},
		{
			name:          "RSA Private Key Header",
			input:         "-----BEGIN " + "RSA " + "PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA0...",
			expectedName:  "Private Key",
			expectedMatch: "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			name:          "Generic Private Key Header",
			input:         "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvgIBADANBgkq...",
			expectedName:  "Private Key",
			expectedMatch: "-----BEGIN PRIVATE KEY-----",
		},
		{
			name:          "OpenSSH Private Key Header",
			input:         "-----BEGIN " + "OPENSSH " + "PRIVATE KEY-----\n" + "b3BlbnNzaC...",
			expectedName:  "Private Key",
			expectedMatch: "-----BEGIN OPENSSH PRIVATE KEY-----",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates, isOversize, _ := ScanBlob([]byte(tt.input))
			if isOversize {
				t.Fatalf("unexpected oversize flag")
			}

			found := false
			for _, c := range candidates {
				if c.PatternName == tt.expectedName && string(c.CandidateBytes) == tt.expectedMatch {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected pattern %q with match %q, got candidates: %+v", tt.expectedName, tt.expectedMatch, candidates)
			}
		})
	}
}
