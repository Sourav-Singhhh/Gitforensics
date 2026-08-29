package detect

import (
	"testing"
)

func TestStrongPatterns(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedName  string
		expectedMatch string
	}{
		{
			name:          "AWS AKIA standard",
			input:         "export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
			expectedName:  "AWS Access Key",
			expectedMatch: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:          "AWS ASIA temporary",
			input:         "aws_access_key_id = ASIAIOSFODNN7EXAMPLE",
			expectedName:  "AWS Access Key",
			expectedMatch: "ASIAIOSFODNN7EXAMPLE",
		},
		{
			name:          "GitHub Personal Access Token",
			input:         "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n",
			expectedName:  "GitHub Token",
			expectedMatch: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		},
		{
			name:          "GitHub OAuth Token",
			input:         "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			expectedName:  "GitHub Token",
			expectedMatch: "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		},
		{
			name:          "Slack Bot Token",
			input:         "slack_api_token = \"xoxb-123456789012-123456789012-abcdefABCDEF\"",
			expectedName:  "Slack Token",
			expectedMatch: "xoxb-123456789012-123456789012-abcdefABCDEF",
		},
		{
			name:          "RSA Private Key Header",
			input:         "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
			expectedName:  "Private Key",
			expectedMatch: "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			name:          "Generic Private Key Header",
			input:         "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkq...",
			expectedName:  "Private Key",
			expectedMatch: "-----BEGIN PRIVATE KEY-----",
		},
		{
			name:          "OpenSSH Private Key Header",
			input:         "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC...",
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
