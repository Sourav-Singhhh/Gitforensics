package detect

import (
	"regexp"
)

// PatternDefinition defines a strong secret detection pattern with metadata (§10).
type PatternDefinition struct {
	Name           string
	Category       string
	Regex          *regexp.Regexp
	BaseConfidence int
	IsPrivateKey   bool
}

// StrongPatterns holds the locked suite of strong regex patterns (§10).
var StrongPatterns = []PatternDefinition{
	{
		Name:           "AWS Access Key",
		Category:       "aws",
		Regex:          regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		BaseConfidence: 45,
		IsPrivateKey:   false,
	},
	{
		Name:           "GitHub Token",
		Category:       "github",
		Regex:          regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`),
		BaseConfidence: 45,
		IsPrivateKey:   false,
	},
	{
		Name:           "Slack Token",
		Category:       "slack",
		Regex:          regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		BaseConfidence: 40,
		IsPrivateKey:   false,
	},
	{
		Name:           "Private Key",
		Category:       "crypto",
		Regex:          regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		BaseConfidence: 45,
		IsPrivateKey:   true,
	},
}

// PatternMatch records the location and metadata of a strong pattern match.
type PatternMatch struct {
	PatternName    string
	Category       string
	Start          int
	End            int
	Match          []byte
	BaseConfidence int
	IsPrivateKey   bool
}
