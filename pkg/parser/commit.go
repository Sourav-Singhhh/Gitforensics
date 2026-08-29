package parser

import (
	"bytes"
	"gitforensics/pkg/object"
	"strconv"
	"strings"
)

// Identity represents the author or committer metadata in a Git commit.
type Identity struct {
	Name      string
	Email     string
	Timestamp int64
	Timezone  string
}

// Header represents a generic Git commit header (key-value pair).
type Header struct {
	Key   string
	Value string
}

// Commit represents a parsed Git commit object.
type Commit struct {
	TreeSHA      string
	ParentSHAs   []string
	Author       Identity
	Committer    Identity
	ExtraHeaders []Header

	// Message is a subslice of the underlying commit payload provided to ParseCommit.
	// It is not copied. Callers retaining Commit beyond the lifetime of the payload
	// buffer must copy Message if the underlying buffer is reused.
	Message []byte
}

// validateTimezone checks that a timezone string follows "+HHMM" or "-HHMM" format (§7).
func validateTimezone(tz string) bool {
	if len(tz) != 5 {
		return false
	}
	if tz[0] != '+' && tz[0] != '-' {
		return false
	}
	for i := 1; i < 5; i++ {
		if tz[i] < '0' || tz[i] > '9' {
			return false
		}
	}
	return true
}

// parseIdentity parses an author or committer line right-to-left:
// <name> <email> <timestamp> <timezone>
func parseIdentity(line string, isAuthor bool) (Identity, error) {
	malformedLineErr := object.ErrCommitMalformedCommitterLine
	if isAuthor {
		malformedLineErr = object.ErrCommitMalformedAuthorLine
	}

	trimmed := strings.TrimSpace(line)
	if len(trimmed) == 0 {
		return Identity{}, malformedLineErr
	}

	// 1. Rightmost token: timezone (+HHMM or -HHMM)
	lastSpace := strings.LastIndexByte(trimmed, ' ')
	if lastSpace == -1 {
		return Identity{}, malformedLineErr
	}
	tz := trimmed[lastSpace+1:]
	if !validateTimezone(tz) {
		return Identity{}, object.ErrCommitMalformedTimezone
	}
	rest := trimmed[:lastSpace]

	// 2. Second rightmost token: timestamp
	prevSpace := strings.LastIndexByte(rest, ' ')
	if prevSpace == -1 {
		return Identity{}, malformedLineErr
	}
	tsStr := rest[prevSpace+1:]
	rest = rest[:prevSpace]

	// Validate timestamp contains decimal digits only (strictly non-negative per §7)
	if len(tsStr) == 0 {
		return Identity{}, object.ErrCommitMalformedTimestamp
	}
	for i := 0; i < len(tsStr); i++ {
		c := tsStr[i]
		if c < '0' || c > '9' {
			return Identity{}, object.ErrCommitMalformedTimestamp
		}
	}

	// Validate timestamp integer range / overflow (hard-fail per §7)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || ts < 0 {
		return Identity{}, object.ErrCommitMalformedTimestamp
	}

	// 3. Email enclosed in '<' and '>'
	openAngle := strings.LastIndexByte(rest, '<')
	closeAngle := strings.LastIndexByte(rest, '>')
	if openAngle == -1 || closeAngle == -1 || openAngle >= closeAngle {
		return Identity{}, malformedLineErr
	}

	email := rest[openAngle+1 : closeAngle]
	name := strings.TrimSpace(rest[:openAngle])

	return Identity{
		Name:      name,
		Email:     email,
		Timestamp: ts,
		Timezone:  tz,
	}, nil
}

// ParseCommit parses the uncompressed payload of a Git commit object.
//
// Invariants enforced (§7):
// 1. "tree" header must be present and must be the first header line.
// 2. "parent" headers (zero or more) are preserved in stored order (supports merge/octopus).
// 3. "author" and "committer" must each appear exactly once.
// 4. Continuation lines (single leading space ' ') are handled generically (e.g. gpgsig).
// 5. Timestamps must be valid decimal integers; malformed/overflow hard-fails with ErrCommitMalformedTimestamp.
// 6. Headers and message must be separated by a blank line (\n\n).
func ParseCommit(payload []byte) (*Commit, error) {
	if len(payload) == 0 {
		return nil, object.ErrCommitMissingTree
	}

	// Find header/message separator: a blank line (\n\n)
	splitIdx := bytes.Index(payload, []byte("\n\n"))
	if splitIdx == -1 {
		return nil, object.ErrCommitMissingMessageSeparator
	}

	headerBytes := payload[:splitIdx]
	messageBytes := payload[splitIdx+2:]

	// Split header block into raw lines
	rawLines := bytes.Split(headerBytes, []byte("\n"))

	// Assemble multiline headers (continuation lines begin with a single space ' ')
	type rawHeader struct {
		key string
		val string
	}
	var headers []rawHeader

	for _, lineBytes := range rawLines {
		if len(lineBytes) == 0 {
			continue
		}

		if lineBytes[0] == ' ' {
			// Continuation of previous header
			if len(headers) == 0 {
				return nil, object.ErrCommitMalformedHeaderLine
			}
			// Append continuation line with newline
			headers[len(headers)-1].val += "\n" + string(lineBytes[1:])
		} else {
			spIdx := bytes.IndexByte(lineBytes, ' ')
			if spIdx == -1 {
				return nil, object.ErrCommitMalformedHeaderLine
			}
			key := string(lineBytes[:spIdx])
			val := string(lineBytes[spIdx+1:])
			headers = append(headers, rawHeader{key: key, val: val})
		}
	}

	if len(headers) == 0 {
		return nil, object.ErrCommitMissingTree
	}

	// Rule 1: 'tree' must be the first header
	if headers[0].key != "tree" {
		return nil, object.ErrCommitMissingTree
	}

	treeSHA := headers[0].val
	if err := object.ValidateOID(treeSHA); err != nil {
		return nil, object.ErrCommitMalformedTreeRef
	}

	parentSHAs := make([]string, 0)
	var author Identity
	var committer Identity
	authorSeen := false
	committerSeen := false
	var extraHeaders []Header

	for i := 1; i < len(headers); i++ {
		h := headers[i]
		switch h.key {
		case "tree":
			// Duplicate tree header
			return nil, object.ErrCommitMalformedHeaderLine
		case "parent":
			if err := object.ValidateOID(h.val); err != nil {
				return nil, object.ErrCommitMalformedParentRef
			}
			parentSHAs = append(parentSHAs, h.val)
		case "author":
			if authorSeen {
				return nil, object.ErrCommitDuplicateAuthor
			}
			id, err := parseIdentity(h.val, true)
			if err != nil {
				return nil, err
			}
			author = id
			authorSeen = true
		case "committer":
			if committerSeen {
				return nil, object.ErrCommitDuplicateCommitter
			}
			id, err := parseIdentity(h.val, false)
			if err != nil {
				return nil, err
			}
			committer = id
			committerSeen = true
		default:
			extraHeaders = append(extraHeaders, Header{Key: h.key, Value: h.val})
		}
	}

	if !authorSeen {
		return nil, object.ErrCommitMissingAuthor
	}
	if !committerSeen {
		return nil, object.ErrCommitMissingCommitter
	}

	return &Commit{
		TreeSHA:      treeSHA,
		ParentSHAs:   parentSHAs,
		Author:       author,
		Committer:    committer,
		ExtraHeaders: extraHeaders,
		Message:      messageBytes,
	}, nil
}
