// Package corpus compiles the records a triage verdict may cite into an index resolved by exact lookup.
package corpus

import (
	"fmt"
	"strconv"
	"strings"
)

// ID is a typed, stable citation. A verdict cites one of these and nothing else.
type ID string

// Kind is the corpus source an ID names.
type Kind string

const (
	KindCheckov  Kind = "checkov"
	KindThreat   Kind = "threat"
	KindDecision Kind = "decision"
	KindControl  Kind = "control"
)

// CheckovID names one check against one resource address in .checkov.baseline.
func CheckovID(check, address string) ID {
	return ID(fmt.Sprintf("%s:%s:%s", KindCheckov, check, address))
}

// ThreatID names a numbered row in the threat model findings table.
func ThreatID(n int) ID {
	return ID(fmt.Sprintf("%s:%d", KindThreat, n))
}

// DecisionID names a decisions.md heading by its anchor.
func DecisionID(anchor string) ID {
	return ID(fmt.Sprintf("%s:%s", KindDecision, anchor))
}

// ControlID names an entry in controls.yaml by its slug.
func ControlID(slug string) ID {
	return ID(fmt.Sprintf("%s:%s", KindControl, slug))
}

// ParseID returns the kind an ID names, or an error if the ID is malformed.
func ParseID(id ID) (Kind, error) {
	parts := strings.Split(string(id), ":")
	kind := Kind(parts[0])

	switch kind {
	case KindCheckov:
		if len(parts) != 3 {
			return "", fmt.Errorf("checkov id %q wants check and address", id)
		}
		if parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("checkov id %q has an empty check or address", id)
		}
	case KindThreat:
		if len(parts) != 2 {
			return "", fmt.Errorf("threat id %q wants a finding number", id)
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 1 {
			return "", fmt.Errorf("threat id %q wants a positive finding number", id)
		}
	case KindDecision, KindControl:
		if len(parts) != 2 || parts[1] == "" {
			return "", fmt.Errorf("%s id %q wants a non-empty name", kind, id)
		}
	default:
		return "", fmt.Errorf("id %q has no known kind", id)
	}
	return kind, nil
}
