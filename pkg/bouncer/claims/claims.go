// Package claims holds the rules for session claims: trusted (type, value)
// facts about a bouncer session that filters read and agentcon never
// interprets.
package claims

import (
	"errors"
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"
)

// Limits on a session's claims.
const (
	// MaxTypeLength is the longest claim type, in characters.
	MaxTypeLength = 64
	// MaxValueBytes is the longest claim value, in bytes.
	MaxValueBytes = 1024
	// MaxTypes is the most claim types a session may hold.
	MaxTypes = 32
	// MaxValues is the most values a session may hold for one type.
	MaxValues = 256
)

// ErrLimit is returned when an addition would exceed MaxTypes or MaxValues.
var ErrLimit = errors.New("claim limit exceeded")

// Added-by values recorded when a claim joins a session.
const (
	// AddedSeeded means the management API set the claim at session creation.
	AddedSeeded = "seeded"
	// AddedOperator means an operator approved a filter's claim request for
	// the session.
	AddedOperator = "operator"
)

// Claim is one fact about a session.
type Claim struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Set maps a claim type to its values. Values are unique and sorted.
// Comparison is exact: nothing is normalized.
type Set map[string][]string

// ValidType reports whether t is a valid claim type: a lowercase letter
// followed by lowercase letters, digits, or underscores, at most
// MaxTypeLength characters.
func ValidType(t string) error {
	if t == "" {
		return errors.New("claim type is empty")
	}
	if len(t) > MaxTypeLength {
		return fmt.Errorf("claim type is longer than %d characters", MaxTypeLength)
	}
	for i, r := range t {
		lower := r >= 'a' && r <= 'z'
		if i == 0 && !lower {
			return fmt.Errorf("claim type %q must start with a lowercase letter", t)
		}
		digit := r >= '0' && r <= '9'
		if !lower && !digit && r != '_' {
			return fmt.Errorf("claim type %q may hold only lowercase letters, digits, and underscores", t)
		}
	}
	return nil
}

// ValidValue reports whether v is a valid claim value: non-empty, at most
// MaxValueBytes, valid UTF-8, and free of control characters.
// The error never quotes the value, which may be long.
func ValidValue(v string) error {
	switch {
	case v == "":
		return errors.New("claim value is empty")
	case len(v) > MaxValueBytes:
		return fmt.Errorf("claim value is longer than %d bytes", MaxValueBytes)
	case !utf8.ValidString(v):
		return errors.New("claim value is not valid UTF-8")
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return errors.New("claim value contains a control character")
		}
	}
	return nil
}

// Valid checks one claim.
func Valid(t, v string) error {
	err := ValidType(t)
	if err != nil {
		return err
	}
	err = ValidValue(v)
	if err != nil {
		return fmt.Errorf("claim %s: %w", t, err)
	}
	return nil
}

// FromMap validates m and returns it as a Set with duplicate values
// removed. Any invalid claim rejects the whole map. A type with no values
// is invalid. A nil map gives an empty Set.
func FromMap(m map[string][]string) (Set, error) {
	if len(m) > MaxTypes {
		return nil, fmt.Errorf("%w: %d claim types, at most %d", ErrLimit, len(m), MaxTypes)
	}
	out := Set{}
	for t, vs := range m {
		err := ValidType(t)
		if err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, fmt.Errorf("claim %s has no values", t)
		}
		for i, v := range vs {
			err = ValidValue(v)
			if err != nil {
				return nil, fmt.Errorf("claim %s value %d: %w", t, i+1, err)
			}
		}
		u := slices.Clone(vs)
		slices.Sort(u)
		u = slices.Compact(u)
		if len(u) > MaxValues {
			return nil, fmt.Errorf("%w: claim %s has %d values, at most %d", ErrLimit, t, len(u), MaxValues)
		}
		out[t] = u
	}
	return out, nil
}

// Clone returns a deep copy. It is never nil.
func (s Set) Clone() Set {
	out := make(Set, len(s))
	for t, vs := range s {
		out[t] = slices.Clone(vs)
	}
	return out
}

// Has reports whether the set holds the claim.
func (s Set) Has(t, v string) bool {
	_, ok := slices.BinarySearch(s[t], v)
	return ok
}

// Check reports whether Add would accept the claim, without changing s.
// A claim already held is fine.
func (s Set) Check(t, v string) error {
	err := Valid(t, v)
	if err != nil {
		return err
	}
	if s.Has(t, v) {
		return nil
	}
	vs, ok := s[t]
	if !ok && len(s) >= MaxTypes {
		return fmt.Errorf("%w: a session holds at most %d claim types", ErrLimit, MaxTypes)
	}
	if len(vs) >= MaxValues {
		return fmt.Errorf("%w: claim %s holds at most %d values", ErrLimit, t, MaxValues)
	}
	return nil
}

// Add adds a claim. It reports false with no error when the set already
// holds it.
func (s Set) Add(t, v string) (bool, error) {
	err := s.Check(t, v)
	if err != nil {
		return false, err
	}
	vs := s[t]
	i, found := slices.BinarySearch(vs, v)
	if found {
		return false, nil
	}
	s[t] = slices.Insert(vs, i, v)
	return true, nil
}

// List returns every claim, ordered by type then value.
func (s Set) List() []Claim {
	types := make([]string, 0, len(s))
	for t := range s {
		types = append(types, t)
	}
	slices.Sort(types)
	var out []Claim
	for _, t := range types {
		for _, v := range s[t] {
			out = append(out, Claim{Type: t, Value: v})
		}
	}
	return out
}

// Count is the number of claims across all types.
func (s Set) Count() int {
	n := 0
	for _, vs := range s {
		n += len(vs)
	}
	return n
}
