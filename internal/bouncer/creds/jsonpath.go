package creds

import (
	"fmt"

	"github.com/ohler55/ojg/jp"
	"github.com/ohler55/ojg/oj"
)

// extractJSONPath returns the source payload, or the JSONPath result when path
// is set. The path must yield exactly one string.
func extractJSONPath(payload []byte, path string) (string, error) {
	if path == "" {
		return string(payload), nil
	}
	expr, err := jp.ParseString(path)
	if err != nil {
		return "", fmt.Errorf("jsonpath %q: %w", path, err)
	}
	var doc any
	err = oj.Unmarshal(payload, &doc)
	if err != nil {
		return "", fmt.Errorf("jsonpath %q: payload is not JSON: %w", path, err)
	}
	got := expr.Get(doc)
	if len(got) == 0 {
		return "", fmt.Errorf("jsonpath %q: no match", path)
	}
	if len(got) != 1 {
		return "", fmt.Errorf("jsonpath %q: %d matches (want 1)", path, len(got))
	}
	s, ok := got[0].(string)
	if !ok {
		return "", fmt.Errorf("jsonpath %q: result is %T, not a string", path, got[0])
	}
	if s == "" {
		return "", fmt.Errorf("jsonpath %q: empty string", path)
	}
	return s, nil
}
