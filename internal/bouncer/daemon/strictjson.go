package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// checkStrictJSON rejects JSON that encoding/json would silently change
// while decoding: invalid UTF-8 and unpaired surrogate escapes become
// U+FFFD, and a later duplicate member name replaces an earlier one. It
// also reports syntax errors.
func checkStrictJSON(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("request body is not valid UTF-8")
	}
	err := checkSurrogates(b)
	if err != nil {
		return err
	}
	return checkDuplicateNames(b)
}

// checkSurrogates rejects \u escapes in strings that do not form a valid
// surrogate pair.
func checkSurrogates(b []byte) error {
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(b) {
				return nil
			}
			if b[i+1] != 'u' {
				i++
				continue
			}
			r, ok := hex4(b, i+2)
			if !ok {
				return nil
			}
			// i now indexes the escape's last hex digit.
			i += 5
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				if i+6 < len(b) && b[i+1] == '\\' && b[i+2] == 'u' {
					low, ok := hex4(b, i+3)
					if ok && low >= 0xDC00 && low <= 0xDFFF {
						i += 6
						continue
					}
				}
				return errors.New("request body has an unpaired surrogate escape")
			case r >= 0xDC00 && r <= 0xDFFF:
				return errors.New("request body has an unpaired surrogate escape")
			}
		}
	}
	return nil
}

// hex4 decodes four hex digits at b[at:].
func hex4(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[at : at+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

// checkDuplicateNames rejects an object, at any depth, that repeats a
// member name.
func checkDuplicateNames(b []byte) error {
	type frame struct {
		object   bool
		wantName bool
		names    map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) > 0 {
				return errors.New("request body: unexpected end of JSON input")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("request body: %w", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top != nil && top.object {
					// The container is this member's value.
					top.wantName = true
				}
				stack = append(stack, &frame{object: d == '{', wantName: d == '{', names: map[string]bool{}})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.wantName {
			name, _ := tok.(string)
			if top.names[name] {
				return fmt.Errorf("request body repeats the member %q", name)
			}
			top.names[name] = true
			top.wantName = false
			continue
		}
		top.wantName = true
	}
}
