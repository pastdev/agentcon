// Package gitobject checks that bytes are an unsigned git commit or tag
// object, as git hands it to gpg.program for signing.
package gitobject

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
)

// MaxSize is the largest object the signer accepts.
const MaxSize = 1 << 20

// Type is a signable object type.
type Type string

const (
	Commit Type = "commit"
	Tag    Type = "tag"
)

// ErrMalformed marks bytes that are not a signable git object.
var ErrMalformed = errors.New("not an unsigned git commit or tag")

var (
	oidRe   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	identRe = regexp.MustCompile(`^[^<>\n]*<[^<>\n]*> [0-9]+ [+-][0-9]{4}$`)
	typeRe  = regexp.MustCompile(`^(commit|tree|blob|tag)$`)
	// sigHeaders mark a commit that already carries a signature.
	sigHeaders = map[string]bool{"gpgsig": true, "gpgsig-sha256": true}
	// sigMarkers start a signature appended to a tag message.
	sigMarkers = [][]byte{
		[]byte("-----BEGIN PGP SIGNATURE-----"),
		[]byte("-----BEGIN SSH SIGNATURE-----"),
		[]byte("-----BEGIN SIGNED MESSAGE-----"),
	}
)

type header struct {
	key, value string
}

// Check returns the object type, or an error wrapping ErrMalformed.
func Check(b []byte) (Type, error) {
	if len(b) > MaxSize {
		return "", fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxSize)
	}
	head, body, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return "", fmt.Errorf("%w: no blank line after the headers", ErrMalformed)
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return "", fmt.Errorf("%w: NUL in headers", ErrMalformed)
	}
	hs, err := parseHeaders(head)
	if err != nil {
		return "", err
	}
	if len(hs) == 0 {
		return "", fmt.Errorf("%w: no headers", ErrMalformed)
	}
	switch hs[0].key {
	case "tree":
		return Commit, checkCommit(hs)
	case "object":
		return Tag, checkTag(hs, body)
	}
	return "", fmt.Errorf("%w: first header is %q", ErrMalformed, hs[0].key)
}

// parseHeaders splits header lines into keys and values. A continuation
// line (leading space) belongs to the header before it.
func parseHeaders(head []byte) ([]header, error) {
	var hs []header
	for _, line := range bytes.Split(head, []byte("\n")) {
		if len(line) == 0 {
			return nil, fmt.Errorf("%w: empty header line", ErrMalformed)
		}
		if line[0] == ' ' {
			if len(hs) == 0 {
				return nil, fmt.Errorf("%w: continuation line before any header", ErrMalformed)
			}
			continue
		}
		k, v, ok := bytes.Cut(line, []byte(" "))
		if !ok || len(k) == 0 {
			return nil, fmt.Errorf("%w: header line without a value", ErrMalformed)
		}
		if sigHeaders[string(k)] {
			return nil, fmt.Errorf("%w: already signed (%s)", ErrMalformed, k)
		}
		hs = append(hs, header{key: string(k), value: string(v)})
	}
	return hs, nil
}

// expect consumes one header with key whose value matches re.
func expect(hs []header, i *int, key string, re *regexp.Regexp) error {
	if *i >= len(hs) || hs[*i].key != key {
		return fmt.Errorf("%w: missing %s header", ErrMalformed, key)
	}
	if re != nil && !re.MatchString(hs[*i].value) {
		return fmt.Errorf("%w: bad %s header", ErrMalformed, key)
	}
	*i++
	return nil
}

// rest refuses a required header repeated among the optional ones.
func rest(hs []header, i int, required ...string) error {
	for _, h := range hs[i:] {
		for _, r := range required {
			if h.key == r {
				return fmt.Errorf("%w: repeated or misplaced %s header", ErrMalformed, r)
			}
		}
	}
	return nil
}

func checkCommit(hs []header) error {
	i := 0
	err := expect(hs, &i, "tree", oidRe)
	if err != nil {
		return err
	}
	for i < len(hs) && hs[i].key == "parent" {
		err = expect(hs, &i, "parent", oidRe)
		if err != nil {
			return err
		}
	}
	err = expect(hs, &i, "author", identRe)
	if err != nil {
		return err
	}
	err = expect(hs, &i, "committer", identRe)
	if err != nil {
		return err
	}
	return rest(hs, i, "tree", "parent", "author", "committer")
}

func checkTag(hs []header, body []byte) error {
	i := 0
	err := expect(hs, &i, "object", oidRe)
	if err != nil {
		return err
	}
	err = expect(hs, &i, "type", typeRe)
	if err != nil {
		return err
	}
	err = expect(hs, &i, "tag", nil)
	if err != nil {
		return err
	}
	err = expect(hs, &i, "tagger", identRe)
	if err != nil {
		return err
	}
	err = rest(hs, i, "object", "type", "tag", "tagger")
	if err != nil {
		return err
	}
	for _, m := range sigMarkers {
		if bytes.Contains(body, m) {
			return fmt.Errorf("%w: tag message already carries a signature", ErrMalformed)
		}
	}
	return nil
}
