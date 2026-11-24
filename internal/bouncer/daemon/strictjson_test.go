package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckStrictJSON(t *testing.T) {
	type testCase struct {
		in      string
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := checkStrictJSON([]byte(tc.in))
		if tc.wantErr == "" {
			assert.NoError(t, err)
			return
		}
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.wantErr)
	}

	t.Run("plain object", func(t *testing.T) {
		tester(t, testCase{in: `{"label":"a","claims":{"repo":["g/a","g/b"],"ticket":["T-1"]}}`})
	})
	t.Run("paired surrogate escape", func(t *testing.T) { tester(t, testCase{in: `{"claims":{"t":["😀"]}}`}) })
	t.Run("raw multibyte text", func(t *testing.T) { tester(t, testCase{in: `{"claims":{"t":["grüße 😀"]}}`}) })
	t.Run("escaped backslash before u is not an escape", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["a\\ud800"]}}`})
	})
	t.Run("same names in different objects", func(t *testing.T) {
		tester(t, testCase{in: `{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}`})
	})
	t.Run("a value equal to a name", func(t *testing.T) { tester(t, testCase{in: `{"a":"a","b":["a","a"]}`}) })
	t.Run("syntax error", func(t *testing.T) { tester(t, testCase{in: `{"a":`, wantErr: "request body"}) })

	t.Run("invalid utf8", func(t *testing.T) {
		tester(t, testCase{in: "{\"claims\":{\"t\":[\"a\xffb\"]}}", wantErr: "not valid UTF-8"})
	})
	t.Run("lone high surrogate", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["a\ud800b"]}}`, wantErr: "unpaired surrogate"})
	})
	t.Run("lone high surrogate at end of string", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["a\ud800"]}}`, wantErr: "unpaired surrogate"})
	})
	t.Run("lone low surrogate", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["\udc00"]}}`, wantErr: "unpaired surrogate"})
	})
	t.Run("high surrogate followed by a non-surrogate escape", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["\ud800A"]}}`, wantErr: "unpaired surrogate"})
	})
	t.Run("surrogate escape in a name", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"\ud800":["x"]}}`, wantErr: "unpaired surrogate"})
	})
	t.Run("duplicate claim type", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["bad\n"],"t":["ok"]}}`, wantErr: `repeats the member "t"`})
	})
	t.Run("duplicate claims key", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["bad\n"]},"claims":{}}`, wantErr: `repeats the member "claims"`})
	})
	t.Run("duplicate after a nested container", func(t *testing.T) {
		tester(t, testCase{in: `{"a":{"b":[1,{"c":2}]},"a":1}`, wantErr: `repeats the member "a"`})
	})
	t.Run("duplicate written with an escape", func(t *testing.T) {
		tester(t, testCase{in: `{"claims":{"t":["x"],"t":["y"]}}`, wantErr: `repeats the member "t"`})
	})
}
