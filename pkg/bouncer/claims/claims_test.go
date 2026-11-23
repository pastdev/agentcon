package claims

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	type testCase struct {
		typ, value string
		err        string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := Valid(tc.typ, tc.value)
		if tc.err == "" {
			assert.NoError(t, err)
			return
		}
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.err)
		if len(tc.value) > 1 {
			assert.NotContains(t, err.Error(), tc.value[1:], "error must not quote the value")
		}
	}

	ok := "gitlab.example.com/group/project"
	t.Run("plain claim", func(t *testing.T) { tester(t, testCase{typ: "repository", value: ok}) })
	t.Run("type with digits and underscores", func(t *testing.T) { tester(t, testCase{typ: "a1_b", value: ok}) })
	t.Run("type at limit", func(t *testing.T) { tester(t, testCase{typ: "a" + strings.Repeat("b", 63), value: ok}) })
	t.Run("value at limit", func(t *testing.T) { tester(t, testCase{typ: "t", value: strings.Repeat("v", 1024)}) })
	t.Run("value with unicode", func(t *testing.T) { tester(t, testCase{typ: "t", value: "grüße/プロジェクト"}) })
	t.Run("value with space", func(t *testing.T) { tester(t, testCase{typ: "t", value: " a b "}) })

	t.Run("empty type", func(t *testing.T) { tester(t, testCase{typ: "", value: ok, err: "type is empty"}) })
	t.Run("uppercase type", func(t *testing.T) { tester(t, testCase{typ: "Repo", value: ok, err: "lowercase letter"}) })
	t.Run("type with uppercase inside", func(t *testing.T) { tester(t, testCase{typ: "rePo", value: ok, err: "only lowercase"}) })
	t.Run("leading digit", func(t *testing.T) { tester(t, testCase{typ: "1repo", value: ok, err: "lowercase letter"}) })
	t.Run("leading underscore", func(t *testing.T) { tester(t, testCase{typ: "_repo", value: ok, err: "lowercase letter"}) })
	t.Run("type with dash", func(t *testing.T) { tester(t, testCase{typ: "re-po", value: ok, err: "only lowercase"}) })
	t.Run("type with unicode", func(t *testing.T) { tester(t, testCase{typ: "rëpo", value: ok, err: "only lowercase"}) })
	t.Run("type too long", func(t *testing.T) {
		tester(t, testCase{typ: strings.Repeat("a", 65), value: ok, err: "longer than 64"})
	})
	t.Run("empty value", func(t *testing.T) { tester(t, testCase{typ: "t", value: "", err: "value is empty"}) })
	t.Run("value too long", func(t *testing.T) {
		tester(t, testCase{typ: "t", value: strings.Repeat("v", 1025), err: "longer than 1024 bytes"})
	})
	t.Run("multibyte value over byte limit", func(t *testing.T) {
		tester(t, testCase{typ: "t", value: strings.Repeat("é", 513), err: "longer than 1024 bytes"})
	})
	t.Run("invalid utf8", func(t *testing.T) { tester(t, testCase{typ: "t", value: "a\xffb", err: "not valid UTF-8"}) })
	for name, c := range map[string]string{
		"newline": "\n", "carriage return": "\r", "tab": "\t", "nul": "\x00", "escape": "\x1b", "delete": "\x7f", "c1": "\u0085",
	} {
		t.Run("value with "+name, func(t *testing.T) {
			tester(t, testCase{typ: "t", value: "a" + c + "b", err: "control character"})
		})
	}
}

func TestFromMap(t *testing.T) {
	type testCase struct {
		in   map[string][]string
		want Set
		err  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := FromMap(tc.in)
		if tc.err != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
			assert.Nil(t, got)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}
	values := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("v%03d", i)
		}
		return out
	}
	types := func(n int) map[string][]string {
		out := map[string][]string{}
		for i := range n {
			out[fmt.Sprintf("t%d", i)] = []string{"v"}
		}
		return out
	}

	t.Run("nil is empty, not nil", func(t *testing.T) { tester(t, testCase{in: nil, want: Set{}}) })
	t.Run("dedupes and sorts", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"repo": {"b", "a", "b"}}, want: Set{"repo": {"a", "b"}}})
	})
	t.Run("does not normalize", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"repo": {"A", "a", "a/"}}, want: Set{"repo": {"A", "a", "a/"}}})
	})
	t.Run("max types", func(t *testing.T) {
		got, err := FromMap(types(32))
		require.NoError(t, err)
		assert.Len(t, got, 32)
	})
	t.Run("too many types", func(t *testing.T) { tester(t, testCase{in: types(33), err: "33 claim types"}) })
	t.Run("max values", func(t *testing.T) {
		got, err := FromMap(map[string][]string{"t": values(256)})
		require.NoError(t, err)
		assert.Len(t, got["t"], 256)
	})
	t.Run("duplicates do not count against the limit", func(t *testing.T) {
		got, err := FromMap(map[string][]string{"t": append(values(256), "v000")})
		require.NoError(t, err)
		assert.Len(t, got["t"], 256)
	})
	t.Run("too many values", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"t": values(257)}, err: "257 values"})
	})
	t.Run("type with no values", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"t": {}}, err: "no values"})
	})
	t.Run("one bad value rejects the whole map", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"a": {"ok"}, "t": {"ok", "bad\n"}}, err: "claim t value 2"})
	})
	t.Run("one bad type rejects the whole map", func(t *testing.T) {
		tester(t, testCase{in: map[string][]string{"a": {"ok"}, "B": {"ok"}}, err: "lowercase"})
	})
	t.Run("does not alias the input", func(t *testing.T) {
		in := map[string][]string{"t": {"b", "a"}}
		_, err := FromMap(in)
		require.NoError(t, err)
		assert.Equal(t, []string{"b", "a"}, in["t"])
	})
}

func TestSetAdd(t *testing.T) {
	type testCase struct {
		start      Set
		typ, value string
		added      bool
		err        string
		want       Set
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		s := tc.start.Clone()
		added, err := s.Add(tc.typ, tc.value)
		if tc.err != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
			assert.Equal(t, tc.start, s, "a failed add changes nothing")
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.added, added)
		assert.Equal(t, tc.want, s)
	}
	full := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("v%03d", i)
		}
		return out
	}
	fullTypes := Set{}
	for i := range 32 {
		fullTypes[fmt.Sprintf("t%02d", i)] = []string{"v"}
	}

	t.Run("adds in order", func(t *testing.T) {
		tester(t, testCase{start: Set{"r": {"a", "c"}}, typ: "r", value: "b", added: true, want: Set{"r": {"a", "b", "c"}}})
	})
	t.Run("new type", func(t *testing.T) {
		tester(t, testCase{start: Set{}, typ: "r", value: "a", added: true, want: Set{"r": {"a"}}})
	})
	t.Run("duplicate is a no-op", func(t *testing.T) {
		tester(t, testCase{start: Set{"r": {"a"}}, typ: "r", value: "a", added: false, want: Set{"r": {"a"}}})
	})
	t.Run("duplicate succeeds at the limit", func(t *testing.T) {
		start := Set{"r": full(256)}
		tester(t, testCase{start: start, typ: "r", value: "v000", added: false, want: start})
	})
	t.Run("value over the limit", func(t *testing.T) {
		tester(t, testCase{start: Set{"r": full(256)}, typ: "r", value: "new", err: "at most 256 values"})
	})
	t.Run("type over the limit", func(t *testing.T) {
		tester(t, testCase{start: fullTypes, typ: "new", value: "v", err: "at most 32 claim types"})
	})
	t.Run("existing type at the type limit", func(t *testing.T) {
		want := fullTypes.Clone()
		want["t00"] = []string{"v", "w"}
		tester(t, testCase{start: fullTypes, typ: "t00", value: "w", added: true, want: want})
	})
	t.Run("invalid type", func(t *testing.T) { tester(t, testCase{start: Set{}, typ: "R", value: "a", err: "lowercase"}) })
	t.Run("invalid value", func(t *testing.T) {
		tester(t, testCase{start: Set{}, typ: "r", value: "a\tb", err: "control character"})
	})
}

func TestSetHelpers(t *testing.T) {
	s := Set{"b": {"x"}, "a": {"y", "z"}}
	t.Run("clone is deep", func(t *testing.T) {
		c := s.Clone()
		c["a"][0] = "changed"
		c["c"] = []string{"new"}
		assert.Equal(t, "y", s["a"][0])
		assert.NotContains(t, s, "c")
	})
	t.Run("clone of nil is empty", func(t *testing.T) {
		var n Set
		assert.NotNil(t, n.Clone())
	})
	t.Run("list is ordered", func(t *testing.T) {
		assert.Equal(t, []Claim{{"a", "y"}, {"a", "z"}, {"b", "x"}}, s.List())
	})
	t.Run("has is exact", func(t *testing.T) {
		assert.True(t, s.Has("a", "z"))
		assert.False(t, s.Has("a", "Z"))
		assert.False(t, s.Has("c", "z"))
	})
	t.Run("count", func(t *testing.T) { assert.Equal(t, 3, s.Count()) })
}
