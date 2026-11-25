package gitobject

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sha1Tree   = "9bedf67800b2923982bdf60c89c57ce6986c4c5b"
	sha1Parent = "bd3539c4e2f1a0b1c2d3e4f5a6b7c8d9e0f1a2b3"
	ident      = "A U Thor <author@example.com> 1764000000 +0000"
)

func commit(headers ...string) string {
	return strings.Join(headers, "\n") + "\n\nSubject line.\n\nBody.\n"
}

func TestCheck(t *testing.T) {
	type testCase struct {
		in      string
		want    Type
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := Check([]byte(tc.in))
		if tc.wantErr != "" {
			require.ErrorIs(t, err, ErrMalformed)
			assert.Contains(t, err.Error(), tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}
	sha256Tree := strings.Repeat("ab", 32)
	tag := func(extra ...string) string {
		hs := append([]string{"object " + sha1Parent, "type commit", "tag v1.2.3", "tagger " + ident}, extra...)
		return strings.Join(hs, "\n") + "\n\nRelease v1.2.3.\n"
	}

	t.Run("root commit", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident), want: Commit})
	})
	t.Run("merge commit", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "parent "+sha1Parent, "parent "+sha1Tree, "author "+ident, "committer "+ident), want: Commit})
	})
	t.Run("sha256 commit", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha256Tree, "parent "+sha256Tree, "author "+ident, "committer "+ident), want: Commit})
	})
	t.Run("commit with encoding and non-utf8 message", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident, "encoding ISO-8859-1") + "caf\xe9\n", want: Commit})
	})
	t.Run("commit with mergetag continuation", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "parent "+sha1Parent, "author "+ident, "committer "+ident, "mergetag object "+sha1Parent, " type commit", " tag v1", " -----BEGIN PGP SIGNATURE-----", " ", " -----END PGP SIGNATURE-----"), want: Commit})
	})
	t.Run("commit with an empty author name", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author <a@example.com> 1764000000 -0500", "committer "+ident), want: Commit})
	})
	t.Run("annotated tag", func(t *testing.T) {
		tester(t, testCase{in: tag(), want: Tag})
	})
	t.Run("no blank line", func(t *testing.T) {
		tester(t, testCase{in: "tree " + sha1Tree + "\nauthor " + ident + "\ncommitter " + ident + "\n", wantErr: "no blank line"})
	})
	t.Run("arbitrary bytes", func(t *testing.T) {
		tester(t, testCase{in: "hello\n\nworld\n", wantErr: "header line without a value"})
	})
	t.Run("plain text with a header-like first line", func(t *testing.T) {
		tester(t, testCase{in: "Dear operator,\n\nplease sign this.\n", wantErr: `first header is "Dear"`})
	})
	t.Run("missing tree", func(t *testing.T) {
		tester(t, testCase{in: commit("parent "+sha1Parent, "author "+ident, "committer "+ident), wantErr: `first header is "parent"`})
	})
	t.Run("bad tree id", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+strings.ToUpper(sha1Tree), "author "+ident, "committer "+ident), wantErr: "bad tree header"})
	})
	t.Run("committer before author", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "committer "+ident, "author "+ident), wantErr: "missing author header"})
	})
	t.Run("bad ident", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author someone", "committer "+ident), wantErr: "bad author header"})
	})
	t.Run("repeated tree", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident, "tree "+sha1Tree), wantErr: "repeated or misplaced tree"})
	})
	t.Run("already signed gpgsig", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident, "gpgsig -----BEGIN PGP SIGNATURE-----", " ", " -----END PGP SIGNATURE-----"), wantErr: "already signed (gpgsig)"})
	})
	t.Run("already signed gpgsig-sha256", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha256Tree, "author "+ident, "committer "+ident, "gpgsig-sha256 x"), wantErr: "already signed (gpgsig-sha256)"})
	})
	t.Run("signed tag", func(t *testing.T) {
		tester(t, testCase{in: tag() + "-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n", wantErr: "already carries a signature"})
	})
	t.Run("tag without tagger", func(t *testing.T) {
		tester(t, testCase{in: "object " + sha1Parent + "\ntype commit\ntag v1\n\nmsg\n", wantErr: "missing tagger header"})
	})
	t.Run("tag with bad type", func(t *testing.T) {
		tester(t, testCase{in: "object " + sha1Parent + "\ntype release\ntag v1\ntagger " + ident + "\n\nmsg\n", wantErr: "bad type header"})
	})
	t.Run("push certificate", func(t *testing.T) {
		tester(t, testCase{in: "certificate version 0.1\npusher " + ident + "\npushee https://example.com/r.git\nnonce 1\n\n" + sha1Parent + " " + sha1Tree + " refs/heads/main\n", wantErr: `first header is "certificate"`})
	})
	t.Run("NUL in headers", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident, "x \x00"), wantErr: "NUL in headers"})
	})
	t.Run("continuation first", func(t *testing.T) {
		tester(t, testCase{in: " tree " + sha1Tree + "\n\nmsg\n", wantErr: "continuation line before any header"})
	})
	t.Run("oversize", func(t *testing.T) {
		tester(t, testCase{in: commit("tree "+sha1Tree, "author "+ident, "committer "+ident) + strings.Repeat("x", MaxSize), wantErr: "larger than"})
	})
}
