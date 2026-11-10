package running

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	type testCase struct {
		home            string
		rec             Record
		wantErr         bool
		wantContains    string
		wantNotContains string
		want            Record
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := Write(tc.home, tc.rec)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		got, err := Read(tc.home, tc.rec.Slug)
		require.NoError(t, err)
		if tc.want.ControlAddr != "" {
			assert.Equal(t, tc.want, got)
		}
		data, err := os.ReadFile(Path(tc.home, tc.rec.Slug))
		require.NoError(t, err)
		if tc.wantContains != "" {
			assert.Contains(t, string(data), tc.wantContains)
		}
		if tc.wantNotContains != "" {
			assert.NotContains(t, string(data), tc.wantNotContains)
		}
	}

	t.Run("writes a sidecar record including container_id", func(t *testing.T) {
		home := t.TempDir()
		rec := Record{
			Context:     "foo",
			Project:     "github.com/pastdev/agentcon",
			Slug:        "deadbeef",
			Cwd:         filepath.Join(home, "git", "github.com", "pastdev", "agentcon"),
			ControlAddr: "127.0.0.1:43129",
			Token:       "secret-token",
			ContainerID: "8f2a1c9e4b0d",
			PID:         18421,
			Started:     time.Date(2026, 10, 29, 18, 8, 12, 0, time.UTC),
		}
		tester(t, testCase{
			home:         home,
			rec:          rec,
			wantContains: "container_id:",
			want:         rec,
		})
	})
	t.Run("omits the container field for a host serve record", func(t *testing.T) {
		home := t.TempDir()
		rec := Record{
			Context:     "foo",
			Project:     "github.com/pastdev/agentcon",
			Slug:        "deadbeef",
			Cwd:         filepath.Join(home, "git", "github.com", "pastdev", "agentcon"),
			ControlAddr: "127.0.0.1:43129",
			Token:       "secret-token",
			PID:         18421,
			Started:     time.Date(2026, 10, 29, 18, 8, 12, 0, time.UTC),
		}
		tester(t, testCase{
			home:            home,
			rec:             rec,
			wantNotContains: "container_id",
		})
	})
	t.Run("requires a slug", func(t *testing.T) {
		tester(t, testCase{
			home:    t.TempDir(),
			rec:     Record{Context: "foo", ControlAddr: "127.0.0.1:1", Token: "t"},
			wantErr: true,
		})
	})
}

func TestRemove(t *testing.T) {
	type testCase struct {
		home string
		slug string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		err := Remove(tc.home, tc.slug)
		require.NoError(t, err)
		_, err = Read(tc.home, tc.slug)
		require.Error(t, err, "expected missing record")
	}

	t.Run("removes a written record", func(t *testing.T) {
		home := t.TempDir()
		rec := Record{
			Context:     "foo",
			Project:     "github.com/pastdev/agentcon",
			Slug:        "deadbeef",
			ControlAddr: "127.0.0.1:43129",
			Token:       "secret-token",
		}
		err := Write(home, rec)
		require.NoError(t, err)
		tester(t, testCase{home: home, slug: "deadbeef"})
	})
}

func TestFileName(t *testing.T) {
	type testCase struct {
		in   string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, FileName(tc.in))
	}

	t.Run("sanitizes spaces", func(t *testing.T) {
		tester(t, testCase{in: "Foo Bar", want: "foo-bar"})
	})
	t.Run("sanitizes a github path", func(t *testing.T) {
		tester(t, testCase{in: "github.com/pastdev/agentcon", want: "github-com-pastdev-agentcon"})
	})
}

func TestBoundedName(t *testing.T) {
	type testCase struct {
		in         string
		want       string
		wantMax    bool
		wantSuffix string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := BoundedName(tc.in)
		if tc.want != "" {
			assert.Equal(t, tc.want, got)
		}
		if tc.wantMax {
			assert.LessOrEqual(t, len(got), boundedMax(), "%q", got)
		}
		if tc.wantSuffix != "" {
			assert.True(t, strings.HasSuffix(got, tc.wantSuffix), "leaf lost: %q", got)
		}
	}

	t.Run("sanitizes a github path", func(t *testing.T) {
		tester(t, testCase{in: "github.com/pastdev/agentcon", want: "github-com-pastdev-agentcon"})
	})
	t.Run("truncates from the left and keeps the leaf", func(t *testing.T) {
		tester(t, testCase{
			in:         "gitlab.com/very/long/group/name/and/subgroup/myproj",
			wantMax:    true,
			wantSuffix: "myproj",
		})
	})
}

func TestResourceName(t *testing.T) {
	type testCase struct {
		project    string
		slug       string
		role       string
		want       string
		wantPrefix string
		wantSuffix string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		name := ResourceName(tc.project, tc.slug, tc.role)
		if tc.want != "" {
			assert.Equal(t, tc.want, name)
		}
		assert.LessOrEqual(t, len(name), maxNameLen, "%q", name)
		if tc.wantPrefix != "" {
			assert.True(t, strings.HasPrefix(name, tc.wantPrefix), "%q", name)
		}
		if tc.wantSuffix != "" {
			assert.True(t, strings.HasSuffix(name, tc.wantSuffix), "%q", name)
		}
	}

	t.Run("fits a github project under the name limit", func(t *testing.T) {
		tester(t, testCase{
			project: "github.com/pastdev/agentcon",
			slug:    "deadbeef",
			role:    "bouncer",
			want:    "agentcon-github-com-pastdev-agentcon-deadbeef-bouncer",
		})
	})
	t.Run("keeps the slug and role on a long project", func(t *testing.T) {
		tester(t, testCase{
			project:    "gitlab.com/very/long/group/name/and/subgroup/myproj",
			slug:       "deadbeef",
			role:       "bouncer",
			wantPrefix: "agentcon-",
			wantSuffix: "-deadbeef-bouncer",
		})
	})
}

func TestProjectPath(t *testing.T) {
	type testCase struct {
		root string
		cwd  string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, ProjectPath(tc.root, tc.cwd))
	}

	root := filepath.Join(string(filepath.Separator), "home", "me", "git")
	t.Run("returns the path under the git root", func(t *testing.T) {
		tester(t, testCase{
			root: root,
			cwd:  filepath.Join(root, "github.com", "pastdev", "agentcon"),
			want: "github.com/pastdev/agentcon",
		})
	})
	t.Run("returns empty at the git root", func(t *testing.T) {
		tester(t, testCase{root: root, cwd: root, want: ""})
	})
}

func TestMatch(t *testing.T) {
	type testCase struct {
		recs    []Record
		q       Query
		want    string
		wantAmb bool
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := Match(tc.recs, tc.q)
		if tc.wantAmb {
			var amb *AmbiguousError
			require.ErrorAs(t, err, &amb)
			return
		}
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got.Slug)
	}

	home := t.TempDir()
	agentcon := filepath.Join(home, "git", "github.com", "pastdev", "agentcon")
	loader := filepath.Join(home, "git", "github.com", "pastdev", "configloader")
	recs := []Record{
		{Context: "git", Project: "github.com/pastdev/agentcon", Slug: "aaaaaaaa", Cwd: agentcon, ControlAddr: "127.0.0.1:1", Token: "a"},
		{Context: "git", Project: "github.com/pastdev/configloader", Slug: "bbbbbbbb", Cwd: loader, ControlAddr: "127.0.0.1:2", Token: "b"},
		{Context: "test", Project: "github.com/pastdev/agentcon", Slug: "cccccccc", Cwd: agentcon, ControlAddr: "127.0.0.1:3", Token: "c"},
	}
	for _, rec := range recs {
		err := os.MkdirAll(rec.Cwd, 0o700)
		require.NoError(t, err)
		err = Write(home, rec)
		require.NoError(t, err)
	}

	t.Run("matches a slug", func(t *testing.T) {
		tester(t, testCase{recs: recs, q: Query{Slug: "bbbbbbbb"}, want: "bbbbbbbb"})
	})
	t.Run("matches a unique project", func(t *testing.T) {
		tester(t, testCase{recs: recs, q: Query{Project: "github.com/pastdev/configloader"}, want: "bbbbbbbb"})
	})
	t.Run("matches cwd under a project", func(t *testing.T) {
		tester(t, testCase{recs: recs, q: Query{Context: "git", Cwd: filepath.Join(agentcon, "pkg", "run")}, want: "aaaaaaaa"})
	})
	t.Run("rejects an ambiguous project across contexts", func(t *testing.T) {
		tester(t, testCase{recs: recs, q: Query{Project: "github.com/pastdev/agentcon"}, wantAmb: true})
	})
	t.Run("matches the only record in a context", func(t *testing.T) {
		tester(t, testCase{recs: recs, q: Query{Context: "test"}, want: "cccccccc"})
	})
}

func TestFind(t *testing.T) {
	type testCase struct {
		home string
		q    Query
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := Find(tc.home, tc.q)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got.Slug)
	}

	t.Run("reads matching records from disk", func(t *testing.T) {
		home := t.TempDir()
		rec := Record{
			Context: "git", Project: "github.com/pastdev/agentcon", Slug: "deadbeef",
			Cwd: filepath.Join(home, "ws"), ControlAddr: "127.0.0.1:9", Token: "t",
		}
		err := os.MkdirAll(rec.Cwd, 0o700)
		require.NoError(t, err)
		err = Write(home, rec)
		require.NoError(t, err)
		tester(t, testCase{home: home, q: Query{Cwd: rec.Cwd}, want: "deadbeef"})
	})
}

func TestNewSlug(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		s := NewSlug()
		assert.True(t, ValidSlug(s), "%q", s)
	}

	t.Run("returns a valid slug", func(t *testing.T) {
		tester(t, testCase{})
	})
}

func TestValidSlug(t *testing.T) {
	type testCase struct {
		in   string
		want bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		assert.Equal(t, tc.want, ValidSlug(tc.in), "%q", tc.in)
	}

	t.Run("rejects an uppercase slug", func(t *testing.T) {
		tester(t, testCase{in: "DEADBEEF"})
	})
	t.Run("rejects a short slug", func(t *testing.T) {
		tester(t, testCase{in: "abcd"})
	})
}
