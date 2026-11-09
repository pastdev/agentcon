package running

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := Read(tc.home, tc.rec.Slug)
		if err != nil {
			t.Fatal(err)
		}
		if tc.want.ControlAddr != "" {
			if got.ControlAddr != tc.want.ControlAddr || got.Token != tc.want.Token || got.Slug != tc.want.Slug || got.Project != tc.want.Project {
				t.Fatalf("%+v", got)
			}
		}
		data, err := os.ReadFile(Path(tc.home, tc.rec.Slug))
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantContains != "" && !strings.Contains(string(data), tc.wantContains) {
			t.Fatalf("sidecar record should include %s:\n%s", tc.wantContains, data)
		}
		if tc.wantNotContains != "" && strings.Contains(string(data), tc.wantNotContains) {
			t.Fatalf("host serve record should omit %s:\n%s", tc.wantNotContains, data)
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
		if err != nil {
			t.Fatal(err)
		}
		_, err = Read(tc.home, tc.slug)
		if err == nil {
			t.Fatal("expected missing record")
		}
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
		if err != nil {
			t.Fatal(err)
		}
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
		if FileName(tc.in) != tc.want {
			t.Fatalf("%q", FileName(tc.in))
		}
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
		if tc.want != "" && got != tc.want {
			t.Fatalf("%q", got)
		}
		if tc.wantMax && len(got) > boundedMax() {
			t.Fatalf("len %d %q", len(got), got)
		}
		if tc.wantSuffix != "" && !strings.HasSuffix(got, tc.wantSuffix) {
			t.Fatalf("leaf lost: %q", got)
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
		if tc.want != "" && name != tc.want {
			t.Fatalf("%q", name)
		}
		if len(name) > maxNameLen {
			t.Fatalf("name len %d %q", len(name), name)
		}
		if tc.wantPrefix != "" && !strings.HasPrefix(name, tc.wantPrefix) {
			t.Fatalf("%q", name)
		}
		if tc.wantSuffix != "" && !strings.HasSuffix(name, tc.wantSuffix) {
			t.Fatalf("%q", name)
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
		if ProjectPath(tc.root, tc.cwd) != tc.want {
			t.Fatalf("%q", ProjectPath(tc.root, tc.cwd))
		}
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
			if err == nil {
				t.Fatal("expected ambiguous project across contexts")
			}
			var amb *AmbiguousError
			if !errors.As(err, &amb) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error")
			}
			return
		}
		if err != nil || got.Slug != tc.want {
			t.Fatalf("%v %v", got, err)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		err = Write(home, rec)
		if err != nil {
			t.Fatal(err)
		}
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
		if err != nil || got.Slug != tc.want {
			t.Fatalf("%v %v", got, err)
		}
	}

	t.Run("reads matching records from disk", func(t *testing.T) {
		home := t.TempDir()
		rec := Record{
			Context: "git", Project: "github.com/pastdev/agentcon", Slug: "deadbeef",
			Cwd: filepath.Join(home, "ws"), ControlAddr: "127.0.0.1:9", Token: "t",
		}
		err := os.MkdirAll(rec.Cwd, 0o700)
		if err != nil {
			t.Fatal(err)
		}
		err = Write(home, rec)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{home: home, q: Query{Cwd: rec.Cwd}, want: "deadbeef"})
	})
}

func TestNewSlug(t *testing.T) {
	type testCase struct{}
	tester := func(t *testing.T, _ testCase) {
		t.Helper()
		s := NewSlug()
		if !ValidSlug(s) {
			t.Fatalf("%q", s)
		}
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
		if ValidSlug(tc.in) != tc.want {
			if tc.want {
				t.Fatalf("%q", tc.in)
			} else {
				t.Fatal("slug should be rejected")
			}
		}
	}

	t.Run("rejects an uppercase slug", func(t *testing.T) {
		tester(t, testCase{in: "DEADBEEF"})
	})
	t.Run("rejects a short slug", func(t *testing.T) {
		tester(t, testCase{in: "abcd"})
	})
}
