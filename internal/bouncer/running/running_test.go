package running

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteReadRemove(t *testing.T) {
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
	err := Write(home, rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(home, "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if got.ControlAddr != rec.ControlAddr || got.Token != rec.Token || got.Slug != rec.Slug || got.Project != rec.Project {
		t.Fatalf("%+v", got)
	}
	data, err := os.ReadFile(Path(home, "deadbeef"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "container_id:") {
		t.Fatalf("sidecar record should include container_id:\n%s", data)
	}

	hostOnly := rec
	hostOnly.ContainerID = ""
	err = Write(home, hostOnly)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(Path(home, "deadbeef"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "container_id") {
		t.Fatalf("host serve record should omit container_id:\n%s", data)
	}

	err = Remove(home, "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Read(home, "deadbeef")
	if err == nil {
		t.Fatal("expected missing record")
	}
}

func TestFileNameSanitizes(t *testing.T) {
	if FileName("Foo Bar") != "foo-bar" {
		t.Fatalf("%q", FileName("Foo Bar"))
	}
	if FileName("github.com/pastdev/agentcon") != "github-com-pastdev-agentcon" {
		t.Fatalf("%q", FileName("github.com/pastdev/agentcon"))
	}
}

func TestBoundedNameTruncatesLeft(t *testing.T) {
	got := BoundedName("github.com/pastdev/agentcon")
	if got != "github-com-pastdev-agentcon" {
		t.Fatalf("%q", got)
	}
	long := "gitlab.com/very/long/group/name/and/subgroup/myproj"
	got = BoundedName(long)
	if len(got) > boundedMax() {
		t.Fatalf("len %d %q", len(got), got)
	}
	if !strings.HasSuffix(got, "myproj") {
		t.Fatalf("leaf lost: %q", got)
	}
	name := ResourceName(long, "deadbeef", "bouncer")
	if len(name) > maxNameLen {
		t.Fatalf("name len %d %q", len(name), name)
	}
	if !strings.HasPrefix(name, "agentcon-") || !strings.HasSuffix(name, "-deadbeef-bouncer") {
		t.Fatalf("%q", name)
	}
}

func TestResourceNameFitsLimit(t *testing.T) {
	name := ResourceName("github.com/pastdev/agentcon", "deadbeef", "bouncer")
	if name != "agentcon-github-com-pastdev-agentcon-deadbeef-bouncer" {
		t.Fatalf("%q", name)
	}
	if len(name) > maxNameLen {
		t.Fatalf("len %d", len(name))
	}
}

func TestWriteRequiresSlug(t *testing.T) {
	err := Write(t.TempDir(), Record{Context: "foo", ControlAddr: "127.0.0.1:1", Token: "t"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProjectPath(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "home", "me", "git")
	cwd := filepath.Join(root, "github.com", "pastdev", "agentcon")
	if ProjectPath(root, cwd) != "github.com/pastdev/agentcon" {
		t.Fatalf("%q", ProjectPath(root, cwd))
	}
	if ProjectPath(root, root) != "" {
		t.Fatalf("root %q", ProjectPath(root, root))
	}
}

func TestMatch(t *testing.T) {
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

	got, err := Match(recs, Query{Slug: "bbbbbbbb"})
	if err != nil || got.Slug != "bbbbbbbb" {
		t.Fatalf("slug %v %v", got, err)
	}

	got, err = Match(recs, Query{Project: "github.com/pastdev/configloader"})
	if err != nil || got.Slug != "bbbbbbbb" {
		t.Fatalf("project %v %v", got, err)
	}

	got, err = Match(recs, Query{Context: "git", Cwd: filepath.Join(agentcon, "pkg", "run")})
	if err != nil || got.Slug != "aaaaaaaa" {
		t.Fatalf("cwd %v %v", got, err)
	}

	_, err = Match(recs, Query{Project: "github.com/pastdev/agentcon"})
	if err == nil {
		t.Fatal("expected ambiguous project across contexts")
	}
	if _, ok := err.(*AmbiguousError); !ok {
		t.Fatalf("got %v", err)
	}

	got, err = Match(recs, Query{Context: "test"})
	if err != nil || got.Slug != "cccccccc" {
		t.Fatalf("only test %v %v", got, err)
	}
}

func TestFindFromDisk(t *testing.T) {
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
	got, err := Find(home, Query{Cwd: rec.Cwd})
	if err != nil || got.Slug != "deadbeef" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestNewSlug(t *testing.T) {
	s := NewSlug()
	if !ValidSlug(s) {
		t.Fatalf("%q", s)
	}
	if ValidSlug("DEADBEEF") {
		t.Fatal("uppercase slug should be rejected")
	}
	if ValidSlug("abcd") {
		t.Fatal("short slug should be rejected")
	}
}
