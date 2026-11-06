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
	got, err := Read(home, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if got.ControlAddr != rec.ControlAddr || got.Token != rec.Token || got.ContainerID != rec.ContainerID || got.PID != rec.PID {
		t.Fatalf("%+v", got)
	}
	data, err := os.ReadFile(Path(home, "foo"))
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
	data, err = os.ReadFile(Path(home, "foo"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "container_id") {
		t.Fatalf("host serve record should omit container_id:\n%s", data)
	}

	err = Remove(home, "foo")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Read(home, "foo")
	if err == nil {
		t.Fatal("expected missing record")
	}
}

func TestFileNameSanitizes(t *testing.T) {
	if FileName("Foo Bar") != "foo-bar" {
		t.Fatalf("%q", FileName("Foo Bar"))
	}
	if Path("/home/u", "foo") != filepath.Join("/home/u", ".local", "state", "agentcon", "running", "foo.yml") {
		t.Fatalf("%q", Path("/home/u", "foo"))
	}
}

func TestWriteRequiresFields(t *testing.T) {
	err := Write(t.TempDir(), Record{Context: "foo"})
	if err == nil {
		t.Fatal("expected error")
	}
}
