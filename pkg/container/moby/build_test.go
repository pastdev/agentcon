package moby

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/moby/api/types/jsonstream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTarDirectory(t *testing.T) {
	tester := func(t *testing.T, root string, want []string) {
		t.Helper()
		r, err := tarDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			found[hdr.Name] = true
		}
		for _, name := range want {
			if !found[name] {
				t.Fatalf("tar entries %v, want %s", found, name)
			}
		}
	}

	t.Run("includes the dockerfile and contrib files", func(t *testing.T) {
		root := t.TempDir()
		err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		err = os.MkdirAll(filepath.Join(root, "contrib"), 0o700)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(root, "contrib", "entrypoint.sh"), []byte("#!/bin/sh\n"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, root, []string{"Dockerfile", "contrib/entrypoint.sh"})
	})
}

func TestDisplayBuild(t *testing.T) {
	type testCase struct {
		in      io.Reader
		wantErr string
		wantOut string
		check   func(*testing.T, string)
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		var out bytes.Buffer
		err := displayBuild(context.Background(), tc.in, &out)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantOut != "" && out.String() != tc.wantOut {
			t.Fatalf("got %q", out.String())
		}
		if tc.check != nil {
			tc.check(t, out.String())
		}
	}

	t.Run("returns an error detail", func(t *testing.T) {
		tester(t, testCase{
			in:      bytes.NewBufferString(`{"errorDetail":{"message":"boom"},"error":"boom"}` + "\n"),
			wantErr: "boom",
		})
	})
	t.Run("prints stream lines", func(t *testing.T) {
		tester(t, testCase{
			in:      bytes.NewBufferString(`{"stream":"Step 1/1\n"}` + "\n"),
			wantOut: "Step 1/1\n",
		})
	})
	t.Run("prints a buildkit trace vertex", func(t *testing.T) {
		started := timestamppb.Now()
		resp := &controlapi.StatusResponse{
			Vertexes: []*controlapi.Vertex{{
				Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Name:      "[internal] load build definition from Dockerfile",
				Started:   started,
				Completed: started,
			}},
		}
		raw, err := proto.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		aux, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		msg := jsonstream.Message{
			ID:  buildkitTraceID,
			Aux: (*json.RawMessage)(&aux),
		}
		line, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		tester(t, testCase{
			in: bytes.NewReader(append(line, '\n')),
			check: func(t *testing.T, got string) {
				t.Helper()
				if !strings.Contains(got, "load build definition from Dockerfile") {
					t.Fatalf("got %q", got)
				}
			},
		})
	})
}

func TestBuildTagSummary(t *testing.T) {
	type testCase struct {
		tags []string
		want string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := buildTagSummary(tc.tags)
		if got != tc.want {
			t.Fatalf("got %q", got)
		}
	}

	t.Run("falls back to image when tags are empty", func(t *testing.T) {
		tester(t, testCase{want: "image"})
	})
	t.Run("uses the first tag", func(t *testing.T) {
		tester(t, testCase{
			tags: []string{"pastdev.com/agentcon-cursor:latest"},
			want: "pastdev.com/agentcon-cursor:latest",
		})
	})
}

func TestTarFiles(t *testing.T) {
	files := map[string][]byte{
		"Dockerfile":    []byte("FROM scratch\n"),
		"ca/extra.pem":  []byte("-----BEGIN CERTIFICATE-----\n"),
		"ca/second.pem": []byte("second\n"),
	}
	first, err := tarFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := io.ReadAll(first)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var order []string
	tr := tar.NewReader(bytes.NewReader(firstBytes))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = string(b)
		order = append(order, h.Name)
	}
	for name, data := range files {
		if got[name] != string(data) {
			t.Fatalf("%s = %q, want %q", name, got[name], data)
		}
	}
	if strings.Join(order, ",") != "Dockerfile,ca/extra.pem,ca/second.pem" {
		t.Fatalf("order %v", order)
	}
	second, err := tarFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same files packed differently")
	}
}
