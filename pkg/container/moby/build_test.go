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

func TestTarDirectoryIncludesDockerfile(t *testing.T) {
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
	if !found["Dockerfile"] || !found["contrib/entrypoint.sh"] {
		t.Fatalf("tar entries %v", found)
	}
}

func TestDisplayBuildError(t *testing.T) {
	in := bytes.NewBufferString(`{"errorDetail":{"message":"boom"},"error":"boom"}` + "\n")
	err := displayBuild(context.Background(), in, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("got %v", err)
	}
}

func TestDisplayBuildStream(t *testing.T) {
	in := bytes.NewBufferString(`{"stream":"Step 1/1\n"}` + "\n")
	var out bytes.Buffer
	err := displayBuild(context.Background(), in, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "Step 1/1\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestDisplayBuildKitTrace(t *testing.T) {
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

	var out bytes.Buffer
	err = displayBuild(context.Background(), bytes.NewReader(append(line, '\n')), &out)
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "load build definition from Dockerfile") {
		t.Fatalf("got %q", got)
	}
}

func TestBuildTagSummary(t *testing.T) {
	if got := buildTagSummary(nil); got != "image" {
		t.Fatalf("empty %q", got)
	}
	got := buildTagSummary([]string{"pastdev.com/agentcon-cursor:latest"})
	if got != "pastdev.com/agentcon-cursor:latest" {
		t.Fatalf("tag %q", got)
	}
}
