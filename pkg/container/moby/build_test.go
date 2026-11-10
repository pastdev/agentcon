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
	"testing"

	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTarDirectory(t *testing.T) {
	tester := func(t *testing.T, root string, want []string) {
		t.Helper()
		r, err := tarDirectory(root)
		require.NoError(t, err)
		var found []string
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			found = append(found, hdr.Name)
		}
		assert.Subset(t, found, want)
	}

	t.Run("includes the dockerfile and contrib files", func(t *testing.T) {
		root := t.TempDir()
		err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM scratch\n"), 0o600)
		require.NoError(t, err)
		err = os.MkdirAll(filepath.Join(root, "contrib"), 0o700)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(root, "contrib", "entrypoint.sh"), []byte("#!/bin/sh\n"), 0o600)
		require.NoError(t, err)
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.wantOut != "" {
			assert.Equal(t, tc.wantOut, out.String())
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
		require.NoError(t, err)
		aux, err := json.Marshal(raw)
		require.NoError(t, err)
		msg := jsonstream.Message{
			ID:  buildkitTraceID,
			Aux: (*json.RawMessage)(&aux),
		}
		line, err := json.Marshal(msg)
		require.NoError(t, err)
		tester(t, testCase{
			in: bytes.NewReader(append(line, '\n')),
			check: func(t *testing.T, got string) {
				t.Helper()
				assert.Contains(t, got, "load build definition from Dockerfile")
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
		assert.Equal(t, tc.want, got)
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
