package moby

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBuildInputs(t *testing.T) {
	type testCase struct {
		files          map[string]string
		dockerfile     string
		wantDir        string
		wantDockerfile string
		wantExcludes   []string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		root := t.TempDir()
		for name, body := range tc.files {
			path := filepath.Join(root, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		}
		got, err := buildInputs(root, tc.dockerfile)
		require.NoError(t, err)
		assert.Equal(t, buildInput{
			contextDir:     root,
			dockerfileDir:  filepath.Join(root, tc.wantDir),
			dockerfileName: tc.wantDockerfile,
			excludes:       tc.wantExcludes,
		}, got)
	}

	t.Run("defaults to Dockerfile at the root with no excludes", func(t *testing.T) {
		tester(t, testCase{files: map[string]string{"Dockerfile": "FROM scratch\n"}, wantDockerfile: "Dockerfile"})
	})
	t.Run("serves a Dockerfile in a subdirectory", func(t *testing.T) {
		tester(t, testCase{
			files:          map[string]string{"build/app.Dockerfile": "FROM scratch\n"},
			dockerfile:     "build/app.Dockerfile",
			wantDir:        "build",
			wantDockerfile: "app.Dockerfile",
		})
	})
	t.Run("reads .dockerignore at the root", func(t *testing.T) {
		tester(t, testCase{
			files:          map[string]string{".dockerignore": ".git\n# comment\n*.tmp\n"},
			wantDockerfile: "Dockerfile",
			wantExcludes:   []string{".git", "*.tmp"},
		})
	})
	t.Run("prefers the Dockerfile's own ignore file", func(t *testing.T) {
		tester(t, testCase{
			files: map[string]string{
				".dockerignore":                     "root-rule\n",
				"build/app.Dockerfile.dockerignore": "own-rule\n",
			},
			dockerfile:     "build/app.Dockerfile",
			wantDir:        "build",
			wantDockerfile: "app.Dockerfile",
			wantExcludes:   []string{"own-rule"},
		})
	})
}

func TestBuildSession(t *testing.T) {
	type testCase struct {
		api     *fakeAPI
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r := &Runtime{api: tc.api}
		err := r.Build(ctx, container.Build{
			Context:    t.TempDir(),
			Dockerfile: "Dockerfile",
			Tags:       []string{"agentcon/test:latest"},
			Output:     io.Discard,
		})
		// Build returns only after its session goroutine ends, so returning
		// at all shows the session was closed.
		require.NoError(t, ctx.Err(), "build did not return")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		opts := tc.api.buildOpts
		assert.Nil(t, tc.api.buildBody, "build body")
		assert.NotEmpty(t, opts.SessionID)
		assert.Equal(t, "client-session", opts.RemoteContext)
		assert.Equal(t, "Dockerfile", opts.Dockerfile)
		assert.Equal(t, []string{"agentcon/test:latest"}, opts.Tags)
		assert.Equal(t, []string{"/session h2c"}, tc.api.dialed)
	}

	t.Run("builds through a session", func(t *testing.T) {
		tester(t, testCase{api: &fakeAPI{sessionUp: make(chan struct{})}})
	})
	t.Run("closes the session after a failed build", func(t *testing.T) {
		tester(t, testCase{api: &fakeAPI{buildErr: errors.New("daemon said no")}, wantErr: "daemon said no"})
	})
	t.Run("stops waiting when the session cannot connect", func(t *testing.T) {
		tester(t, testCase{
			api:     &fakeAPI{buildWaits: true, dialErr: errors.New("hijack refused")},
			wantErr: "build session: failed to dial gRPC: hijack refused",
		})
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
