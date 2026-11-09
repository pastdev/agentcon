package moby

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/pastdev/agentcon/pkg/container"
)

// fakeAPI implements only the calls a test makes. Any other call panics on
// the nil embedded interface.
type fakeAPI struct {
	apiClient
	inspectErr error
	pullErr    error
	pullBody   string
	pulled     string
	buildOpts  client.ImageBuildOptions
	network    network.Inspect
}

func (f *fakeAPI) ImageInspect(context.Context, string, ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	return client.ImageInspectResult{}, f.inspectErr
}

func (f *fakeAPI) ImagePull(_ context.Context, ref string, _ client.ImagePullOptions) (client.ImagePullResponse, error) {
	f.pulled = ref
	if f.pullErr != nil {
		return nil, f.pullErr
	}
	return fakePull{io.NopCloser(strings.NewReader(f.pullBody))}, nil
}

func (f *fakeAPI) ImageBuild(_ context.Context, _ io.Reader, opts client.ImageBuildOptions) (client.ImageBuildResult, error) {
	f.buildOpts = opts
	return client.ImageBuildResult{Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (f *fakeAPI) NetworkInspect(context.Context, string, client.NetworkInspectOptions) (client.NetworkInspectResult, error) {
	return client.NetworkInspectResult{Network: f.network}, nil
}

type fakePull struct {
	io.ReadCloser
}

func (fakePull) JSONMessages(context.Context) iter.Seq2[jsonstream.Message, error] { return nil }
func (fakePull) Wait(context.Context) error                                        { return nil }

func TestImageExists(t *testing.T) {
	type testCase struct {
		inspectErr error
		want       bool
		wantErr    bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		r := &Runtime{api: &fakeAPI{inspectErr: tc.inspectErr}}
		got, err := r.ImageExists(context.Background(), "example/image:1")
		if tc.wantErr != (err != nil) {
			t.Fatalf("err = %v", err)
		}
		if got != tc.want {
			t.Fatalf("got %v", got)
		}
	}

	t.Run("present", func(t *testing.T) {
		tester(t, testCase{want: true})
	})
	t.Run("absent", func(t *testing.T) {
		tester(t, testCase{inspectErr: cerrdefs.ErrNotFound.WithMessage("no such image")})
	})
	t.Run("daemon error", func(t *testing.T) {
		tester(t, testCase{inspectErr: errors.New("connection refused"), wantErr: true})
	})
}

func TestPull(t *testing.T) {
	type testCase struct {
		pullErr     error
		body        string
		wantOut     string
		wantErr     string
		wantPrivate bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		f := &fakeAPI{pullErr: tc.pullErr, pullBody: tc.body}
		r := &Runtime{api: f}
		var out bytes.Buffer
		err := r.Pull(context.Background(), "example/image:1", &out)
		if f.pulled != "example/image:1" {
			t.Fatalf("pulled %q", f.pulled)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			if tc.wantPrivate != strings.Contains(err.Error(), "docker pull example/image:1") {
				t.Fatalf("private image hint: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if out.String() != tc.wantOut {
			t.Fatalf("out %q, want %q", out.String(), tc.wantOut)
		}
	}

	t.Run("prints status lines and skips progress updates", func(t *testing.T) {
		tester(t, testCase{
			body: `{"status":"Pulling from example/image","id":"1"}
{"status":"Pulling fs layer","progressDetail":{},"id":"abc"}
{"status":"Downloading","progressDetail":{"current":10,"total":100},"id":"abc"}
{"status":"Download complete","progressDetail":{},"id":"abc"}
{"status":"Pull complete","progressDetail":{},"id":"abc"}
{"status":"Status: Downloaded newer image for example/image:1"}
`,
			wantOut: "pulling example/image:1\n1: Pulling from example/image\nabc: Pulling fs layer\nabc: Download complete\nabc: Pull complete\nStatus: Downloaded newer image for example/image:1\n",
		})
	})
	t.Run("returns a stream error", func(t *testing.T) {
		tester(t, testCase{body: `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}` + "\n", wantErr: "manifest unknown"})
	})
	t.Run("explains a refused pull", func(t *testing.T) {
		tester(t, testCase{pullErr: cerrdefs.ErrUnauthenticated.WithMessage("pull access denied"), wantErr: "pull access denied", wantPrivate: true})
	})
	t.Run("does not blame credentials for other failures", func(t *testing.T) {
		tester(t, testCase{pullErr: errors.New("connection refused"), wantErr: "connection refused"})
	})
}

func TestBuildPullParent(t *testing.T) {
	for _, pull := range []bool{false, true} {
		f := &fakeAPI{}
		r := &Runtime{api: f}
		err := r.Build(context.Background(), container.Build{Context: t.TempDir(), Output: io.Discard, PullParent: pull})
		if err != nil {
			t.Fatal(err)
		}
		if f.buildOpts.PullParent != pull {
			t.Fatalf("PullParent %v, want %v", f.buildOpts.PullParent, pull)
		}
	}
}
