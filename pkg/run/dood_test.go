package run

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pastdev/agentcon/pkg/container"
)

func TestParseDooD(t *testing.T) {
	type testCase struct {
		environ []string
		want    *DooD
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := ParseDooD(tc.environ)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("got %+v, want %+v", got, tc.want)
		}
	}

	t.Run("nil without the variables", func(t *testing.T) {
		tester(t, testCase{environ: []string{"HOME=/home/me", "PATH=/usr/bin"}})
	})
	t.Run("reads the network and mounts sorted by path", func(t *testing.T) {
		tester(t, testCase{
			environ: []string{
				"DOOD_NETWORK=dev",
				"DOOD_MOUNT_WORKSPACE=dev-workspace:/workspace",
				"DOOD_MOUNT_HOME=dev-home:/home/me/",
				"HOME=/home/me",
			},
			want: &DooD{
				Network: "dev",
				Mounts: []VolumePath{
					{Volume: "dev-home", Path: "/home/me"},
					{Volume: "dev-workspace", Path: "/workspace"},
				},
			},
		})
	})
	t.Run("reads mounts without a network", func(t *testing.T) {
		tester(t, testCase{
			environ: []string{"DOOD_MOUNT_DATA=data:/data"},
			want:    &DooD{Mounts: []VolumePath{{Volume: "data", Path: "/data"}}},
		})
	})
	t.Run("ignores the bare prefix", func(t *testing.T) {
		tester(t, testCase{environ: []string{"DOOD_MOUNT_=x:/x"}})
	})
	t.Run("rejects a mount without a volume", func(t *testing.T) {
		tester(t, testCase{environ: []string{"DOOD_MOUNT_HOME=:/home/me"}, wantErr: "DOOD_MOUNT_HOME"})
	})
	t.Run("rejects a relative path", func(t *testing.T) {
		tester(t, testCase{environ: []string{"DOOD_MOUNT_HOME=dev-home:home/me"}, wantErr: "absolute path"})
	})
}

func TestTranslateMounts(t *testing.T) {
	dood := &DooD{Mounts: []VolumePath{
		{Volume: "dev-root", Path: "/"},
		{Volume: "dev-home", Path: "/home/me"},
		{Volume: "dev-workspace", Path: "/workspace"},
	}}
	type testCase struct {
		dood    *DooD
		in      []container.Mount
		want    []container.Mount
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := translateMounts(tc.in, tc.dood)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("got %+v, want %+v", got, tc.want)
		}
	}
	binds := []container.Mount{{Source: "/home/me/git", Target: "/workspace"}}

	t.Run("leaves binds alone without DooD", func(t *testing.T) {
		tester(t, testCase{in: binds, want: binds})
	})
	t.Run("leaves binds alone with only a network", func(t *testing.T) {
		tester(t, testCase{dood: &DooD{Network: "dev"}, in: binds, want: binds})
	})
	t.Run("uses the longest matching path", func(t *testing.T) {
		tester(t, testCase{
			dood: dood,
			in: []container.Mount{
				{Source: "/workspace/github.com", Target: "/workspace"},
				{Source: "/home/me/.cursor", Target: "/agent/cursor"},
				{Source: "/opt/tools", Target: "/tools"},
			},
			want: []container.Mount{
				{Source: "/workspace/github.com", Target: "/workspace", Volume: "dev-workspace", Subpath: "github.com"},
				{Source: "/home/me/.cursor", Target: "/agent/cursor", Volume: "dev-home", Subpath: ".cursor"},
				{Source: "/opt/tools", Target: "/tools", Volume: "dev-root", Subpath: "opt/tools"},
			},
		})
	})
	t.Run("mounts a whole volume for its own path", func(t *testing.T) {
		tester(t, testCase{
			dood: dood,
			in:   []container.Mount{{Source: "/workspace/", Target: "/workspace"}},
			want: []container.Mount{{Source: "/workspace/", Target: "/workspace", Volume: "dev-workspace"}},
		})
	})
	t.Run("does not match a sibling with a shared prefix", func(t *testing.T) {
		tester(t, testCase{
			dood:    &DooD{Mounts: []VolumePath{{Volume: "dev-workspace", Path: "/workspace"}}},
			in:      []container.Mount{{Source: "/workspace-old/x", Target: "/x"}},
			wantErr: "mount source /workspace-old/x is not under any DOOD_MOUNT_* path",
		})
	})
	t.Run("refuses a source under no volume", func(t *testing.T) {
		tester(t, testCase{
			dood:    &DooD{Mounts: []VolumePath{{Volume: "dev-home", Path: "/home/me"}}},
			in:      []container.Mount{{Source: "/tmp/ssh-agent.sock", Target: "/opt/agentcon/ssh-agent.sock"}},
			wantErr: "/tmp/ssh-agent.sock",
		})
	})
}
