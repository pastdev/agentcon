package run

import (
	"context"
	"errors"
	"testing"

	"github.com/pastdev/agentcon/pkg/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
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
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
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

func TestDooDNetwork(t *testing.T) {
	type testCase struct {
		network container.NetworkInfo
		netErr  error
		want    externalNet
		wantErr string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		rt := &captureRuntime{network: tc.network, netErr: tc.netErr}
		got, err := doodNetwork(context.Background(), rt, "dev", "agentcon-x-deadbeef-bouncer")
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("reaches the sidecar by name with no published port", func(t *testing.T) {
		tester(t, testCase{
			network: container.NetworkInfo{Name: "dev", Subnet: "172.30.0.0/16"},
			want:    externalNet{name: "dev", subnet: "172.30.0.0/16", controlAddr: "agentcon-x-deadbeef-bouncer:8228"},
		})
	})
	t.Run("refuses an internal network", func(t *testing.T) {
		tester(t, testCase{
			network: container.NetworkInfo{Name: "dev", Subnet: "172.30.0.0/16", Internal: true},
			wantErr: "DOOD_NETWORK dev is an internal network, so the bouncer sidecar would have no egress",
		})
	})
	t.Run("refuses a network without a subnet", func(t *testing.T) {
		tester(t, testCase{network: container.NetworkInfo{Name: "dev"}, wantErr: "has no subnet"})
	})
	t.Run("reports a failed inspect", func(t *testing.T) {
		tester(t, testCase{netErr: errors.New("no such network"), wantErr: "no such network"})
	})
}

func TestBouncerSidecarSpecOnDooDNetwork(t *testing.T) {
	ext := externalNet{name: "dev", subnet: "172.30.0.0/16", controlAddr: "agentcon-x-deadbeef-bouncer:8228"}
	spec := bouncerSidecarSpec(Request{User: testUser}, sidecarImage, nil, ext, "agent-net", "10.1.0.0/16")
	assert.Equal(t, []string{"dev", "agent-net"}, spec.Networks)
	assert.Empty(t, spec.Ports)
	assert.Contains(t, spec.Env, "MANAGEMENT_NETWORK=172.30.0.0/16")
}
