package moby

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/pastdev/agentcon/pkg/container"
)

func TestMounts(t *testing.T) {
	type testCase struct {
		in   []container.Mount
		want []mount.Mount
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got := mounts(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("got %+v, want %+v", got, tc.want)
		}
	}

	t.Run("binds a source", func(t *testing.T) {
		tester(t, testCase{
			in:   []container.Mount{{Source: "/home/me/git", Target: "/workspace"}},
			want: []mount.Mount{{Type: mount.TypeBind, Source: "/home/me/git", Target: "/workspace"}},
		})
	})
	t.Run("mounts a volume subpath", func(t *testing.T) {
		tester(t, testCase{
			in: []container.Mount{{Source: "/workspace/git", Target: "/workspace", Volume: "dev-workspace", Subpath: "git"}},
			want: []mount.Mount{{
				Type:          mount.TypeVolume,
				Source:        "dev-workspace",
				Target:        "/workspace",
				VolumeOptions: &mount.VolumeOptions{Subpath: "git"},
			}},
		})
	})
}

func TestInspectNetwork(t *testing.T) {
	for _, internal := range []bool{false, true} {
		inspected := network.Inspect{}
		inspected.ID = "abc"
		inspected.Name = "dev"
		inspected.Internal = internal
		inspected.IPAM.Config = []network.IPAMConfig{{Subnet: netip.MustParsePrefix("172.30.0.0/16")}}
		r := &Runtime{api: &fakeAPI{network: inspected}}
		got, err := r.InspectNetwork(context.Background(), "dev")
		if err != nil {
			t.Fatal(err)
		}
		want := container.NetworkInfo{ID: "abc", Name: "dev", Subnet: "172.30.0.0/16", Internal: internal}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
}
