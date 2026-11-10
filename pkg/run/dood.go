package run

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pastdev/agentcon/pkg/container"
)

const (
	envDooDNetwork     = "DOOD_NETWORK"
	envDooDMountPrefix = "DOOD_MOUNT_"
)

// DooD describes a Docker-outside-of-Docker environment: agentcon runs in a
// container that drives the host's Docker daemon, so paths and loopback
// addresses it sees are not the daemon's.
type DooD struct {
	// Network is a Docker network this container is attached to. It is
	// assumed to have egress to the public internet.
	Network string
	// Mounts say which Docker volume backs each path in this container.
	Mounts []VolumePath
}

// VolumePath says Path in this container is the Docker volume Volume.
type VolumePath struct {
	Volume string
	Path   string
}

// ParseDooD reads DOOD_NETWORK and each DOOD_MOUNT_<NAME>=<volume>:<path>
// from environ. It returns nil when neither is set.
func ParseDooD(environ []string) (*DooD, error) {
	d := &DooD{}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		switch {
		case name == envDooDNetwork:
			d.Network = value
		case strings.HasPrefix(name, envDooDMountPrefix) && len(name) > len(envDooDMountPrefix):
			volume, path, ok := strings.Cut(value, ":")
			if !ok || volume == "" || !filepath.IsAbs(path) {
				return nil, fmt.Errorf("%s=%q: want <volume>:<absolute path>", name, value)
			}
			d.Mounts = append(d.Mounts, VolumePath{Volume: volume, Path: filepath.Clean(path)})
		}
	}
	if d.Network == "" && len(d.Mounts) == 0 {
		return nil, nil
	}
	sort.Slice(d.Mounts, func(i, j int) bool { return d.Mounts[i].Path < d.Mounts[j].Path })
	return d, nil
}

// translateMounts turns each bind source into a subpath of the volume that
// backs it, because the Docker daemon cannot see this container's paths.
// The longest matching DOOD_MOUNT_* path wins. Without DOOD_MOUNT_* the
// mounts are returned unchanged.
func translateMounts(mounts []container.Mount, d *DooD) ([]container.Mount, error) {
	if d == nil || len(d.Mounts) == 0 {
		return mounts, nil
	}
	out := make([]container.Mount, 0, len(mounts))
	for _, m := range mounts {
		if m.Volume != "" {
			out = append(out, m)
			continue
		}
		vp, rel, ok := d.volumeFor(m.Source)
		if !ok {
			return nil, fmt.Errorf("mount source %s is not under any %s* path, so the Docker host cannot see it", m.Source, envDooDMountPrefix)
		}
		m.Volume = vp.Volume
		m.Subpath = rel
		out = append(out, m)
	}
	return out, nil
}

// volumeFor finds the volume backing path and path's location inside it.
func (d *DooD) volumeFor(path string) (VolumePath, string, bool) {
	path = filepath.Clean(path)
	var best VolumePath
	var bestRel string
	found := false
	for _, vp := range d.Mounts {
		rel, err := filepath.Rel(vp.Path, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if found && len(vp.Path) <= len(best.Path) {
			continue
		}
		best, found = vp, true
		bestRel = filepath.ToSlash(rel)
		if bestRel == "." {
			bestRel = ""
		}
	}
	return best, bestRel, found
}

// externalNet is the bouncer sidecar's external network and the address
// agentcon uses for the sidecar's management API.
type externalNet struct {
	name   string
	subnet string
	// hostPort is published on the host loopback. Zero publishes nothing.
	hostPort    int
	controlAddr string
}

// doodNetwork uses DOOD_NETWORK as the sidecar's external network. This
// container is attached to it, so it reaches the sidecar by container name
// and needs no published port.
func doodNetwork(ctx context.Context, rt container.Runtime, network, sidecarName string) (externalNet, error) {
	info, err := rt.InspectNetwork(ctx, network)
	if err != nil {
		return externalNet{}, fmt.Errorf("inspect %s %s: %w", envDooDNetwork, network, err)
	}
	if info.Internal {
		return externalNet{}, fmt.Errorf("%s %s is an internal network, so the bouncer sidecar would have no egress", envDooDNetwork, network)
	}
	if info.Subnet == "" {
		return externalNet{}, fmt.Errorf("%s %s has no subnet", envDooDNetwork, network)
	}
	return externalNet{
		name:        network,
		subnet:      info.Subnet,
		controlAddr: net.JoinHostPort(sidecarName, defaultProxyPort),
	}, nil
}
