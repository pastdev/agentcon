package run

import (
	"context"
	"fmt"
	"io"

	"github.com/pastdev/agentcon/pkg/container"
)

// PullPolicy says when run fetches an image from its registry.
type PullPolicy string

const (
	// PullMissing pulls an image only when it is not present locally.
	PullMissing PullPolicy = "missing"
	// PullAlways pulls before every run, and builds refresh their base images.
	PullAlways PullPolicy = "always"
	// PullNever uses only local images.
	PullNever PullPolicy = "never"
)

// ParsePullPolicy checks a policy name. Empty means PullMissing.
func ParsePullPolicy(s string) (PullPolicy, error) {
	switch p := PullPolicy(s); p {
	case "":
		return PullMissing, nil
	case PullMissing, PullAlways, PullNever:
		return p, nil
	}
	return "", fmt.Errorf("unknown pull policy %q (want missing, always, or never)", s)
}

// ensureImage makes image available locally as policy allows. An empty
// policy is PullMissing.
func ensureImage(ctx context.Context, rt container.Runtime, image string, policy PullPolicy, out io.Writer) error {
	if policy == PullAlways {
		return pull(ctx, rt, image, out)
	}
	exists, err := rt.ImageExists(ctx, image)
	if err != nil {
		return fmt.Errorf("check image: %w", err)
	}
	if exists {
		return nil
	}
	if policy == PullNever {
		return fmt.Errorf("image %s is not present locally and the pull policy is never", image)
	}
	return pull(ctx, rt, image, out)
}

func pull(ctx context.Context, rt container.Runtime, image string, out io.Writer) error {
	err := rt.Pull(ctx, image, out)
	if err != nil {
		return fmt.Errorf("fetch image: %w", err)
	}
	return nil
}
