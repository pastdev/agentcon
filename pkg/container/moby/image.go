package moby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/client"
)

func (r *Runtime) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := r.api.ImageInspect(ctx, ref)
	if cerrdefs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect image %s: %w", ref, err)
	}
	return true, nil
}

func (r *Runtime) Pull(ctx context.Context, ref string, out io.Writer) error {
	if out == nil {
		out = os.Stderr
	}
	_, err := fmt.Fprintf(out, "pulling %s\n", ref)
	if err != nil {
		return fmt.Errorf("write pull header: %w", err)
	}
	resp, err := r.api.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return pullError(ref, err)
	}
	defer func() { _ = resp.Close() }()
	return displayPull(ctx, resp, out, ref)
}

// pullError explains a refused pull. agentcon sends no registry
// credentials, so a private image has to be pulled with docker first.
func pullError(ref string, err error) error {
	if cerrdefs.IsUnauthorized(err) || cerrdefs.IsNotFound(err) || cerrdefs.IsPermissionDenied(err) {
		return fmt.Errorf("pull %s (agentcon pulls without registry credentials, so run `docker pull %s` for a private image): %w", ref, ref, err)
	}
	return fmt.Errorf("pull %s: %w", ref, err)
}

// displayPull prints one line per status change and skips the repeated
// download and extract progress updates.
func displayPull(ctx context.Context, in io.Reader, out io.Writer, ref string) error {
	dec := json.NewDecoder(in)
	for {
		err := ctx.Err()
		if err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		var msg jsonstream.Message
		err = dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode pull output: %w", err)
		}
		if msg.Error != nil {
			return pullError(ref, msg.Error)
		}
		// Status lines such as "Pull complete" carry an empty progress
		// object, so only a counted update is skipped.
		if msg.Status == "" || (msg.Progress != nil && msg.Progress.Current > 0) {
			continue
		}
		line := msg.Status
		if msg.ID != "" {
			line = msg.ID + ": " + msg.Status
		}
		_, err = fmt.Fprintln(out, line)
		if err != nil {
			return fmt.Errorf("write pull status: %w", err)
		}
	}
}
