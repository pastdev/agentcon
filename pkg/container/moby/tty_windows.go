//go:build windows

package moby

import (
	"context"

	"github.com/pastdev/agentcon/pkg/container"
)

func (r *Runtime) monitorTtySize(ctx context.Context, id string, spec container.Spec) func() {
	r.resizeTty(ctx, id, spec)
	return func() {}
}
