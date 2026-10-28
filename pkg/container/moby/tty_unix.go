//go:build unix

package moby

import (
	"context"
	"os"
	"os/signal"

	"github.com/pastdev/agentcon/pkg/container"
	"golang.org/x/sys/unix"
)

func (r *Runtime) monitorTtySize(ctx context.Context, id string, spec container.Spec) func() {
	r.resizeTty(ctx, id, spec)
	if !spec.TTY {
		return func() {}
	}

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-winch:
				r.resizeTty(ctx, id, spec)
			}
		}
	}()
	return func() {
		signal.Stop(winch)
		close(done)
	}
}
