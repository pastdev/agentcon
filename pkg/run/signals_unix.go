//go:build unix

package run

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func notifyRunSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}
