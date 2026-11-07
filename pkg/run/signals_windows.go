//go:build windows

package run

import (
	"context"
	"os"
	"os/signal"
)

func notifyRunSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt)
}
