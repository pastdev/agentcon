//go:build integration

package moby

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/stretchr/testify/require"
)

// dockerClient connects to the Docker daemon in the environment and pings it
// once per test binary. A healthy daemon answers in milliseconds, and a
// missing socket fails at once, so the timeout only bounds a hung daemon.
var dockerClient = sync.OnceValues(func() (*client.Client, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = c.Ping(ctx, client.PingOptions{})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("docker ping: %w", err)
	}
	return c, nil
})

// requireDocker returns a client for the Docker daemon in the environment,
// or skips the test when none answers. The client is shared by every test.
func requireDocker(t *testing.T) *client.Client {
	t.Helper()
	c, err := dockerClient()
	if err != nil {
		t.Skipf("docker not available: %v", err)
	}
	return c
}

// TestBuildIntegration builds a context that needs BuildKit several times,
// each under a deadline, so a build that stalls fails instead of hanging.
// The Dockerfile checks that .dockerignore kept a file out of the context.
func TestBuildIntegration(t *testing.T) {
	const tag = "agentcon/build-integration:test"
	c := requireDocker(t)
	r := &Runtime{api: c}
	t.Cleanup(func() {
		_, _ = c.ImageRemove(context.Background(), tag, client.ImageRemoveOptions{Force: true})
	})
	tester := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		var out bytes.Buffer
		err := r.Build(ctx, container.Build{
			Context: filepath.Join("testdata", "session-build"),
			Tags:    []string{tag},
			Output:  &out,
		})
		require.NoError(t, err, out.String())
	}

	for i := 1; i <= 5; i++ {
		t.Run(fmt.Sprintf("build %d", i), func(t *testing.T) {
			tester(t)
		})
	}
}
