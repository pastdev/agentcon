package run

import (
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/container"
	"github.com/stretchr/testify/assert"
)

func TestWithSSHAuthSock(t *testing.T) {
	tester := func(t *testing.T) {
		t.Helper()
		spec := withSSHAuthSock(containerSpecEnvOnly(), "/tmp/agent.sock")
		assert.Equal(t, []container.Mount{{Source: "/tmp/agent.sock", Target: host.SidecarSSHAuthSock}}, spec.Mounts)
		assert.Contains(t, spec.Env, "SSH_AUTH_SOCK="+host.SidecarSSHAuthSock)
	}

	t.Run("binds the socket and sets SSH_AUTH_SOCK", func(t *testing.T) {
		tester(t)
	})
}

func containerSpecEnvOnly() container.Spec {
	return bouncerSidecarSpec(
		Request{Image: testImage, User: testUser},
		sidecarImage,
		nil,
		externalNet{name: "ext-net", subnet: "10.2.0.0/16", hostPort: 18228, controlAddr: "127.0.0.1:18228"},
		"agent-net",
		"10.1.0.0/16",
	)
}
