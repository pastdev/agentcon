package daemon

import (
	"testing"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

func TestPlanListenDefault(t *testing.T) {
	t.Setenv("AGENT_NETWORK", "")
	t.Setenv("MANAGEMENT_NETWORK", "")
	plan, err := planListen(&config.Config{Listen: "127.0.0.1:8228", SSHListen: "127.0.0.1:8229"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.split {
		t.Fatal("expected combined listen")
	}
	if plan.proxy != "127.0.0.1:8228" || plan.mgmt != "127.0.0.1:8228" {
		t.Fatalf("plan %+v", plan)
	}
}

func TestPlanListenRequiresBoth(t *testing.T) {
	t.Setenv("AGENT_NETWORK", "10.0.0.0/16")
	t.Setenv("MANAGEMENT_NETWORK", "")
	_, err := planListen(&config.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}
