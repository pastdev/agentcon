package app

import (
	"fmt"
	"sort"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/policy"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// ProfileInfo is a compiled profile summary from Check.
type ProfileInfo struct {
	Name      string
	HTTP      int
	SSH       int
	Unmatched string
}

// CheckResult is the outcome of compiling a policy file.
type CheckResult struct {
	Path     string
	Profiles []ProfileInfo
}

// Check compiles every filter in an already-loaded service config.
func Check(cfg *config.Config) (CheckResult, error) {
	if cfg == nil {
		return CheckResult{}, fmt.Errorf("bouncer config is required")
	}
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	if err != nil {
		return CheckResult{}, fmt.Errorf("compile policy: %w", err)
	}
	names := make([]string, 0, len(set.Profiles))
	for name := range set.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	out := CheckResult{Path: cfg.Path, Profiles: make([]ProfileInfo, 0, len(names))}
	for _, name := range names {
		p := set.Profiles[name]
		out.Profiles = append(out.Profiles, ProfileInfo{
			Name:      name,
			HTTP:      len(p.HTTP),
			SSH:       len(p.SSH),
			Unmatched: p.Unmatched,
		})
	}
	return out, nil
}
