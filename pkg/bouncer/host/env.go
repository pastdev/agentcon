package host

import (
	"fmt"
	"os"
	"sort"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

func envCreds(policy []byte, extra []string) (map[string]string, error) {
	overlay, err := parseEnvPairs(extra)
	if err != nil {
		return nil, err
	}
	cfg, err := parsePolicy(policy)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, c := range cfg.Credentials {
		for _, slot := range c.Slots() {
			if slot.Source.Source == "env" {
				names[slot.Source.Env] = true
			}
		}
	}
	for _, a := range bouncercfg.BitwardenAccounts(cfg.Credentials) {
		if a.Password != nil && a.Password.Source == "env" {
			names[a.Password.Env] = true
		}
	}
	out := map[string]string{}
	var missing []string
	for name := range names {
		if v := overlay[name]; v != "" {
			out[name] = v
			continue
		}
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			missing = append(missing, name)
			continue
		}
		out[name] = v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func parseEnvPairs(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for i, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			// By position: a mistyped entry may hold the secret itself.
			return nil, fmt.Errorf("sidecar env entry %d must be NAME=value", i+1)
		}
		out[k] = v
	}
	return out, nil
}
