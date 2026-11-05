package run

import (
	"fmt"
	"os"
	"sort"
	"strings"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
	"gopkg.in/yaml.v3"
)

func hostEnvCreds(policy []byte, extra []string) (map[string]string, error) {
	overlay, err := parseEnvPairs(extra)
	if err != nil {
		return nil, err
	}
	var cfg bouncercfg.Config
	err = yaml.Unmarshal(policy, &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse bouncer policy: %w", err)
	}
	out := map[string]string{}
	var missing []string
	for name, c := range cfg.Credentials {
		if c == nil || c.Source != "env" {
			continue
		}
		if c.Env == "" {
			return nil, fmt.Errorf("credential %s: source env requires env", name)
		}
		if v := overlay[c.Env]; v != "" {
			out[c.Env] = v
			continue
		}
		v, ok := os.LookupEnv(c.Env)
		if !ok || v == "" {
			missing = append(missing, c.Env)
			continue
		}
		out[c.Env] = v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func parseEnvPairs(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("sidecar env %q must be NAME=value", p)
		}
		out[k] = v
	}
	return out, nil
}
