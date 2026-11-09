// Package policy compiles a config into per-profile filter chains.
package policy

import (
	"fmt"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/jsfilter"
	"github.com/pastdev/agentcon/internal/bouncer/kv"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Set is a compiled config.
type Set struct {
	Config   *config.Config
	Profiles map[string]*Profile
}

// Profile is a compiled profile.
type Profile struct {
	Name      string
	Unmatched string
	Tunnel    []string
	// AllowPrivate permits tunnels to non-public addresses.
	AllowPrivate bool
	HTTP         []*Service
	SSH          []*SSHService
}

// Service is an intercepted HTTP service with its full filter chain:
// profile filters, then service filters, then the service's rules.
// A matching allow or approved-ask rule then runs that rule's filters.
type Service struct {
	Config  *config.Service
	Filters []chain.Filter
}

// SSHService is a terminated SSH service with its filter chain.
type SSHService struct {
	Config  *config.SSHService
	Filters []chain.Filter
}

// Compile loads every filter referenced by cfg. Each (profile, filter path)
// pair is loaded once, so a filter attached at several levels still gets
// its own config and pool.
func Compile(cfg *config.Config, env *chain.Env, store *kv.Store) (*Set, error) {
	set := &Set{Config: cfg, Profiles: map[string]*Profile{}}
	for name := range cfg.Profiles {
		rp, err := cfg.ResolvedProfile(name)
		if err != nil {
			return nil, fmt.Errorf("resolve profile: %w", err)
		}
		p := &Profile{Name: name, Unmatched: rp.UnmatchedMode(), Tunnel: rp.Tunnel, AllowPrivate: rp.AllowPrivate != nil && *rp.AllowPrivate}
		load := func(refs []config.FilterRef) ([]chain.Filter, error) {
			var out []chain.Filter
			for _, ref := range refs {
				f, err := jsfilter.Load(jsfilter.Options{Path: ref.Path, Config: ref.Config, Timeout: ref.Timeout.D, Env: env, KV: store})
				if err != nil {
					return nil, fmt.Errorf("profile %q: %w", name, err)
				}
				out = append(out, f)
			}
			return out, nil
		}
		profileFilters, err := load(rp.Filters)
		if err != nil {
			return nil, err
		}
		loadRuleFilters := func(rules []config.Rule) ([][]chain.Filter, error) {
			out := make([][]chain.Filter, len(rules))
			for i, rule := range rules {
				fs, err := load(rule.Filters)
				if err != nil {
					return nil, err
				}
				out[i] = fs
			}
			return out, nil
		}
		for _, s := range rp.HTTP {
			sf, err := load(s.Filters)
			if err != nil {
				return nil, err
			}
			rf, err := loadRuleFilters(s.Rules)
			if err != nil {
				return nil, err
			}
			fs := append(append(append([]chain.Filter{}, profileFilters...), sf...), chain.NewRules(s, env).WithRuleFilters(rf).WithUnmatched(p.Unmatched))
			p.HTTP = append(p.HTTP, &Service{Config: s, Filters: fs})
		}
		for _, s := range rp.SSH {
			sf, err := load(s.Filters)
			if err != nil {
				return nil, err
			}
			rf, err := loadRuleFilters(s.Rules)
			if err != nil {
				return nil, err
			}
			fs := append(append(append([]chain.Filter{}, profileFilters...), sf...), chain.NewSSHRules(s, env).WithRuleFilters(rf))
			p.SSH = append(p.SSH, &SSHService{Config: s, Filters: fs})
		}
		set.Profiles[name] = p
	}
	return set, nil
}

// MatchHTTP returns the first http entry whose hosts match host[:port].
func (p *Profile) MatchHTTP(hostport string) *Service {
	for _, s := range p.HTTP {
		if config.HostMatches(s.Config.Hosts, hostport) {
			return s
		}
	}
	return nil
}

// Tunnels reports whether an unmatched host may be tunneled.
func (p *Profile) Tunnels(hostport string) bool {
	return p.Unmatched != config.UnmatchedDeny || config.HostMatches(p.Tunnel, hostport)
}

// MatchSSH returns the first SSH service whose hosts match host.
func (p *Profile) MatchSSH(host string) *SSHService {
	for _, s := range p.SSH {
		if config.HostMatches(s.Config.Hosts, host) {
			return s
		}
	}
	return nil
}
