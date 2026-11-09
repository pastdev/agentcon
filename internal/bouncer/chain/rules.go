package chain

import (
	"fmt"
	"slices"

	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// actionAnonymous is the implicit HTTP default when no rule matches and the
// profile unmatched mode is tunnel: forward, do not attach the credential.
const actionAnonymous = "anonymous"

// Rules evaluates declarative rules: first match wins, else the default.
// Filters listed on a matching allow or approved-ask rule run after the
// verdict, wrapping next. Deny and the service default skip them.
type Rules struct {
	name        string
	rules       []config.Rule
	ruleFilters [][]Filter
	def         string
	defYAML     string
	env         *Env
	ssh         bool
	sshSvc      *config.SSHService
	service     string
}

// NewRules builds the rules filter for an HTTP service.
func NewRules(svc *config.Service, env *Env) *Rules {
	return &Rules{name: "rules:" + svc.Name, rules: svc.Rules, def: svc.DefaultAction(), defYAML: svc.Default, env: env, service: svc.Name}
}

// NewSSHRules builds the rules filter for an SSH service. It also enforces the
// service's capability allowlist before any rule is consulted.
func NewSSHRules(svc *config.SSHService, env *Env) *Rules {
	return &Rules{name: "rules:" + svc.Name, rules: svc.Rules, def: svc.DefaultAction(), env: env, ssh: true, sshSvc: svc, service: svc.Name}
}

// WithRuleFilters attaches compiled filters parallel to svc.Rules.
// A nil or shorter slice means later rules have no extra filters.
func (r *Rules) WithRuleFilters(filters [][]Filter) *Rules {
	if r != nil {
		r.ruleFilters = filters
	}
	return r
}

// WithUnmatched sets the implicit default from the profile unmatched mode.
// An explicit `default:` on the http entry wins. unmatched tunnel with
// rules and no default forwards without the credential. Unmatched deny
// (and tests that skip this) keep deny.
func (r *Rules) WithUnmatched(mode string) *Rules {
	if r == nil || r.defYAML != "" || len(r.rules) == 0 {
		return r
	}
	if mode == config.UnmatchedDeny {
		r.def = config.ActionDeny
		return r
	}
	r.def = actionAnonymous
	return r
}

func (r *Rules) Name() string { return r.name }

func (r *Rules) Handle(req *Request, next Handler) (*Response, error) {
	if r.ssh && req.SSH != nil && !r.sshSvc.Allows(req.SSH.Kind) {
		return Deny(r.name, fmt.Sprintf("ssh %s is not in the allow list for %s", req.SSH.Kind, r.service)), nil
	}
	for i := range r.rules {
		rule := &r.rules[i]
		ok, err := Match(req, rule, r.env)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if ok {
			return r.act(req, next, i, rule.Action, fmt.Sprintf("%s rules[%d]", r.name, i), rule.Reason, rule.Prompt)
		}
	}
	return r.act(req, next, -1, r.def, r.name+" default", "", "")
}

func (r *Rules) wrap(i int, next Handler) Handler {
	if i < 0 || i >= len(r.ruleFilters) || len(r.ruleFilters[i]) == 0 {
		return next
	}
	return Build(r.ruleFilters[i], next)
}

func (r *Rules) act(req *Request, next Handler, i int, action, by, reason, prompt string) (*Response, error) {
	switch action {
	case config.ActionAllow:
		req.AllowedBy = by
		return r.wrap(i, next)(req)
	case actionAnonymous:
		req.AllowedBy = by
		req.SkipCredential = true
		return next(req)
	case config.ActionAsk:
		if r.env == nil || r.env.Approver == nil {
			return Deny(by, "approval required but no approver is configured"), nil
		}
		if prompt == "" {
			prompt = "Allow " + req.Describe() + "?"
		}
		ok, err := r.env.Approver.Ask(req.Ctx, AskRequest{Session: req.Session, Filter: r.name, Prompt: prompt, Request: req.Describe()})
		if err != nil {
			return Deny(by, "approval failed: "+err.Error()), nil //nolint:nilerr // a failed approval is a deny, not an error
		}
		if !ok {
			if reason == "" {
				reason = "denied by user"
			}
			return Deny(by, reason), nil
		}
		req.AllowedBy = by + " (approved)"
		return r.wrap(i, next)(req)
	default:
		if reason == "" {
			reason = "no rule allows " + req.Describe()
			if by != r.name+" default" {
				reason = "denied by " + by
			}
		}
		return Deny(by, reason), nil
	}
}

// Match reports whether all of a rule's matchers match req.
func Match(req *Request, rule *config.Rule, env *Env) (bool, error) {
	isHTTP := req.Transport == TransportHTTP
	if len(rule.Methods) > 0 && (!isHTTP || !slices.Contains(rule.Methods, req.Method)) {
		return false, nil
	}
	if rule.Path != "" && (!isHTTP || !Glob(rule.Path, req.Path())) {
		return false, nil
	}
	if rule.PathRegexp != nil && (!isHTTP || !rule.PathRegexp.MatchString(req.Path())) {
		return false, nil
	}
	if rule.SSH != nil {
		if req.SSH == nil {
			return false, nil
		}
		if len(rule.SSH.Kinds) > 0 && !slices.Contains(rule.SSH.Kinds, req.SSH.Kind) {
			return false, nil
		}
		if rule.SSH.CommandRegexp != nil && !rule.SSH.CommandRegexp.MatchString(req.SSH.Command) {
			return false, nil
		}
	}
	if p := rule.GitLabProject; p != nil {
		ok, err := matchGitLabProject(req, env, p)
		if err != nil || !ok {
			return false, err
		}
	}
	if len(rule.GitHubRepo) > 0 {
		ok, err := matchGitHubRepo(req, rule.GitHubRepo, rule.GitHubSubpaths)
		if err != nil || !ok {
			return false, err
		}
	}
	if g := rule.Git; g != nil {
		ok, err := matchGit(req, g)
		if err != nil || !ok {
			return false, err
		}
	}
	if q := rule.GraphQL; q != nil {
		ok, err := matchGraphQL(req, q)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func matchGit(req *Request, g *config.GitMatch) (bool, error) {
	info := req.Git()
	if info == nil {
		return false, nil
	}
	if g.Service != "" && info.Service != g.Service {
		return false, nil
	}
	if len(g.Refs) == 0 && len(g.Updates) == 0 {
		return true, nil
	}
	push, err := req.Push()
	if err != nil || push == nil {
		return false, err
	}
	for _, u := range push.Updates {
		if len(g.Updates) > 0 && !slices.Contains(g.Updates, u.Type) {
			continue
		}
		if len(g.Refs) > 0 && !slices.ContainsFunc(g.Refs, func(p string) bool { return Glob(p, u.Ref) }) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func matchGraphQL(req *Request, q *config.GraphQLRule) (bool, error) {
	ops, err := req.GraphQL()
	if err != nil || ops == nil {
		return false, err
	}
	for _, op := range ops {
		if len(q.Operations) > 0 && !slices.Contains(q.Operations, op.Type) {
			continue
		}
		if len(q.Fields) == 0 {
			return true, nil
		}
		for _, f := range op.Fields {
			if slices.Contains(q.Fields, f) {
				return true, nil
			}
		}
	}
	return false, nil
}
