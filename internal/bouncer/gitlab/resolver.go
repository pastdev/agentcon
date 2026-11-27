// Package gitlab looks up GitLab data that rules need to decide a request.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// cacheTTL is how long a resolved project ID is kept.
const cacheTTL = time.Hour

// Getter returns a credential's secret for a request of kind.
type Getter func(ctx context.Context, name, kind string) (creds.Secret, error)

// Resolver maps a GitLab project path to its numeric ID. It implements
// chain.ProjectResolver.
type Resolver struct {
	Transport http.RoundTripper
	Creds     Getter
	Log       zerolog.Logger

	// cache maps lookup credential, host, and project to a resolved ID.
	cache sync.Map
}

type resolved struct {
	id      int64
	expires time.Time
}

// Resolve looks up project on host with svc's lookup_credential. svc is
// the service of the profile that matched the request, so a lookup never
// uses another profile's credential. Results are cached per credential,
// host, and project: profiles share a result only when they look up with
// the same token.
func (r *Resolver) Resolve(ctx context.Context, svc *config.Service, host, project string) (int64, error) {
	name := svc.LookupCredential
	if name == "" {
		return 0, fmt.Errorf("http %q has no lookup_credential", svc.Name)
	}
	key := name + "\x00" + host + "\x00" + project
	if v, ok := r.cache.Load(key); ok {
		if c := v.(resolved); time.Now().Before(c.expires) {
			return c.id, nil
		}
	}
	u := "https://" + host + "/api/v4/projects/" + url.PathEscape(project)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, fmt.Errorf("gitlab request: %w", err)
	}
	// Lookups run while rules decide an agent request, so they use the
	// agent kind: the store refuses an elevated credential.
	secret, err := r.Creds(ctx, name, config.AllowAgent)
	if err != nil {
		creds.LogError(r.Log.Warn(), err).Str("service", svc.Name).Str("credential", name).Msg("credential unavailable for gitlab project lookup")
		return 0, fmt.Errorf("gitlab api: %w", creds.Unavailable(svc.Name))
	}
	// Bearer works for personal, project, and group access tokens and for
	// OAuth tokens. PRIVATE-TOKEN does not take OAuth tokens.
	req.Header.Set("Authorization", "Bearer "+secret.HTTP())
	resp, err := r.Transport.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("gitlab project %s: %w", project, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var body struct {
		ID int64 `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	if err != nil {
		return 0, fmt.Errorf("decode gitlab project %s: %w", project, err)
	}
	r.cache.Store(key, resolved{id: body.ID, expires: time.Now().Add(cacheTTL)})
	return body.ID, nil
}
