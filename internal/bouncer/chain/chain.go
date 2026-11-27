package chain

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/pkg/bouncer/claims"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Handler processes a request, typically by calling the rest of the chain.
type Handler func(*Request) (*Response, error)

// Filter is one link in the chain. Like a servlet filter it may inspect or
// modify the request, short-circuit with a denial or synthetic response, or
// call next and post-process the response.
type Filter interface {
	Name() string
	Handle(req *Request, next Handler) (*Response, error)
}

// Approver asks a human to approve a request.
type Approver interface {
	Ask(ctx context.Context, a AskRequest) (bool, error)
}

// AskRequest is a pending human decision.
type AskRequest struct {
	Session *Session
	Filter  string
	Prompt  string
	// Key identifies the decision for "allow for this session". It defaults
	// to the prompt plus the request, so a remembered answer covers only
	// identical requests; filters pass a key to group requests on purpose.
	Key     string
	Request string
	// Origin says where a subrequest came from. It is empty for an agent
	// request.
	Origin string
}

// ErrClaimRejected marks a claim request that is invalid or would exceed a
// claim limit. It is the filter's mistake, so the filter sees an exception
// and no human is asked.
var ErrClaimRejected = errors.New("claim request rejected")

// ClaimRequest asks a human to add a claim to a session.
type ClaimRequest struct {
	Session *Session
	Filter  string
	Prompt  string
	Claim   claims.Claim
	Request string
	// Origin says where a subrequest came from. It is empty for an agent
	// request.
	Origin string
}

// ClaimRequester adds claims to sessions with a human's approval.
type ClaimRequester interface {
	// RequestClaim resolves true when the session holds the claim or the
	// human allows the request. An error wrapping ErrClaimRejected means
	// nobody was asked. Other errors are reported alongside the result.
	RequestClaim(ctx context.Context, r ClaimRequest) (bool, error)
}

// ProjectResolver maps a GitLab project path to its numeric ID on a host.
// svc is the service of the profile that matched the request, so a lookup
// uses only that service's lookup_credential.
type ProjectResolver func(ctx context.Context, svc *config.Service, host, project string) (int64, error)

// Env is shared by every filter in a daemon.
type Env struct {
	Approver Approver
	// Claims answers requestClaim. Nil makes every claim request resolve
	// false.
	Claims ClaimRequester
	// Log receives filter log output. Each line names its filter.
	Log      zerolog.Logger
	Resolver ProjectResolver
	// Placeholder checks that a filter may send a credential in a
	// subrequest: it exists and allows subrequest. Nil accepts any name.
	Placeholder func(name string) error
	// Subrequest sends a filter's subrequest. Nil makes subrequest() throw.
	Subrequest SubrequestFunc
}

// Build composes filters around terminal. A filter error or panic fails
// closed: the request is denied, attributed to the failing filter.
func Build(filters []Filter, terminal Handler) Handler {
	h := terminal
	for i := len(filters) - 1; i >= 0; i-- {
		f, next := filters[i], h
		h = func(req *Request) (resp *Response, err error) {
			defer func() {
				if p := recover(); p != nil {
					resp, err = Deny(f.Name(), fmt.Sprintf("filter panic: %v", p)), nil
				}
			}()
			resp, err = f.Handle(req, next)
			if err != nil {
				return Deny(f.Name(), "filter error: "+err.Error()), nil
			}
			if resp == nil {
				return Deny(f.Name(), "filter returned no response"), nil
			}
			return resp, nil
		}
	}
	return h
}
