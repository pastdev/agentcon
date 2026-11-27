package chain

import (
	"net/http"
	"net/url"
	"time"
)

// MaxSubrequestDepth bounds how deeply subrequests may nest. A subrequest
// made while handling an agent request has depth 1.
const MaxSubrequestDepth = 4

// MaxSubrequestRedirects bounds how many redirects one subrequest follows.
const MaxSubrequestRedirects = 5

// SubrequestInfo marks a request a filter made with subrequest(). Bouncer
// sets it, so the agent cannot forge it.
type SubrequestInfo struct {
	// Filter names the filter that made the subrequest.
	Filter string `json:"filter"`
	// ID is the policy-assigned id of the filter placement that made the
	// subrequest. Empty when the placement has none.
	ID string `json:"id"`
	// Depth is 1 for a subrequest made while handling an agent request.
	Depth int `json:"depth"`
	// Parent describes the request that caused the subrequest.
	Parent string `json:"parent"`
}

// Origin describes where a subrequest came from, for prompts. It is empty
// for an agent request.
func (s *SubrequestInfo) Origin() string {
	if s == nil {
		return ""
	}
	return "subrequest from " + s.Who() + " for " + s.Parent
}

// Who names the subrequest's maker: its placement id when it has one, else
// its filter name.
func (s *SubrequestInfo) Who() string {
	if s.ID != "" {
		return s.ID
	}
	return s.Filter
}

// SubrequestCaller is the filter run that makes a subrequest.
type SubrequestCaller struct {
	// Filter is the filter's display name.
	Filter string
	// ID is the filter placement's policy-assigned id, or empty.
	ID string
	// Placeholders maps each one-time placeholder the run issued to its
	// credential name.
	Placeholders map[string]string
}

// SubrequestSpec is what a filter asks subrequest() to send.
type SubrequestSpec struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
	// Manual returns a redirect instead of following it.
	Manual bool
	// Timeout bounds the whole subrequest, redirects and prompts included.
	// Zero leaves only the parent request's context.
	Timeout time.Duration
}

// SubrequestFunc sends a subrequest on behalf of caller, which is handling
// parent. It returns the final response and its URL. An error means there
// is no response.
type SubrequestFunc func(parent *Request, caller SubrequestCaller, spec SubrequestSpec) (*Response, *url.URL, error)
