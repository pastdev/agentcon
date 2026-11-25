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
	return "subrequest from " + s.Filter + " for " + s.Parent
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

// SubrequestFunc sends a subrequest on behalf of the filter named filter,
// which is handling parent. It returns the final response and its URL. An
// error means there is no response.
type SubrequestFunc func(parent *Request, filter string, spec SubrequestSpec) (*Response, *url.URL, error)
