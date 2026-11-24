package signer

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/internal/bouncer/creds"
	"github.com/pastdev/agentcon/internal/bouncer/gitobject"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

// Response headers that describe a signature for git's status line, so the
// agent helper never parses the signature.
const (
	HeaderFingerprint = "X-Bouncer-Signer-Fingerprint"
	HeaderKeyAlgo     = "X-Bouncer-Signer-Key-Algorithm"
	HeaderHash        = "X-Bouncer-Signer-Hash"
	HeaderCreated     = "X-Bouncer-Signer-Created"
	HeaderType        = "X-Bouncer-Signer-Type"
)

// By names the signer in denials and the audit log.
const By = "signer"

func refuse(status int, reason string) *chain.Response {
	return &chain.Response{Status: status, Denial: &chain.Denial{By: By, Reason: reason, Status: status}}
}

// Terminal returns the chain terminal for a signer service. It runs only
// after every filter and rule called next, never forwards upstream, and
// refuses anything but a well-formed, unsigned git object.
func Terminal(svc *config.Service, s Signer, log zerolog.Logger) chain.Handler {
	return func(req *chain.Request) (*chain.Response, error) {
		if req.SkipCredential {
			return refuse(http.StatusForbidden, "no rule allowed this request, and a signer never forwards upstream"), nil
		}
		if req.URL == nil || req.URL.Scheme != "https" {
			return refuse(http.StatusForbidden, "the signer answers only https"), nil
		}
		if req.URL.Path != config.SignerPath {
			return refuse(http.StatusNotFound, "unknown signer path "+strconv.Quote(req.URL.Path)), nil
		}
		if req.Method != http.MethodPost {
			return refuse(http.StatusMethodNotAllowed, "the signer takes only POST"), nil
		}
		keys := req.URL.Query()["key"]
		if len(keys) != 1 {
			return refuse(http.StatusBadRequest, "exactly one key parameter is required"), nil
		}
		id, err := config.NormalizeKeyID(keys[0])
		if err != nil {
			return refuse(http.StatusForbidden, "unknown signing key"), nil //nolint:nilerr // a bad key id is the agent's mistake, reported as a denial
		}
		key := svc.Signer.OpenPGP.Key(id)
		if key == nil {
			return refuse(http.StatusForbidden, "unknown signing key"), nil
		}
		if req.Body == nil {
			return refuse(http.StatusBadRequest, "missing body"), nil
		}
		body, err := req.Body.ReadAll()
		if err != nil {
			return refuse(http.StatusBadRequest, "read body: "+err.Error()), nil //nolint:nilerr // reported as a denial
		}
		typ, err := gitobject.Check(body)
		if err != nil {
			return refuse(http.StatusBadRequest, err.Error()), nil
		}
		sig, err := s.Sign(req.Ctx, *key, body)
		switch {
		case errors.Is(err, ErrUnavailable):
			creds.LogError(log.Warn(), err).Str("credential", key.Credential).Msg("signing key unavailable")
			return refuse(http.StatusServiceUnavailable, creds.Unavailable(svc.Name).Error()), nil
		case err != nil:
			log.Error().Err(err).Str("credential", key.Credential).Str("key", key.ID).Msg("signing failed")
			return refuse(http.StatusInternalServerError, fmt.Sprintf("signing with key %s failed; see the bouncer log", key.ID)), nil
		}
		h := http.Header{}
		h.Set("Content-Type", "application/pgp-signature")
		h.Set(HeaderFingerprint, sig.Fingerprint)
		h.Set(HeaderKeyAlgo, strconv.Itoa(sig.KeyAlgo))
		h.Set(HeaderHash, strconv.Itoa(sig.Hash))
		h.Set(HeaderCreated, strconv.FormatInt(sig.Created.Unix(), 10))
		h.Set(HeaderType, string(typ))
		return &chain.Response{Status: http.StatusOK, Header: h, Body: chain.BytesBody(sig.Armored)}, nil
	}
}
