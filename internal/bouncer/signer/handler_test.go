package signer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pastdev/agentcon/internal/bouncer/chain"
	"github.com/pastdev/agentcon/pkg/bouncer/config"
)

type stubSigner struct {
	err    error
	called bool
	got    config.OpenPGPKey
}

func (s *stubSigner) Sign(_ context.Context, k config.OpenPGPKey, _ []byte) (*Signature, error) {
	s.called = true
	s.got = k
	if s.err != nil {
		return nil, s.err
	}
	return &Signature{Armored: []byte("SIG"), Fingerprint: "ABCD", KeyAlgo: 22, Hash: 8, Created: time.Unix(1764000000, 0)}, nil
}

func TestTerminal(t *testing.T) {
	svc := &config.Service{Name: "signing", Signer: &config.Signer{OpenPGP: &config.OpenPGPSigner{Keys: []config.OpenPGPKey{
		{ID: "0123456789ABCDEF0123456789ABCDEF01234567", Credential: "sign-a"},
		{ID: "C26E02CE599B53FF", Credential: "sign-b"},
	}}}}
	type testCase struct {
		method     string
		rawURL     string
		body       string
		skipCred   bool
		signErr    error
		wantStatus int
		wantReason string
		wantCred   string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		u, err := url.Parse(tc.rawURL)
		require.NoError(t, err)
		method := tc.method
		if method == "" {
			method = http.MethodPost
		}
		req := &chain.Request{
			Ctx: t.Context(), Transport: chain.TransportHTTP, Method: method, URL: u,
			Header: http.Header{}, Body: chain.NewBody(io.NopCloser(strings.NewReader(tc.body))),
			SkipCredential: tc.skipCred,
		}
		s := &stubSigner{err: tc.signErr}
		resp, err := Terminal(svc, s, zerolog.Nop())(req)
		require.NoError(t, err)
		assert.Equal(t, tc.wantStatus, resp.Status)
		if tc.wantReason != "" {
			require.NotNil(t, resp.Denial)
			assert.Equal(t, By, resp.Denial.By)
			assert.Contains(t, resp.Denial.Reason, tc.wantReason)
			return
		}
		require.Nil(t, resp.Denial)
		assert.True(t, s.called)
		assert.Equal(t, tc.wantCred, s.got.Credential)
		assert.Equal(t, "application/pgp-signature", resp.Header.Get("Content-Type"))
		assert.Equal(t, "ABCD", resp.Header.Get(HeaderFingerprint))
		assert.Equal(t, "22", resp.Header.Get(HeaderKeyAlgo))
		assert.Equal(t, "8", resp.Header.Get(HeaderHash))
		assert.Equal(t, "1764000000", resp.Header.Get(HeaderCreated))
		assert.Equal(t, "commit", resp.Header.Get(HeaderType))
		b, err := resp.Body.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, "SIG", string(b))
	}
	const base = "https://signer.bouncer.internal/openpgp/sign"

	t.Run("signs with the key matching a long id", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=89abcdef01234567&repository=x", body: testCommit, wantStatus: 200, wantCred: "sign-a"})
	})
	t.Run("signs with the key matching a 0x id", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=0xC26E02CE599B53FF", body: testCommit, wantStatus: 200, wantCred: "sign-b"})
	})
	t.Run("refuses a request no rule allowed", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=C26E02CE599B53FF", body: testCommit, skipCred: true, wantStatus: 403, wantReason: "never forwards upstream"})
	})
	t.Run("refuses plain http", func(t *testing.T) {
		tester(t, testCase{rawURL: "http://signer.bouncer.internal/openpgp/sign?key=C26E02CE599B53FF", body: testCommit, wantStatus: 403, wantReason: "only https"})
	})
	t.Run("refuses another path", func(t *testing.T) {
		tester(t, testCase{rawURL: "https://signer.bouncer.internal/openpgp/sign/x?key=C26E02CE599B53FF", body: testCommit, wantStatus: 404, wantReason: "unknown signer path"})
	})
	t.Run("refuses GET", func(t *testing.T) {
		tester(t, testCase{method: http.MethodGet, rawURL: base + "?key=C26E02CE599B53FF", wantStatus: 405, wantReason: "only POST"})
	})
	t.Run("refuses a missing key", func(t *testing.T) {
		tester(t, testCase{rawURL: base, body: testCommit, wantStatus: 400, wantReason: "exactly one key"})
	})
	t.Run("refuses a repeated key", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=C26E02CE599B53FF&key=C26E02CE599B53FF", body: testCommit, wantStatus: 400, wantReason: "exactly one key"})
	})
	t.Run("refuses an unknown key without listing keys", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=1111111111111111", body: testCommit, wantStatus: 403, wantReason: "unknown signing key"})
	})
	t.Run("refuses an email as key", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=" + url.QueryEscape("A <a@example.com>"), body: testCommit, wantStatus: 403, wantReason: "unknown signing key"})
	})
	t.Run("refuses arbitrary bytes", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=C26E02CE599B53FF", body: "please sign this", wantStatus: 400, wantReason: "not an unsigned git commit or tag"})
	})
	t.Run("reports an unavailable key without its error", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=C26E02CE599B53FF", body: testCommit, signErr: errors.Join(ErrUnavailable, errors.New("vault output")), wantStatus: 503, wantReason: "credential for signing is unavailable"})
	})
	t.Run("reports a signing failure by key id", func(t *testing.T) {
		tester(t, testCase{rawURL: base + "?key=C26E02CE599B53FF", body: testCommit, signErr: errors.Join(ErrKey, errors.New("passphrase rejected")), wantStatus: 500, wantReason: "signing with key C26E02CE599B53FF failed"})
	})
}
