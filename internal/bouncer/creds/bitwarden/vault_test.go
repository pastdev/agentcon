package bitwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Bitwarden mandates RSA-OAEP with SHA-1
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testEmail    = "user@example.com"
	testPassword = "correct horse battery staple"
)

func testIdentity(t *testing.T) identity {
	t.Helper()
	id, err := deriveIdentity(testEmail, testPassword, kdfParams{kind: kdfPBKDF2, iterations: 1000})
	require.NoError(t, err)
	require.Equal(t, "8vx9APjb5Q1wtLcQUtQiEautn2Wd5oBGzkZeyYe9tV4=", base64.StdEncoding.EncodeToString(id.passwordHash))
	return id
}

func mustEnc(t *testing.T, k keys, s string) string {
	t.Helper()
	out, err := encryptSymmetric(k, []byte(s))
	require.NoError(t, err)
	return out
}

type fakeServer struct {
	mu            sync.Mutex
	passwordHash  string
	syncBody      []byte
	refreshToken  string
	requireSecond bool
	requireDevice bool
	logins        int
	refreshes     int
	syncs         int
	devices       []string
	authEmails    []string
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/accounts/prelogin"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Kdf":0,"KdfIterations":1000,"KdfMemory":null,"KdfParallelism":null}`)
	case strings.HasSuffix(r.URL.Path, "/connect/token"):
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			s.refreshes++
			if r.Form.Get("refresh_token") != s.refreshToken || r.Form.Get("client_id") != "cli" {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "invalid refresh"})
				return
			}
			s.refreshToken = "refresh-2"
			writeJSON(w, 200, map[string]string{"access_token": "access-2", "refresh_token": "refresh-2"})
			return
		}
		s.logins++
		s.devices = append(s.devices, r.Form.Get("deviceIdentifier"))
		s.authEmails = append(s.authEmails, r.Header.Get("auth-email"))
		if r.Form.Get("client_id") != "cli" || r.Form.Get("scope") != "api offline_access" || r.Form.Get("deviceType") != cliDeviceType() {
			writeJSON(w, 400, map[string]string{"error": "invalid_client"})
			return
		}
		if r.Form.Get("username") != testEmail || r.Form.Get("password") != s.passwordHash {
			writeJSON(w, 400, map[string]any{
				"error":             "invalid_grant",
				"error_description": "invalid_username_or_password",
				"ErrorModel":        map[string]string{"Message": "Username or password is incorrect. Try again"},
			})
			return
		}
		if s.requireDevice && r.Form.Get("newDeviceOtp") == "" {
			writeJSON(w, 400, map[string]any{
				"error":             "device_error",
				"error_description": "New device verification required",
				"ErrorModel":        map[string]string{"Message": "new device verification required"},
			})
			return
		}
		if s.requireDevice && r.Form.Get("newDeviceOtp") != "654321" {
			writeJSON(w, 400, map[string]any{"errorModel": map[string]string{"message": "Invalid OTP"}})
			return
		}
		if s.requireSecond && r.Form.Get("twoFactorToken") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":[0]}`)
			return
		}
		if s.requireSecond && r.Form.Get("twoFactorToken") != "123456" {
			writeJSON(w, 400, map[string]any{"errorModel": map[string]string{"message": "Invalid TOTP code"}})
			return
		}
		if s.refreshToken == "" {
			s.refreshToken = "refresh-1"
		}
		writeJSON(w, 200, map[string]string{"access_token": "access-1", "refresh_token": s.refreshToken})
	case strings.HasSuffix(r.URL.Path, "/sync"):
		if r.Header.Get("Authorization") == "" || r.Header.Get("Bitwarden-Client-Version") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.syncs++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.syncBody)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func buildVault(t *testing.T, id identity) []byte {
	t.Helper()
	userMaterial := make([]byte, 64)
	for i := range userMaterial {
		userMaterial[i] = byte(i + 1)
	}
	user, err := keysFromMaterial(userMaterial)
	require.NoError(t, err)
	protectedUser, err := encryptSymmetric(id.keys, userMaterial)
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	encPriv := mustEnc(t, user, string(der))
	orgMaterial := bytesRepeat(0x42, 64)
	org, err := keysFromMaterial(orgMaterial)
	require.NoError(t, err)
	rsaCT, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, orgMaterial, nil) //nolint:gosec // Bitwarden mandates RSA-OAEP with SHA-1
	require.NoError(t, err)
	orgKey := "4." + base64.StdEncoding.EncodeToString(rsaCT)

	itemMaterial := bytesRepeat(0x11, 64)
	itemKey, err := keysFromMaterial(itemMaterial)
	require.NoError(t, err)
	encItemKey := mustEnc(t, user, string(itemMaterial))

	body := map[string]any{
		"profile": map[string]any{
			"key":        protectedUser,
			"privateKey": encPriv,
			"organizations": []any{map[string]any{
				"id":  "org-1",
				"key": orgKey,
			}},
		},
		"folders": []any{
			map[string]any{"id": "folder-work", "name": mustEnc(t, user, "Work")},
			map[string]any{"id": "folder-personal", "name": mustEnc(t, user, "Personal")},
		},
		"ciphers": []any{
			loginCipher("id-work", "folder-work", "", user, "GitLab", "oauth2", "gl-token", "otp-secret", "a note", map[string]string{"token": "custom-token"}),
			loginCipher("id-personal", "folder-personal", "", user, "GitLab", "", "other-token", "", "", nil),
			map[string]any{
				"id": "id-ssh", "organizationId": nil, "folderId": nil,
				"name": mustEnc(t, user, "sandbox"),
				"sshKey": map[string]any{
					"privateKey":     mustEnc(t, user, "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n"),
					"publicKey":      mustEnc(t, user, "ssh-ed25519 AAAAC3"),
					"keyFingerprint": mustEnc(t, user, "SHA256:abc"),
				},
			},
			loginCipher("id-org", "", "org-1", org, "Org Secret", "", "org-password", "", "", nil),
			map[string]any{
				"id": "id-wrapped", "name": mustEnc(t, itemKey, "Wrapped"), "key": encItemKey,
				"login": map[string]any{"password": mustEnc(t, itemKey, "from-item-key")},
			},
			map[string]any{
				"id": "id-gone", "name": mustEnc(t, user, "Gone"), "deletedDate": "2020-01-01T00:00:00.000Z",
				"login": map[string]any{"password": mustEnc(t, user, "nope")},
			},
			map[string]any{
				"id": "id-note", "name": mustEnc(t, user, "Runbook"), "notes": mustEnc(t, user, "do the thing"),
			},
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func loginCipher(id, folder, org string, k keys, name, user, pass, totp, notes string, fields map[string]string) map[string]any {
	c := map[string]any{
		"id": id, "name": mustEncT(k, name),
		"organizationId": nil, "folderId": nil,
		"login": map[string]any{},
	}
	if folder != "" {
		c["folderId"] = folder
	}
	if org != "" {
		c["organizationId"] = org
	}
	login := map[string]any{}
	if user != "" {
		login["username"] = mustEncT(k, user)
	}
	if pass != "" {
		login["password"] = mustEncT(k, pass)
	}
	if totp != "" {
		login["totp"] = mustEncT(k, totp)
	}
	c["login"] = login
	if notes != "" {
		c["notes"] = mustEncT(k, notes)
	}
	if len(fields) > 0 {
		var fs []any
		for n, v := range fields {
			fs = append(fs, map[string]any{"name": mustEncT(k, n), "value": mustEncT(k, v)})
		}
		c["fields"] = fs
	}
	return c
}

func mustEncT(k keys, s string) string {
	out, err := encryptSymmetric(k, []byte(s))
	if err != nil {
		panic(err)
	}
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

type memPrompt struct {
	passwords []string
	codes     []string
	nPass     int
	nCode     int
}

func (m *memPrompt) MasterPassword(context.Context, string, int, int) (string, error) {
	if m.nPass >= len(m.passwords) {
		return "", errors.New("no more passwords")
	}
	s := m.passwords[m.nPass]
	m.nPass++
	return s, nil
}

func (m *memPrompt) TwoFactorCode(context.Context, string, string, int, int) (string, error) {
	if m.nCode >= len(m.codes) {
		return "", errors.New("no more codes")
	}
	s := m.codes[m.nCode]
	m.nCode++
	return s, nil
}

func startVault(t *testing.T, second bool) (*httptest.Server, *fakeServer) {
	t.Helper()
	id := testIdentity(t)
	fake := &fakeServer{passwordHash: base64.StdEncoding.EncodeToString(id.passwordHash), syncBody: buildVault(t, id), requireSecond: second}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return srv, fake
}

func TestGet(t *testing.T) {
	type testCase struct {
		v            *Vaults
		q            Query
		want         string
		wantContains string
		wantErr      string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := tc.v.Get(context.Background(), tc.q)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
			return
		}
		require.NoError(t, err)
		if tc.wantContains != "" {
			assert.Contains(t, got, tc.wantContains)
			return
		}
		assert.Equal(t, tc.want, got)
	}

	t.Run("looks up items and reuses an unlocked vault", func(t *testing.T) {
		srv, fake := startVault(t, false)
		dir := t.TempDir()
		t.Setenv("BW_MASTER", testPassword)
		v := New(Options{StateDir: dir, Prompt: &memPrompt{}})
		q := Query{Account: Account{Email: "User@Example.com", Server: srv.URL, PasswordEnv: "BW_MASTER"}, Item: "GitLab", Folder: "Work"}
		tester(t, testCase{v: v, q: q, want: "gl-token"})
		tester(t, testCase{v: v, q: q, want: "gl-token"})
		fake.mu.Lock()
		assert.Equal(t, 1, fake.logins, "logins")
		assert.Equal(t, 1, fake.syncs, "syncs")
		assert.Equal(t, 0, fake.refreshes, "refreshes")
		assert.Equal(t, []string{"dXNlckBleGFtcGxlLmNvbQ"}, fake.authEmails)
		fake.mu.Unlock()

		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "username"}, want: "oauth2"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "token"}, want: "custom-token"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "notes"}, want: "a note"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "totp"}, want: "otp-secret"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "id-personal", Field: "password"}, want: "other-token"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "GitLab"}, wantErr: "set folder"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "sandbox", Field: "private_key"}, wantContains: "BEGIN OPENSSH PRIVATE KEY"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "Org Secret"}, want: "org-password"})
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "Wrapped"}, want: "from-item-key"})
		_, err := v.Get(context.Background(), Query{Account: q.Account, Item: "Gone"})
		require.Error(t, err, "deleted item was returned")
		tester(t, testCase{v: v, q: Query{Account: q.Account, Item: "Runbook", Field: "notes"}, want: "do the thing"})

		raw, err := v.ItemJSON(context.Background(), q)
		require.NoError(t, err)
		var doc map[string]any
		err = json.Unmarshal(raw, &doc)
		require.NoError(t, err)
		assert.Equal(t, "a note", doc["notes"])
		login, _ := doc["login"].(map[string]any)
		assert.Equal(t, "oauth2", login["username"])
		assert.Equal(t, "gl-token", login["password"])
		sshRaw, err := v.ItemJSON(context.Background(), Query{Account: q.Account, Item: "sandbox"})
		require.NoError(t, err)
		var sshDoc map[string]any
		err = json.Unmarshal(sshRaw, &sshDoc)
		require.NoError(t, err)
		sshKey, _ := sshDoc["sshKey"].(map[string]any)
		priv, _ := sshKey["privateKey"].(string)
		assert.Contains(t, priv, "BEGIN OPENSSH PRIVATE KEY")

		matches, err := filepath.Glob(filepath.Join(dir, "bitwarden", "*.json"))
		require.NoError(t, err)
		require.Len(t, matches, 1, "state files")
		info, err := os.Stat(matches[0])
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		v2 := New(Options{StateDir: dir})
		tester(t, testCase{v: v2, q: q, want: "gl-token"})
		fake.mu.Lock()
		defer fake.mu.Unlock()
		assert.Equal(t, 1, fake.logins, "logins after restart")
		assert.Equal(t, 1, fake.refreshes, "refreshes after restart")
		assert.Equal(t, 2, fake.syncs, "syncs after restart")
	})
	t.Run("retries a wrong password", func(t *testing.T) {
		srv, fake := startVault(t, false)
		p := &memPrompt{passwords: []string{"nope", testPassword}}
		v := New(Options{StateDir: t.TempDir(), Prompt: p})
		tester(t, testCase{
			v: v,
			q: Query{
				Account: Account{Email: testEmail, Server: srv.URL},
				Item:    "GitLab", Folder: "Work",
			},
			want: "gl-token",
		})
		assert.Equal(t, 2, p.nPass, "prompts")
		fake.mu.Lock()
		defer fake.mu.Unlock()
		assert.Equal(t, 2, fake.logins, "logins")
	})
	t.Run("does not stick a failed password env", func(t *testing.T) {
		srv, _ := startVault(t, false)
		v := New(Options{StateDir: t.TempDir(), Prompt: &memPrompt{}})
		t.Setenv("BW_MASTER", "nope")
		q := Query{Account: Account{Email: testEmail, Server: srv.URL, PasswordEnv: "BW_MASTER"}, Item: "sandbox", Field: "private_key"}
		tester(t, testCase{v: v, q: q, wantErr: "incorrect"})
		t.Setenv("BW_MASTER", testPassword)
		tester(t, testCase{v: v, q: q, wantContains: "BEGIN OPENSSH PRIVATE KEY"})
	})
	t.Run("prompts for new device verification", func(t *testing.T) {
		srv, fake := startVault(t, false)
		fake.mu.Lock()
		fake.requireDevice = true
		fake.mu.Unlock()
		p := &memPrompt{passwords: []string{testPassword}, codes: []string{"654321"}}
		v := New(Options{StateDir: t.TempDir(), Prompt: p})
		tester(t, testCase{
			v:    v,
			q:    Query{Account: Account{Email: testEmail, Server: srv.URL}, Item: "Org Secret"},
			want: "org-password",
		})
		assert.Equal(t, 1, p.nCode, "codes")
		fake.mu.Lock()
		defer fake.mu.Unlock()
		assert.Equal(t, 2, fake.logins, "logins")
	})
	t.Run("retries a wrong two-factor code", func(t *testing.T) {
		srv, fake := startVault(t, true)
		p := &memPrompt{passwords: []string{testPassword}, codes: []string{"000000", "123456"}}
		v := New(Options{StateDir: t.TempDir(), Prompt: p})
		tester(t, testCase{
			v:    v,
			q:    Query{Account: Account{Email: testEmail, Server: srv.URL}, Item: "Org Secret"},
			want: "org-password",
		})
		assert.Equal(t, 2, p.nCode, "codes")
		fake.mu.Lock()
		defer fake.mu.Unlock()
		assert.Equal(t, 3, fake.logins, "logins")
	})
	t.Run("prompts for two-factor", func(t *testing.T) {
		srv, fake := startVault(t, true)
		p := &memPrompt{passwords: []string{testPassword}, codes: []string{"123456"}}
		v := New(Options{StateDir: t.TempDir(), Prompt: p})
		tester(t, testCase{
			v:    v,
			q:    Query{Account: Account{Email: testEmail, Server: srv.URL}, Item: "Org Secret"},
			want: "org-password",
		})
		assert.Equal(t, 1, p.nCode, "codes")
		fake.mu.Lock()
		defer fake.mu.Unlock()
		assert.Equal(t, 2, fake.logins, "logins")
	})
}

func TestUnlock(t *testing.T) {
	type testCase struct {
		accounts []Account
		wantErr  string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		v := New(Options{StateDir: t.TempDir()})
		err := v.Unlock(context.Background(), tc.accounts)
		require.ErrorContains(t, err, tc.wantErr)
	}

	t.Run("rejects conflicting password env values", func(t *testing.T) {
		tester(t, testCase{
			accounts: []Account{
				{Email: "User@Example.com", PasswordEnv: "ONE"},
				{Email: "user@example.com", PasswordEnv: "TWO"},
			},
			wantErr: "conflicting password_env",
		})
	})
}
