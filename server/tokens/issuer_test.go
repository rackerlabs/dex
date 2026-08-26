package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func newTestIssuer(t *testing.T) (*Issuer, storage.Storage) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	store := memory.New(logger)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sig, err := signer.NewMockSigner(key)
	require.NoError(t, err)

	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)

	return NewIssuer(store, sig, *issuerURL, time.Hour, time.Now, logger), store
}

func testAuthorization() Authorization {
	return Authorization{
		Client:        storage.Client{ID: "client-1"},
		Claims:        storage.Claims{UserID: "u1", Username: "alice", Email: "alice@example.com"},
		Scopes:        []string{"openid", "email", "offline_access"},
		ConnectorID:   "mock",
		Nonce:         "n",
		ConnectorData: []byte(`{"conn":"data"}`),
	}
}

func TestIssuerIssue(t *testing.T) {
	ctx := t.Context()
	iss, store := newTestIssuer(t)
	auth := testAuthorization()

	// With refresh requested: access + id + refresh, and the refresh token is persisted.
	ts, err := iss.Issue(ctx, auth, "", true)
	require.NoError(t, err)
	require.NotEmpty(t, ts.AccessToken)
	require.NotEmpty(t, ts.IDToken)
	require.NotEmpty(t, ts.RefreshToken)

	var rt internal.RefreshToken
	require.NoError(t, internal.Unmarshal(ts.RefreshToken, &rt))
	stored, err := store.GetRefresh(ctx, rt.RefreshId)
	require.NoError(t, err)
	require.Equal(t, "client-1", stored.ClientID)
	require.Equal(t, "mock", stored.ConnectorID)
	require.Equal(t, auth.ConnectorData, stored.ConnectorData)

	sess, err := store.GetOfflineSessions(ctx, "u1", "mock")
	require.NoError(t, err)
	require.Contains(t, sess.Refresh, "client-1")

	// Without refresh: access + id only.
	ts2, err := iss.Issue(ctx, auth, "", false)
	require.NoError(t, err)
	require.NotEmpty(t, ts2.AccessToken)
	require.NotEmpty(t, ts2.IDToken)
	require.Empty(t, ts2.RefreshToken)
}

func TestIDRACPrivilegesClaim(t *testing.T) {
	ctx := t.Context()
	iss, _ := newTestIssuer(t)

	readClaims := func(t *testing.T, scopes []string) *IDRACPrivileges {
		t.Helper()
		raw, _, err := iss.SignIDToken(ctx, Authorization{
			Client:      storage.Client{ID: "idrac"},
			Claims:      storage.Claims{UserID: "u1"},
			Scopes:      scopes,
			ConnectorID: "mock",
		}, "", "")
		require.NoError(t, err)

		keys, err := iss.signer.ValidationKeys(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, keys)
		jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		payload, err := jws.Verify(keys[0])
		require.NoError(t, err)
		var claims struct {
			IDRACPrivileges *IDRACPrivileges `json:"xidp,omitempty"`
		}
		require.NoError(t, json.Unmarshal(payload, &claims))
		return claims.IDRACPrivileges
	}

	withScope := readClaims(t, []string{ScopeOpenID, ScopeIDRACPrivs})
	require.Equal(t, &IDRACPrivileges{All: []string{"L", "TA", "SC", "AR", "VM", "DC"}}, withScope)

	withoutScope := readClaims(t, []string{ScopeOpenID})
	require.Nil(t, withoutScope)
}
