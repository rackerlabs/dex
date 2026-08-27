package device

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestGetDeviceVerificationURI(t *testing.T) {
	u, err := url.Parse("https://dex.example.com/non-root-path")
	require.NoError(t, err)

	h := &Handler{IssuerURL: oauth2.IssuerURL{URL: *u}}
	require.Equal(t, "/non-root-path/device/auth/verify_code", h.getDeviceVerificationURI())
}

// TestCreateDeviceAuthorizationUsesInjectedClock pins the device request and
// token expiry to the handler's clock. Both were minted from a mix of
// time.Now() and h.Now(), which made the two expiries drift apart under a
// fixed test clock.
func TestCreateDeviceAuthorizationUsesInjectedClock(t *testing.T) {
	u, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)

	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &Handler{
		IssuerURL:        oauth2.IssuerURL{URL: *u},
		Storage:          memory.New(logger),
		Logger:           logger,
		Now:              func() time.Time { return fixed },
		RequestsValidFor: 5 * time.Minute,
	}
	require.NoError(t, h.Storage.CreateClient(t.Context(), storage.Client{ID: "test"}))

	resp, ferr := h.createDeviceAuthorization(t.Context(), deviceCodeRequest{
		clientID: "test",
		scopes:   []string{"openid"},
	})
	require.Nil(t, ferr)

	want := fixed.Add(5 * time.Minute)

	req, err := h.Storage.GetDeviceRequest(t.Context(), resp.UserCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, req.Expiry, 0)

	token, err := h.Storage.GetDeviceToken(t.Context(), resp.DeviceCode)
	require.NoError(t, err)
	require.WithinDuration(t, want, token.Expiry, 0)
	require.WithinDuration(t, fixed, token.LastRequestTime, 0)
}

func TestCreateDeviceAuthorizationEnforcesDynamicClientPolicy(t *testing.T) {
	u, err := url.Parse("https://dex.example.com")
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &Handler{
		IssuerURL: oauth2.IssuerURL{URL: *u}, Storage: memory.New(logger), Logger: logger,
		Now: time.Now, RequestsValidFor: 5 * time.Minute,
	}
	client := storage.Client{
		ID: "dynamic", Secret: "secret", DynamicallyRegistered: true,
		GrantTypes: []string{oauth2.GrantTypeAuthorizationCode}, AllowedScopes: []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_post",
	}
	require.NoError(t, h.Storage.CreateClient(t.Context(), client))

	_, ferr := h.createDeviceAuthorization(t.Context(), deviceCodeRequest{clientID: client.ID, clientSecret: client.Secret, clientAuthMethod: "client_secret_post", scopes: []string{"openid"}})
	require.NotNil(t, ferr)
	require.Equal(t, oauth2.UnauthorizedClient, ferr.code)

	client.GrantTypes = []string{oauth2.GrantTypeDeviceCode}
	require.NoError(t, h.Storage.UpdateClient(t.Context(), client.ID, func(storage.Client) (storage.Client, error) { return client, nil }))
	_, ferr = h.createDeviceAuthorization(t.Context(), deviceCodeRequest{clientID: client.ID, clientSecret: "wrong", clientAuthMethod: "client_secret_post", scopes: []string{"openid"}})
	require.NotNil(t, ferr)
	require.Equal(t, oauth2.InvalidClient, ferr.code)

	_, ferr = h.createDeviceAuthorization(t.Context(), deviceCodeRequest{clientID: client.ID, clientSecret: client.Secret, clientAuthMethod: "client_secret_post", scopes: []string{"openid", "email"}})
	require.NotNil(t, ferr)
	require.Equal(t, oauth2.InvalidScope, ferr.code)

	_, ferr = h.createDeviceAuthorization(t.Context(), deviceCodeRequest{clientID: client.ID, clientSecret: client.Secret, clientAuthMethod: "client_secret_basic", scopes: []string{"openid"}})
	require.NotNil(t, ferr)
	require.Equal(t, oauth2.InvalidClient, ferr.code)

	client.TokenEndpointAuthMethod = "client_secret_basic"
	require.NoError(t, h.Storage.UpdateClient(t.Context(), client.ID, func(storage.Client) (storage.Client, error) { return client, nil }))
	_, ferr = h.createDeviceAuthorization(t.Context(), deviceCodeRequest{clientID: client.ID, clientSecret: client.Secret, clientAuthMethod: "client_secret_basic", scopes: []string{"openid"}})
	require.Nil(t, ferr)
}

func TestParseDeviceCodeRequestClientAuthenticationMethod(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &Handler{Logger: logger}

	form := url.Values{"client_id": {"post-client"}, "client_secret": {"post-secret"}}
	req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, ferr := h.parseDeviceCodeRequest(req)
	require.Nil(t, ferr)
	require.Equal(t, "client_secret_post", parsed.clientAuthMethod)
	require.Equal(t, "post-client", parsed.clientID)

	req = httptest.NewRequest(http.MethodPost, "/device/code", nil)
	req.SetBasicAuth(url.QueryEscape("basic client"), url.QueryEscape("basic secret"))
	parsed, ferr = h.parseDeviceCodeRequest(req)
	require.Nil(t, ferr)
	require.Equal(t, "client_secret_basic", parsed.clientAuthMethod)
	require.Equal(t, "basic client", parsed.clientID)
	require.Equal(t, "basic secret", parsed.clientSecret)

	form = url.Values{"client_id": {"public-client"}}
	req = httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, ferr = h.parseDeviceCodeRequest(req)
	require.Nil(t, ferr)
	require.Equal(t, "none", parsed.clientAuthMethod)
}
