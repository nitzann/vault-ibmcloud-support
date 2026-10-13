// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package ibmcloud

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	// jwksPath is the IAM path that publishes the token signing keys.
	jwksPath = "/identity/keys"

	// discoveryPath is the IAM OIDC discovery document. It is the source of
	// the expected "iss" claim, so non-default IAM endpoints (private,
	// staging) do not need the issuer to be guessed from the endpoint URL.
	discoveryPath = "/identity/.well-known/openid-configuration"

	// jwksMinRefetchInterval bounds how often IAM is contacted for keys or
	// discovery, both after a failure and when a token presents an unknown
	// "kid", to avoid refetch storms.
	jwksMinRefetchInterval = 30 * time.Second

	// jwtClockSkew is the leeway applied to exp/nbf/iat checks.
	jwtClockSkew = 10 * time.Second

	jwksMaxResponseBytes = 1 << 20
)

// errInvalidToken marks failures caused by the presented token itself (as
// opposed to infrastructure failures such as IAM being unreachable).
var errInvalidToken = errors.New("invalid token")

// jwksVerifier verifies IBM Cloud IAM JWTs offline against the IAM JWKS.
//
// The expected issuer is read from the IAM OIDC discovery document and the
// keys from the JWKS endpoint, both lazily on first use. Keys are refetched
// only when a token presents a "kid" that is not in the cached set. All IAM
// requests, successful or not, are at most one per minRefetchInterval. There
// is no periodic refresh.
type jwksVerifier struct {
	jwksURL            string
	discoveryURL       string
	httpClient         *http.Client
	minRefetchInterval time.Duration

	// mu protects the cached values read on the login hot path.
	mu     sync.RWMutex
	keys   map[string]*jose.JSONWebKey
	issuer string

	// refreshMu serializes fetches so the network round trip does not block
	// logins that hit the cache. It protects lastAttempt and lastErr.
	refreshMu   sync.Mutex
	lastAttempt time.Time
	lastErr     error
}

func newJWKSVerifier(iamEndpoint string, httpClient *http.Client) *jwksVerifier {
	base := strings.TrimRight(iamEndpoint, "/")
	return &jwksVerifier{
		jwksURL:            base + jwksPath,
		discoveryURL:       base + discoveryPath,
		httpClient:         httpClient,
		minRefetchInterval: jwksMinRefetchInterval,
	}
}

// verify checks the RS256 signature, issuer, exp and nbf of the token.
// Failures caused by the token wrap errInvalidToken.
//
// Note: IBM IAM tokens carry no Vault-specific audience, so no audience check
// is possible. Account ID and role binding checks are the primary guard.
func (v *jwksVerifier) verify(ctx context.Context, rawToken string) error {
	tok, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return fmt.Errorf("%w: malformed token: %s", errInvalidToken, err)
	}

	if len(tok.Headers) != 1 {
		return fmt.Errorf("%w: expected exactly one signature", errInvalidToken)
	}
	header := tok.Headers[0]
	if header.Algorithm != string(jose.RS256) {
		return fmt.Errorf("%w: unsupported signing algorithm %q", errInvalidToken, header.Algorithm)
	}
	if header.KeyID == "" {
		return fmt.Errorf("%w: missing key id", errInvalidToken)
	}

	key, issuer, err := v.keyFor(ctx, header.KeyID)
	if err != nil {
		return err
	}

	var claims jwt.Claims
	if err := tok.Claims(key.Key, &claims); err != nil {
		return fmt.Errorf("%w: signature verification failed", errInvalidToken)
	}

	// jwt.Claims.Validate skips the expiry check when exp is absent; require it.
	if claims.Expiry == nil {
		return fmt.Errorf("%w: missing exp claim", errInvalidToken)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer}, jwtClockSkew); err != nil {
		return fmt.Errorf("%w: %s", errInvalidToken, err)
	}

	return nil
}

// cached returns the key for kid and the expected issuer if both are known.
func (v *jwksVerifier) cached(kid string) (*jose.JSONWebKey, string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, ok := v.keys[kid]
	if !ok || v.issuer == "" {
		return nil, "", false
	}
	return key, v.issuer, true
}

// keyFor returns the signing key for kid and the expected issuer, refetching
// from IAM at most once per minRefetchInterval if the kid is unknown.
func (v *jwksVerifier) keyFor(ctx context.Context, kid string) (*jose.JSONWebKey, string, error) {
	if key, issuer, ok := v.cached(kid); ok {
		return key, issuer, nil
	}

	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	if key, issuer, ok := v.cached(kid); ok {
		return key, issuer, nil
	}

	v.mu.RLock()
	haveKeys := len(v.keys) > 0
	v.mu.RUnlock()

	if !v.lastAttempt.IsZero() && time.Since(v.lastAttempt) < v.minRefetchInterval {
		if !haveKeys && v.lastErr != nil {
			return nil, "", v.lastErr
		}
		return nil, "", fmt.Errorf("%w: unknown key id", errInvalidToken)
	}

	v.lastAttempt = time.Now()
	v.lastErr = v.refresh(ctx)
	if v.lastErr != nil {
		// A cancelled request says nothing about IAM's health; do not let it
		// throttle other callers.
		if ctx.Err() != nil {
			v.lastAttempt = time.Time{}
		}
		return nil, "", v.lastErr
	}

	if key, issuer, ok := v.cached(kid); ok {
		return key, issuer, nil
	}
	return nil, "", fmt.Errorf("%w: unknown key id", errInvalidToken)
}

// refresh loads the issuer (once) and the key set from IAM. v.refreshMu must
// be held.
func (v *jwksVerifier) refresh(ctx context.Context) error {
	v.mu.RLock()
	issuer := v.issuer
	v.mu.RUnlock()

	if issuer == "" {
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := v.getJSON(ctx, v.discoveryURL, &doc); err != nil {
			return fmt.Errorf("failed to fetch IAM discovery document: %w", err)
		}
		if doc.Issuer == "" {
			return errors.New("IAM discovery document has no issuer")
		}
		issuer = doc.Issuer
	}

	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, v.jwksURL, &set); err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	keys := make(map[string]*jose.JSONWebKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		if k.KeyID == "" || !k.IsPublic() || !k.Valid() {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if _, ok := k.Key.(*rsa.PublicKey); !ok {
			continue
		}
		keys[k.KeyID] = &k
	}

	v.mu.Lock()
	v.issuer = issuer
	v.keys = keys
	v.mu.Unlock()
	return nil
}

// getJSON performs a GET and decodes a size-limited JSON response into out.
func (v *jwksVerifier) getJSON(ctx context.Context, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, jwksMaxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}
