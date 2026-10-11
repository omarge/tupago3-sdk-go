// Package auth implements dynamic JWT retrieval and per-RPC Bearer injection.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// TokenProvider supplies a Bearer token for a gRPC call. Implementations must
// never log or expose the token.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// PerRPCCredentials implements credentials.PerRPCCredentials using a
// TokenProvider. RequireTransportSecurity must be true when talking to remote
// TLS endpoints and false only for loopback plaintext dev connections.
type PerRPCCredentials struct {
	Provider                 TokenProvider
	requireTransportSecurity bool
}

func NewBearerCredentials(provider TokenProvider, requireTLS bool) *PerRPCCredentials {
	return &PerRPCCredentials{Provider: provider, requireTransportSecurity: requireTLS}
}

// GetRequestMetadata returns the Authorization header. The token is never
// written to any log.
func (c *PerRPCCredentials) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := c.Provider.Token(ctx)
	if err != nil {
		return nil, err
	}
	// No logging of token by design.
	return map[string]string{"authorization": "Bearer " + token}, nil
}

func (c *PerRPCCredentials) RequireTransportSecurity() bool { return c.requireTransportSecurity }

// StaticTokenProvider returns a fixed token (e.g. synthetic dev token).
func StaticTokenProvider(token string) TokenProvider {
	return FuncTokenProvider(func(context.Context) (string, error) {
		if token == "" {
			return "", errEmptyToken
		}
		return token, nil
	})
}

// FuncTokenProvider adapts a function to TokenProvider.
func FuncTokenProvider(f func(context.Context) (string, error)) TokenProvider {
	return funcProvider(f)
}

type funcProvider func(context.Context) (string, error)

func (f funcProvider) Token(ctx context.Context) (string, error) { return f(ctx) }

// JWTTokenProvider supports dynamic rotation: it caches a token until its
// `exp` claim, then refetches. If the token cannot be parsed it is not cached.
type JWTTokenProvider struct {
	mu     sync.Mutex
	fetch  func(context.Context) (string, error)
	cache  string
	expiry time.Time
}

func NewJWTTokenProvider(fetch func(context.Context) (string, error)) *JWTTokenProvider {
	return &JWTTokenProvider{fetch: fetch}
}

func (p *JWTTokenProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache != "" && p.expiry.After(time.Now()) {
		return p.cache, nil
	}
	if p.fetch == nil {
		return "", errNoFetcher
	}
	tok, err := p.fetch(ctx)
	if err != nil {
		return "", err
	}
	p.cache = tok
	p.expiry = jwtExpiry(tok) // zero time if unparseable -> always refetch
	return tok, nil
}

// jwtExpiry reads the `exp` claim from an unverified JWT payload. It does not
// validate the signature; it only schedules rotation. Returns zero time if the
// token is not parseable.
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}
	}
	if claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

var errEmptyToken = errorString("tupago: empty token")
var errNoFetcher = errorString("tupago: JWTTokenProvider has no fetcher")

type errorString string

func (e errorString) Error() string { return string(e) }
