package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/omarge/tupago3-sdk-go/auth"
)

func TestStaticTokenProviderRejectsEmpty(t *testing.T) {
	_, err := auth.StaticTokenProvider("").Token(context.Background())
	require.Error(t, err)
}

func TestStaticTokenProviderReturnsToken(t *testing.T) {
	tok, err := auth.StaticTokenProvider("abc").Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "abc", tok)
}

func TestBearerCredentialsHeader(t *testing.T) {
	c := auth.NewBearerCredentials(auth.StaticTokenProvider("secret"), true)
	md, err := c.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer secret", md["authorization"])
	assert.True(t, c.RequireTransportSecurity())

	plain := auth.NewBearerCredentials(auth.StaticTokenProvider("secret"), false)
	assert.False(t, plain.RequireTransportSecurity())
}

func TestJWTTokenProviderCachesUntilExpiry(t *testing.T) {
	calls := 0
	fetch := func(context.Context) (string, error) {
		calls++
		// valid-for-1h exp claim
		return "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQ5MjI3MDcyMDAsImIiOiJjIn0.x", nil
	}
	p := auth.NewJWTTokenProvider(fetch)
	tok1, err := p.Token(context.Background())
	require.NoError(t, err)
	tok2, err := p.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2)
	assert.Equal(t, 1, calls, "token must be cached within validity")
}

func TestJWTTokenProviderRefetchesWhenUnparseable(t *testing.T) {
	calls := 0
	fetch := func(context.Context) (string, error) {
		calls++
		return "not-a-jwt", nil
	}
	p := auth.NewJWTTokenProvider(fetch)
	_, _ = p.Token(context.Background())
	_, _ = p.Token(context.Background())
	assert.Equal(t, 2, calls, "unparseable exp must force refetch")
}
