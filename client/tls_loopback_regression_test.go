package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F03 regression: a loopback target with NEITHER explicit TLS NOR explicit
// Insecure must NOT silently fall back to plaintext. Explicit TLS (or an explicit
// Insecure opt-in) is required. Verification is never disabled.
func TestLoopbackNoSilentPlaintext(t *testing.T) {
	ctx := context.Background()

	// Loopback, no TLS, no Insecure -> config error (fail-closed, no downgrade).
	_, err := client.NewClient(ctx, &client.Config{Target: "127.0.0.1:29091"})
	require.Error(t, err, "loopback without explicit TLS/Insecure must be rejected")
	assert.Contains(t, err.Error(), "TLS",
		"rejection must demand explicit TLS, not silently downgrade to plaintext")

	// Non-loopback, no TLS -> config error (unchanged fail-closed baseline).
	_, err = client.NewClient(ctx, &client.Config{Target: "10.0.0.5:443"})
	require.Error(t, err)

	// Explicit Insecure + loopback is the only sanctioned plaintext path. It must
	// pass config validation (it will then fail at connect, since no server is up,
	// but must NOT be rejected with the TLS-required message).
	_, err = client.NewClient(ctx, &client.Config{Target: "127.0.0.1:29091", Insecure: true})
	require.Error(t, err, "expected connect failure (no server) for plaintext loopback")
	assert.False(t, strings.Contains(err.Error(), "explicit TLS is required"),
		"explicit Insecure loopback must not be rejected as TLS-required")
}
