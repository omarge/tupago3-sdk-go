// Package security enforces the transport security policy:
//   - Remote (non-loopback) targets REQUIRE TLS with certificate verification.
//   - Plaintext is permitted ONLY for loopback addresses (127.0.0.1, ::1,
//     localhost).
//   - A consumer-supplied CA is supported for private PKI.
package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// TLSConfig wraps a *tls.Config for use as gRPC transport credentials.
type TLSConfig struct {
	*tls.Config
}

// Option mutates a *tls.Config.
type Option func(*tls.Config) error

// WithCACertPEM installs a custom root CA from PEM bytes (private PKI).
func WithCACertPEM(pem []byte) Option {
	return func(c *tls.Config) error {
		if len(pem) == 0 {
			return errors.New("tupago: empty CA PEM")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("tupago: failed to parse CA PEM")
		}
		c.RootCAs = pool
		return nil
	}
}

// WithServerName sets the TLS server name used for certificate verification
// (matched against the certificate SAN). It does NOT disable verification.
func WithServerName(name string) Option {
	return func(c *tls.Config) error {
		if name == "" {
			return errors.New("tupago: empty ServerName")
		}
		c.ServerName = name
		return nil
	}
}

// NewTLSConfig builds a TLS config with a secure baseline (TLS 1.2+). Server
// certificate verification is ALWAYS enforced; there is no option to disable it.
func NewTLSConfig(opts ...Option) (*TLSConfig, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	return &TLSConfig{Config: cfg}, nil
}

// IsLoopback reports whether host (with or without port) is a loopback address.
func IsLoopback(target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	case "":
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RequireTLSForTarget enforces plaintext-only-on-loopback. It returns an error
// when a non-loopback target is configured without TLS.
func RequireTLSForTarget(target string, tlsEnabled bool) error {
	if !IsLoopback(target) && !tlsEnabled {
		return errors.New("tupago: TLS required for non-loopback target " +
			target + "; plaintext is only allowed for loopback (127.0.0.1, ::1, localhost)")
	}
	if !tlsEnabled && IsLoopback(target) {
		// loopback plaintext is explicitly permitted
		return nil
	}
	return nil
}
