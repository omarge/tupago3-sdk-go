// Package transportutil holds the SDK-authoritative invariants shared by the
// REST and GraphQL transport constructors and by client.NewClient. Centralizing
// them guarantees that NO public constructor path can bypass the scheme/TLS
// authority law (Gatekeeper R2, P0-HTTP-04/05).
package transportutil

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/omarge/tupago3-sdk-go/security"
)

// ValidateSchemeTLS enforces the SCHEME/TLS AUTHORITY LAW for REST/GraphQL HTTP
// endpoints (Gatekeeper R2, P0-HTTP-04):
//
//   - scheme MUST be present and be http or https.
//   - NON-LOOPBACK host: scheme MUST be https AND a verified TLS config MUST be
//     present (InsecureSkipVerify is never permitted).
//   - LOOPBACK host: https + TLS allowed; http ONLY when insecure==true.
//   - No other combination is permitted: http+TLS, http+Insecure=false,
//     http+Insecure=true for a remote host, and any unsupported scheme are all
//     rejected. Security is derived from the ACTUAL URL scheme+host, never from
//     cfg.TLS alone.
func ValidateSchemeTLS(rawURL string, tlsCfg *security.TLSConfig, insecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("tupago: invalid endpoint URL %q: %w", rawURL, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("tupago: endpoint URL %q has no scheme; expected http or https", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("tupago: unsupported scheme %q in endpoint URL %q; only http/https are permitted", u.Scheme, rawURL)
	}
	if u.Host == "" {
		return fmt.Errorf("tupago: endpoint URL %q has no host", rawURL)
	}

	// Server identity verification must never be disabled, in any configuration.
	if tlsCfg != nil && tlsCfg.Config != nil && tlsCfg.Config.InsecureSkipVerify {
		return fmt.Errorf("tupago: InsecureSkipVerify is not permitted on endpoint %q (server certificate verification cannot be disabled)", rawURL)
	}

	loopback := security.IsLoopback(u.Host)

	if scheme == "https" {
		if tlsCfg == nil || tlsCfg.Config == nil {
			return fmt.Errorf("tupago: https endpoint %q requires a verified TLS config", rawURL)
		}
		return nil
	}

	// scheme == "http"
	if !insecure {
		return fmt.Errorf("tupago: plaintext http endpoint %q requires Insecure:true", rawURL)
	}
	if !loopback {
		return fmt.Errorf("tupago: plaintext http endpoint %q with Insecure:true is only permitted for loopback targets", rawURL)
	}
	return nil
}

// CloneTLSConfig returns a defensive copy of the caller-supplied TLS config so the
// SDK-owned *http.Transport is immune to later caller-side mutation of the
// original *tls.Config (Gatekeeper R2, §5 / P0-HTTP-05). A nil input yields nil.
func CloneTLSConfig(tlsCfg *security.TLSConfig) *tls.Config {
	if tlsCfg == nil || tlsCfg.Config == nil {
		return nil
	}
	return tlsCfg.Config.Clone()
}
