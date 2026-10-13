// Package client is the public, idiomatic entry point of the TUPAGO3 Go SDK.
// It exposes PaymentClient with the six PaymentService RPCs, injectable TLS and
// JWT configuration, bounded read retries, and the strict "Create is
// exactly-once, never auto-retried" financial invariant.
//
// TRANSPORT SECURITY (fail-closed):
//   - Loopback targets may use plaintext (Insecure) — this is the only sanctioned
//     plaintext path and is used for the isolated loopback dev/backend lab.
//   - Any non-loopback target REQUIRES verified TLS with server-certificate
//     verification. There is NO public option that can downgrade or bypass this:
//     the SDK derives transport credentials solely from cfg.TLS / cfg.Insecure
//     (loopback-checked) and appends them LAST, so they are authoritative and cannot
//     be overridden. A consumer-supplied CA (WithCACertPEM) and ServerName are
//     supported, but server identity verification can never be disabled.
//   - There is no public dialer-injection option: tests use an in-process,
//     test-only server (real loopback listener) rather than a configurable dialer,
//     so no caller can redirect the connection to a remote plaintext peer.
package client

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client/graphql"
	"github.com/omarge/tupago3-sdk-go/client/rest"
	"github.com/omarge/tupago3-sdk-go/errors"
	"github.com/omarge/tupago3-sdk-go/internal/rpcstats"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/retry"
	"github.com/omarge/tupago3-sdk-go/security"
)

const (
	DefaultMaxRecvMsgSize = 16 * 1024 * 1024
	DefaultMaxSendMsgSize = 16 * 1024 * 1024
	DefaultConnectTimeout = 10 * time.Second
)

// Config configures a PaymentClient.
type Config struct {
	// Target is the gRPC authority, e.g. "127.0.0.1:8080" or "pay.tupago:443".
	Target string

	// TLS, when non-nil, enables verified TLS. Required for non-loopback.
	TLS *security.TLSConfig

	// Credentials supplies the per-RPC Bearer JWT. Exactly one of Credentials or
	// PerRPCCredentials should be set; PerRPCCredentials takes precedence.
	Credentials auth.TokenProvider

	// PerRPCCredentials overrides the default Bearer credentials.
	PerRPCCredentials credentials.PerRPCCredentials

	// ReadRetry overrides the default bounded read-backoff policy. Create RPCs
	// always use NoRetry regardless of this field.
	ReadRetry *retry.Policy

	// MaxRecvMsgSize / MaxSendMsgSize bound gRPC message sizes. Zero => default.
	MaxRecvMsgSize int
	MaxSendMsgSize int

	// ConnectTimeout bounds the initial connection readiness probe. Zero => default.
	ConnectTimeout time.Duration

	// Insecure disables TLS and uses plaintext transport credentials. It is ONLY
	// permitted for LOOPBACK targets (127.0.0.1, ::1, localhost). Any non-loopback
	// target with Insecure is rejected at construction time (fail-closed). NEVER
	// use Insecure against a real remote target.
	Insecure bool

	// Transport selects the wire protocol. "" or "grpc" use the gRPC peer adapter
	// (default). "rest" uses the REST/JSON peer adapter (requires REST). "graphql"
	// uses the GraphQL peer adapter (requires GraphQL). All adapters implement the
	// same six capabilities and return the identical typed results and error model.
	Transport string

	// REST configures the REST/JSON transport. Required when Transport == "rest".
	REST *RESTOptions

	// GraphQL configures the GraphQL transport. Required when Transport == "graphql".
	GraphQL *GraphQLOptions
}

// GraphQLOptions configures the GraphQL peer adapter (see client/graphql).
type GraphQLOptions struct {
	// EndpointURL is the backend origin, e.g. "https://pay.tupago.mx" or
	// "http://127.0.0.1:8080" for an isolated loopback lab.
	EndpointURL string

	// Endpoint is the GraphQL path (default "/graphql").
	Endpoint string

	// HTTPClient overrides the default *http.Client (e.g. for proxying/testing).
	// When nil, one is built from the client TLS/Insecure configuration.
	HTTPClient *http.Client
}

// RESTOptions configures the REST/JSON peer adapter (see client/rest).
type RESTOptions struct {
	// BaseURL is the backend origin, e.g. "https://pay.tupago.mx" or
	// "http://127.0.0.1:8080" for an isolated loopback lab.
	BaseURL string

	// Routes overrides individual capability paths. Nil uses backend3 defaults.
	Routes *rest.Routes

	// HTTPClient overrides the default *http.Client (e.g. for proxying/testing).
	// When nil, one is built from the client TLS/Insecure configuration.
	HTTPClient *http.Client
}

// PaymentClient is a reusable, concurrency-safe TUPAGO3 client.
type PaymentClient struct {
	conn      *grpc.ClientConn
	transport Transport
	cfg       *Config
	tracker   *rpcstats.Tracker

	closeOnce sync.Once
	closeErr  error
}

// NewClient builds and connects a PaymentClient. It fails fast on invalid
// configuration (e.g. non-loopback without TLS, missing target, empty token).
//
// Transport credentials are appended LAST and are authoritative: no caller
// option can override the SDK's chosen transport security.
func NewClient(ctx context.Context, cfg *Config) (*PaymentClient, error) {
	if cfg == nil {
		return nil, errors.NewConfigError("cfg", "nil config")
	}
	if cfg.Target == "" {
		return nil, errors.NewConfigError("Target", "required")
	}
	tlsEnabled := cfg.TLS != nil

	// For the REST/GraphQL transports the actual wire endpoint is REST.BaseURL /
	// GraphQL.EndpointURL; resolve the security/loopback target from it so
	// plaintext-only-on-loopback is enforced against the real destination, not the
	// (unused) gRPC Target.
	useREST := cfg.Transport == "rest" || (cfg.Transport == "" && cfg.REST != nil)
	secTarget := cfg.Target
	if useREST && cfg.REST != nil && cfg.REST.BaseURL != "" {
		if u, perr := url.Parse(cfg.REST.BaseURL); perr == nil && u.Host != "" {
			secTarget = u.Host
		}
	}
	if cfg.Transport == "graphql" && cfg.GraphQL != nil && cfg.GraphQL.EndpointURL != "" {
		if u, perr := url.Parse(cfg.GraphQL.EndpointURL); perr == nil && u.Host != "" {
			secTarget = u.Host
		}
	}

	// Server identity verification is ALWAYS required for TLS. Reject any config
	// that tries to disable it (fail-closed), including a consumer-supplied
	// *tls.Config mutated directly. Encryption without authentication is not
	// allowed by the public API.
	if tlsEnabled && cfg.TLS.Config != nil && cfg.TLS.Config.InsecureSkipVerify {
		return nil, errors.NewConfigError("TLS",
			"InsecureSkipVerify is not permitted: server certificate verification cannot be disabled")
	}

	// Plaintext is permitted ONLY when Insecure is explicitly set AND the target is
	// loopback. There is no implicit loopback exception: a target with neither an
	// explicit TLS config nor an explicit Insecure opt-in never silently falls back
	// to plaintext (fail-closed). This removes the previous loopback downgrade so
	// that transport security is always explicit and verifiable.
	plaintextAllowed := false
	if cfg.Insecure {
		if !security.IsLoopback(secTarget) {
			return nil, errors.NewConfigError("Insecure",
				"plaintext not permitted for non-loopback target "+cfg.Target)
		}
		plaintextAllowed = true
	}
	if !plaintextAllowed && !tlsEnabled {
		return nil, errors.NewConfigError("TLS",
			"explicit TLS is required: provide cfg.TLS (loopback plaintext is only permitted when Insecure:true is set explicitly)")
	}

	// GraphQL transport branch.
	if cfg.Transport == "graphql" {
		if cfg.Credentials == nil {
			return nil, errors.NewConfigError("Credentials", "a TokenProvider is required for the GraphQL transport (fail-closed)")
		}
		if cfg.GraphQL == nil || cfg.GraphQL.EndpointURL == "" {
			return nil, errors.NewConfigError("GraphQL", "GraphQL.EndpointURL is required when Transport=graphql")
		}
		tr, err := graphql.NewTransport(&graphql.Options{
			BaseURL:     cfg.GraphQL.EndpointURL,
			Endpoint:    cfg.GraphQL.Endpoint,
			HTTPClient:  cfg.GraphQL.HTTPClient,
			TLS:         cfg.TLS,
			Insecure:    cfg.Insecure,
			Credentials: cfg.Credentials,
		})
		if err != nil {
			return nil, err
		}
		return &PaymentClient{
			transport: tr,
			cfg:       cfg,
			tracker:   rpcstats.NewTracker(),
		}, nil
	}

	// REST/JSON transport branch.
	if cfg.Transport == "rest" || (cfg.Transport == "" && cfg.REST != nil) {
		if cfg.Credentials == nil {
			return nil, errors.NewConfigError("Credentials", "a TokenProvider is required for the REST transport (fail-closed)")
		}
		if cfg.REST == nil || cfg.REST.BaseURL == "" {
			return nil, errors.NewConfigError("REST", "REST.BaseURL is required when Transport=rest")
		}
		tr, err := rest.NewTransport(&rest.Options{
			BaseURL:     cfg.REST.BaseURL,
			Routes:      cfg.REST.Routes,
			HTTPClient:  cfg.REST.HTTPClient,
			TLS:         cfg.TLS,
			Insecure:    cfg.Insecure,
			Credentials: cfg.Credentials,
		})
		if err != nil {
			return nil, err
		}
		return &PaymentClient{
			transport: tr,
			cfg:       cfg,
			tracker:   rpcstats.NewTracker(),
		}, nil
	}

	// gRPC transport branch (default).
	var perRPC credentials.PerRPCCredentials
	requireTLS := tlsEnabled
	if cfg.PerRPCCredentials != nil {
		perRPC = cfg.PerRPCCredentials
	} else if cfg.Credentials != nil {
		perRPC = auth.NewBearerCredentials(cfg.Credentials, requireTLS)
	} else {
		return nil, errors.NewConfigError("Credentials", "a TokenProvider or PerRPCCredentials is required")
	}

	maxRecv := cfg.MaxRecvMsgSize
	if maxRecv <= 0 {
		maxRecv = DefaultMaxRecvMsgSize
	}
	maxSend := cfg.MaxSendMsgSize
	if maxSend <= 0 {
		maxSend = DefaultMaxSendMsgSize
	}

	tracker := rpcstats.NewTracker()
	dialOpts := []grpc.DialOption{
		grpc.WithStatsHandler(tracker.Handler()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxRecv),
			grpc.MaxCallSendMsgSize(maxSend),
		),
	}

	// Authoritative transport credentials (ALWAYS last). Derived solely from the
	// SDK's own config; callers cannot supply an alternative transport-credential
	// option, so there is no way to downgrade TLS to plaintext for a remote target.
	if tlsEnabled {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg.TLS.Config)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Per-RPC Bearer JWT (cannot alter transport security).
	dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(perRPC))

	conn, err := grpc.NewClient(cfg.Target, dialOpts...)
	if err != nil {
		return nil, errors.NewConfigError("Target", "dial failed: "+err.Error())
	}

	timeout := cfg.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	if err := waitReady(ctx, conn, timeout); err != nil {
		_ = conn.Close()
		return nil, errors.NewConfigError("Target", "connect timeout: "+err.Error())
	}

	return &PaymentClient{
		conn:      conn,
		transport: &grpcTransport{raw: v1.NewPaymentServiceClient(conn)},
		cfg:       cfg,
		tracker:   tracker,
	}, nil
}

func (c *PaymentClient) readPolicy() *retry.Policy {
	if c.cfg.ReadRetry != nil {
		return c.cfg.ReadRetry
	}
	return retry.Default()
}

// Close releases the underlying connection. It is safe to call multiple times.
func (c *PaymentClient) Close() error {
	if c.conn == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

// waitReady triggers connection and waits until Ready or ctx/timeout expires.
func waitReady(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn.Connect()
	for {
		s := conn.GetState()
		if s == connectivity.Ready {
			return nil
		}
		if s == connectivity.Shutdown {
			return errConnShutdown
		}
		if !conn.WaitForStateChange(ctx, s) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errConnNotReady
		}
	}
}

var (
	errConnShutdown = errors.NewConfigError("Target", "connection shutdown")
	errConnNotReady = errors.NewConfigError("Target", "connection not ready within timeout")
)
