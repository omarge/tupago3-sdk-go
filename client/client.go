// Package client is the public, idiomatic entry point of the TUPAGO3 Go SDK.
// It exposes PaymentClient with the six PaymentService RPCs, injectable TLS and
// JWT configuration, bounded read retries, and the strict "Create is
// exactly-once, never auto-retried" financial invariant.
//
// TRANSPORT SECURITY (fail-closed):
//   - Loopback targets may use plaintext (Insecure) — this is the only sanctioned
//     plaintext path and is used for the isolated loopback dev/backend lab.
//   - Any non-loopback target REQUIRES verified TLS. There is NO public option that
//     can downgrade or bypass this: the SDK derives transport credentials solely
//     from cfg.TLS / cfg.Insecure (loopback-checked) and appends them LAST, so they
//     are authoritative and cannot be overridden by caller-supplied dial options.
//   - TestDialer is a TEST-ONLY escape hatch that injects a connection dialer
//     (e.g. an in-memory bufconn listener). It carries NO transport credentials and
//     therefore cannot disable TLS; if TLS is configured the dialer connection is
//     still TLS-protected, and Insecure (plaintext) remains loopback-only.
package client

import (
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/omarge/tupago3-sdk-go/auth"
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
	// target with Insecure is rejected at construction time (fail-closed); this
	// holds even when TestDialer is supplied. NEVER use Insecure against a real
	// remote target.
	Insecure bool

	// TestDialer is a TEST-ONLY escape hatch that injects a custom connection
	// dialer (e.g. an in-memory bufconn listener) via grpc.WithContextDialer. It
	// MUST NOT be used in production. Crucially it carries NO transport credentials
	// and cannot disable TLS: the SDK always sets its own transport credentials
	// (derived from TLS/Insecure) AFTER the dialer, so they remain authoritative.
	// Callers must ensure the dialer is in-memory; the SDK cannot verify this and
	// relies on the documented test contract. Insecure (plaintext) stays
	// loopback-only regardless of TestDialer.
	TestDialer func(ctx context.Context, addr string) (net.Conn, error)
}

// PaymentClient is a reusable, concurrency-safe TUPAGO3 client.
type PaymentClient struct {
	conn    *grpc.ClientConn
	raw     v1.PaymentServiceClient
	cfg     *Config
	tracker *rpcstats.Tracker

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

	// Plaintext is permitted ONLY for loopback targets. This is fail-closed: a
	// non-loopback target with Insecure is rejected regardless of any dialer.
	plaintextAllowed := false
	if cfg.Insecure {
		if !security.IsLoopback(cfg.Target) {
			return nil, errors.NewConfigError("Insecure",
				"plaintext not permitted for non-loopback target "+cfg.Target)
		}
		plaintextAllowed = true
	}
	if !plaintextAllowed && !tlsEnabled {
		// Loopback without TLS is explicitly permitted; non-loopback without TLS
		// is rejected by RequireTLSForTarget (fail-closed).
		if err := security.RequireTLSForTarget(cfg.Target, false); err != nil {
			return nil, err
		}
		plaintextAllowed = true
	}

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

	// TEST-ONLY dialer injection. It is added BEFORE transport credentials so it
	// can never override the SDK's chosen security. The dialer only decides HOW to
	// reach the peer; the SDK still enforces TLS-or-loopback-plaintext on top.
	if cfg.TestDialer != nil {
		dialOpts = append(dialOpts, grpc.WithContextDialer(cfg.TestDialer))
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
		conn:    conn,
		raw:     v1.NewPaymentServiceClient(conn),
		cfg:     cfg,
		tracker: tracker,
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
