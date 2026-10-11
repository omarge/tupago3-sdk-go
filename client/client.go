// Package client is the public, idiomatic entry point of the TUPAGO3 Go SDK.
// It exposes PaymentClient with the six PaymentService RPCs, injectable TLS and
// JWT configuration, bounded read retries, and the strict "Create is
// exactly-once, never auto-retried" financial invariant.
package client

import (
	"context"
	"strings"
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

	// Insecure disables TLS and uses plaintext transport credentials. It is only
	// permitted for loopback targets, or for in-memory test transports that are
	// not addressable as a network host (e.g. a bufconn "bufnet" target reached
	// via a grpc.WithContextDialer in ExtraDialOptions). NEVER use Insecure
	// against a real remote target: plaintext to a non-loopback, non-in-memory
	// target is rejected at construction time (fail-closed).
	Insecure bool

	// ExtraDialOptions are appended last to the grpc dial options.
	ExtraDialOptions []grpc.DialOption
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
func NewClient(ctx context.Context, cfg *Config) (*PaymentClient, error) {
	if cfg == nil {
		return nil, errors.NewConfigError("cfg", "nil config")
	}
	if cfg.Target == "" {
		return nil, errors.NewConfigError("Target", "required")
	}
	tlsEnabled := cfg.TLS != nil
	plaintextAllowed := false
	if cfg.Insecure {
		if security.IsLoopback(cfg.Target) || isInMemoryTarget(cfg.Target) {
			plaintextAllowed = true
		} else {
			return nil, errors.NewConfigError("Insecure",
				"plaintext not permitted for non-loopback target "+cfg.Target)
		}
	}
	if !plaintextAllowed && !tlsEnabled {
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
	if tlsEnabled {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg.TLS.Config)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(perRPC))
	dialOpts = append(dialOpts, cfg.ExtraDialOptions...)

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

// isInMemoryTarget reports whether target addresses an in-memory test transport
// (e.g. a bufconn "bufnet" listener) rather than a real network host. Such
// targets are only reachable through a custom dialer supplied via
// ExtraDialOptions (grpc.WithContextDialer), so plaintext is safe there: it can
// never reach an off-host peer. This is the only sanctioned exception to the
// loopback-only plaintext rule and replaces the removed AllowInsecureNonLoopback
// public flag, which previously let callers disable TLS for arbitrary remote
// targets.
func isInMemoryTarget(target string) bool {
	if target == "" {
		return false
	}
	if target == "bufnet" {
		return true
	}
	// grpc's passthrough resolver passes the target verbatim to the dialer,
	// which for bufconn is a grpc.WithContextDialer to an in-memory listener.
	if strings.HasPrefix(target, "passthrough://") {
		return true
	}
	return false
}
