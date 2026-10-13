package client

import (
	"context"
	"time"

	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// defaultCallTimeout bounds any RPC whose caller context has no deadline, so a
// create/read against an unreachable server fails fast (mapping to a typed error)
// instead of blocking on indefinite transport reconnect.
const defaultCallTimeout = 30 * time.Second

// withDefaultDeadline returns a context that carries a deadline if the caller's
// context does not already have one. The returned CancelFunc must be deferred.
func withDefaultDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultCallTimeout)
}

// Transport is the protocol-agnostic backend for the six PaymentService
// capabilities. Both the gRPC and REST adapters implement it, returning the same
// typed results and the SDK's canonical error model so callers are
// transport-neutral. Reads apply the bounded read-retry policy held by
// PaymentClient; creates are exactly-once and never auto-retried.
type Transport interface {
	GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error)
	GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error)
	GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error)
	GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error)
	CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error)
	CreateTelefonico(ctx context.Context, req *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error)
}

// grpcTransport is the gRPC peer adapter. It delegates to the generated
// v1.PaymentServiceClient and applies the exact same error classification
// (ReadRetry is applied by PaymentClient; create uses MapCreateError with the
// rpcstats wire-send tracker).
type grpcTransport struct {
	raw v1.PaymentServiceClient
}

func (g *grpcTransport) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	out, err := g.raw.GetCliente(ctx, req)
	if err != nil {
		return nil, errors.MapRPCError(err, "GetCliente")
	}
	return out, nil
}

func (g *grpcTransport) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	out, err := g.raw.GetCatalogo(ctx, req)
	if err != nil {
		return nil, errors.MapRPCError(err, "GetCatalogo")
	}
	return out, nil
}

func (g *grpcTransport) GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	out, err := g.raw.GetQrStatus(ctx, req)
	if err != nil {
		return nil, errors.MapRPCError(err, "GetQrStatus")
	}
	return out, nil
}

func (g *grpcTransport) GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	out, err := g.raw.GetTelefonicoStatus(ctx, req)
	if err != nil {
		return nil, errors.MapRPCError(err, "GetTelefonicoStatus")
	}
	return out, nil
}

func (g *grpcTransport) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	ctx, sentFn := withSendTracking(ctx)
	out, err := g.raw.CreateQr(ctx, req)
	if err != nil {
		return nil, errors.MapCreateError(err, "CreateQr", sentFn())
	}
	return out, nil
}

func (g *grpcTransport) CreateTelefonico(ctx context.Context, req *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error) {
	ctx, cancel := withDefaultDeadline(ctx)
	defer cancel()
	ctx, sentFn := withSendTracking(ctx)
	out, err := g.raw.CreateTelefonico(ctx, req)
	if err != nil {
		return nil, errors.MapCreateError(err, "CreateTelefonico", sentFn())
	}
	return out, nil
}
