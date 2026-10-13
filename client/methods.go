package client

import (
	"context"

	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// GetCliente returns the client profile for the given id. Bounded read retry.
func (c *PaymentClient) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	var out *v1.ClientePerfil
	err := c.readPolicy().Do(ctx, func(ctx context.Context) error {
		var e error
		out, e = c.transport.GetCliente(ctx, req)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetCatalogo returns the institution catalog for a clave. Bounded read retry.
func (c *PaymentClient) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	var out *v1.CatalogoInstitucion
	err := c.readPolicy().Do(ctx, func(ctx context.Context) error {
		var e error
		out, e = c.transport.GetCatalogo(ctx, req)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetQrStatus returns the raw Banxico QR status payload. Bounded read retry.
func (c *PaymentClient) GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	var out *v1.JsonResponse
	err := c.readPolicy().Do(ctx, func(ctx context.Context) error {
		var e error
		out, e = c.transport.GetQrStatus(ctx, req)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetTelefonicoStatus returns the raw Banxico telefonico status payload.
// Bounded read retry.
func (c *PaymentClient) GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	var out *v1.JsonResponse
	err := c.readPolicy().Do(ctx, func(ctx context.Context) error {
		var e error
		out, e = c.transport.GetTelefonicoStatus(ctx, req)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateQr creates a QR payment. EXACTLY ONE attempt is made; the call is never
// retried. Transient errors after the request is sent map to UnknownOutcomeError
// (reconcile, do not blind-retry). The idempotency_key is preserved verbatim.
func (c *PaymentClient) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	if err := validateCreateQr(req); err != nil {
		return nil, err
	}
	return c.transport.CreateQr(ctx, req)
}

// CreateTelefonico creates a telefonico payment. EXACTLY ONE attempt, never
// retried, same financial invariants as CreateQr.
func (c *PaymentClient) CreateTelefonico(ctx context.Context, req *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error) {
	if err := validateCreateTelefonico(req); err != nil {
		return nil, err
	}
	return c.transport.CreateTelefonico(ctx, req)
}

func validateCreateQr(req *v1.CreateQrRequest) error {
	if req == nil {
		return errors.NewInvalidArgument("CreateQr", "nil request")
	}
	if req.IdempotencyKey == "" {
		return errors.NewInvalidArgument("CreateQr", "idempotency_key is required and must be preserved verbatim")
	}
	if err := ValidateMonto(req.Monto); err != nil {
		return errors.NewInvalidArgument("CreateQr", "monto: "+err.Error())
	}
	return nil
}

func validateCreateTelefonico(req *v1.CreateTelefonicoRequest) error {
	if req == nil {
		return errors.NewInvalidArgument("CreateTelefonico", "nil request")
	}
	if req.IdempotencyKey == "" {
		return errors.NewInvalidArgument("CreateTelefonico", "idempotency_key is required and must be preserved verbatim")
	}
	if err := ValidateMonto(req.Monto); err != nil {
		return errors.NewInvalidArgument("CreateTelefonico", "monto: "+err.Error())
	}
	return nil
}
