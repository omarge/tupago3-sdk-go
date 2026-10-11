// Package tupago3 is the idiomatic root import for the TUPAGO3 Go SDK. It
// re-exports the most common entry points; the subpackages
// (client, auth, security, errors, retry, proto/tupago/api/v1) are the
// canonical, stable public API and may be imported directly.
package tupago3

import (
	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/retry"
	"github.com/omarge/tupago3-sdk-go/security"
)

// Client API.
type (
	PaymentClient = client.PaymentClient
	Config        = client.Config
)

var (
	NewClient             = client.NewClient
	ValidateMonto         = client.ValidateMonto
	MaxMonto              = client.MaxMonto
	MinMonto              = client.MinMonto
	DefaultMaxRecvMsgSize = client.DefaultMaxRecvMsgSize
	DefaultMaxSendMsgSize = client.DefaultMaxSendMsgSize
	DefaultConnectTimeout = client.DefaultConnectTimeout
)

// Auth API.
var (
	StaticTokenProvider  = auth.StaticTokenProvider
	FuncTokenProvider    = auth.FuncTokenProvider
	NewJWTTokenProvider  = auth.NewJWTTokenProvider
	NewBearerCredentials = auth.NewBearerCredentials
)

type (
	TokenProvider     = auth.TokenProvider
	PerRPCCredentials = auth.PerRPCCredentials
)

// Security API.
var (
	NewTLSConfig  = security.NewTLSConfig
	IsLoopback    = security.IsLoopback
	WithCACertPEM = security.WithCACertPEM
)

type TLSConfig = security.TLSConfig

// Errors API.
type (
	TupagoError                = errors.TupagoError
	UnknownOutcomeError        = errors.UnknownOutcomeError
	PendingReconciliationError = errors.PendingReconciliationError
	ConfigError                = errors.ConfigError
)

var (
	NewInvalidArgument          = errors.NewInvalidArgument
	NewPendingReconciliation    = errors.NewPendingReconciliation
	NewUnknownOutcome           = errors.NewUnknownOutcome
	MapRPCError                 = errors.MapRPCError
	MapCreateError              = errors.MapCreateError
	IsTupagoError               = errors.IsTupagoError
	IsUnknownOutcome            = errors.IsUnknownOutcome
	IsPendingReconciliation     = errors.IsPendingReconciliation
	IsRequestNotSent            = errors.IsRequestNotSent
	HasGRPCCode                 = errors.HasGRPCCode
	PendingReconciliationMarker = errors.PendingReconciliationMarker
)

// Retry API.
var (
	NoRetry            = retry.NoRetry
	BoundedReadBackoff = retry.BoundedReadBackoff
	IsRetryableRead    = retry.IsRetryableRead
)

type RetryPolicy = retry.Policy

// Proto types (re-exported for convenience).
type (
	GetClienteRequest       = v1.GetClienteRequest
	GetCatalogoRequest      = v1.GetCatalogoRequest
	GetStatusRequest        = v1.GetStatusRequest
	CreateQrRequest         = v1.CreateQrRequest
	CreateTelefonicoRequest = v1.CreateTelefonicoRequest
	ClientePerfil           = v1.ClientePerfil
	Cliente                 = v1.Cliente
	CatalogoInstitucion     = v1.CatalogoInstitucion
	JsonResponse            = v1.JsonResponse
)
