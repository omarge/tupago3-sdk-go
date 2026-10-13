// Package graphql implements the GraphQL peer adapter for the TUPAGO3 Go SDK.
// It is a structural peer of the gRPC and REST adapters: every capability maps
// to a backend3 GraphQL operation (discovered from the authoritative backend3
// schema tupago.graphqls + TupagoGraphQlController), uses the standard library
// net/http + encoding/json, propagates context deadlines, injects the Bearer JWT
// from the existing auth.TokenProvider, and enforces the same int64 identity law,
// exactly-once create, idempotency, read-retry classification and
// UnknownOutcome / PendingReconciliation semantics as the other transports.
//
// The backend's GraphQlConfig maps domain exceptions to typed GraphQL errors
// carrying a stable "code" (IDEMPOTENCY_CONFLICT, PAYMENT_LIMIT,
// PAYMENT_PENDING_RECONCILIATION, ...) and a "classification" extension. We map
// those to the SDK's canonical gRPC-status-based error model so GraphQL clients
// detect outcomes exactly as gRPC/REST clients do (F07 cross-protocol parity).
//
// No third-party HTTP/GraphQL dependency is used; the transport is idiomatic Go.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Options configures the GraphQL transport.
type Options struct {
	// BaseURL is the backend origin, e.g. "https://pay.tupago.mx" or
	// "http://127.0.0.1:8080" for an isolated loopback lab.
	BaseURL string
	// Endpoint is the GraphQL path (default "/graphql").
	Endpoint string

	// TLS, when non-nil, provides the verified TLS configuration (fail-closed;
	// server certificate verification can never be disabled). Insecure is only
	// honoured for loopback targets by the caller (client.NewClient).
	TLS *security.TLSConfig
	// Insecure selects plaintext HTTP (loopback-only, enforced by client.NewClient).
	Insecure bool
	// Credentials supplies the per-request Bearer JWT (never logged).
	Credentials auth.TokenProvider
}

// sentTracker provides authoritative HTTP send tracking via httptrace.WroteRequest,
// the HTTP analogue of the gRPC rpcstats send tracker (P0-HTTP-01). If the request
// was written (or we cannot prove it was not), a later failure is an UnknownOutcome
// (reconcile), never request-not-sent.
type sentTracker struct {
	wroteRequest atomic.Bool
}

func (s *sentTracker) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { s.wroteRequest.Store(true) },
	}
}

func (s *sentTracker) wrote() bool { return s.wroteRequest.Load() }

// Transport is the GraphQL implementation of the SDK's PaymentService capabilities.
// It satisfies the client.Transport interface structurally.
type Transport struct {
	endpoint string
	creds    auth.TokenProvider
	hc       *http.Client
}

// NewTransport builds a GraphQL Transport. The *http.Client is ALWAYS constructed by
// the SDK from the TLS/Insecure configuration with a fail-closed redirect policy (no
// automatic following) so the SDK stays authoritative for destination, TLS and
// financial send tracking (P0-HTTP-02/03).
func NewTransport(o *Options) (*Transport, error) {
	if o == nil {
		return nil, sdkerrors.NewConfigError("GraphQL", "nil options")
	}
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		return nil, sdkerrors.NewConfigError("GraphQL", "BaseURL is required")
	}
	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = "/graphql"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	tr := &http.Transport{}
	if o.TLS != nil && o.TLS.Config != nil {
		tr.TLSClientConfig = o.TLS.Config
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		// Fail-closed: never automatically follow redirects. A 3xx is returned to the
		// caller as a non-success response without issuing a second request (preserves
		// single financial dispatch; no bearer/variable leakage).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Transport{endpoint: base + endpoint, creds: o.Credentials, hc: hc}, nil
}

// ---- GraphQL wire types ----

type gqlRequest struct {
	OperationName string                 `json:"operationName"`
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables"`
}

type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

type gqlError struct {
	Message    string                 `json:"message"`
	Extensions map[string]interface{} `json:"extensions"`
}

// idString marshals an int64 to a JSON string, matching the GraphQL ID scalar and
// preserving the int64 identity law exactly (no float64 truncation).
type idString int64

func (i idString) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatInt(int64(i), 10) + `"`), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// ---- request execution ----

// call executes a GraphQL-over-HTTP POST. It returns the response, the response
// body bytes, whether the request bytes were placed on the wire (authoritative, via
// httptrace), and a network error (nil on an HTTP-level response).
func (t *Transport) call(ctx context.Context, opName, query string, vars map[string]interface{}) (*http.Response, []byte, bool, error) {
	payload := gqlRequest{OperationName: opName, Query: query, Variables: vars}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, false, err
	}
	req, err := http.NewRequest(http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if t.creds == nil {
		return nil, nil, false, sdkerrors.NewConfigError("Credentials", "a TokenProvider is required (fail-closed)")
	}
	tok, e := t.creds.Token(ctx)
	if e != nil {
		return nil, nil, false, sdkerrors.NewConfigError("Credentials", "token provider error: "+e.Error())
	}
	if tok == "" {
		return nil, nil, false, sdkerrors.NewConfigError("Credentials", "empty bearer token (fail-closed)")
	}
	// Token is never written to any log.
	req.Header.Set("Authorization", "Bearer "+tok)

	var sent sentTracker
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), sent.trace()))
	resp, netErr := t.hc.Do(req)
	if netErr != nil {
		// A generic network error after the request may have reached the server is
		// conservatively classified as sent (UnknownOutcome), never request-not-sent.
		return nil, nil, sent.wrote(), netErr
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp, rb, sent.wrote(), nil
}

func httpStatusToCode(sc int) codes.Code {
	switch {
	case sc == 202:
		return codes.Aborted // PendingReconciliation (must precede the 2xx range)
	case sc >= 200 && sc < 300:
		return codes.OK
	case sc >= 300 && sc < 400:
		// A 3xx reached the SDK only because CheckRedirect is fail-closed
		// (ErrUseLastResponse): the SDK refuses to follow it, so the server did NOT
		// process a payment. Definite, non-retryable client policy outcome (not an
		// ambiguous financial UnknownOutcome); must not trigger a resend.
		return codes.FailedPrecondition
	case sc == 400:
		return codes.InvalidArgument
	case sc == 401:
		return codes.Unauthenticated
	case sc == 403:
		return codes.PermissionDenied
	case sc == 404:
		return codes.NotFound
	case sc == 409:
		return codes.AlreadyExists
	case sc == 429:
		return codes.Unavailable
	case sc >= 500:
		return codes.Unavailable
	case sc >= 400:
		return codes.InvalidArgument
	default:
		return codes.Unknown
	}
}

func (t *Transport) errorFromHTTP(op string, resp *http.Response, body []byte, isCreate bool) error {
	code := httpStatusToCode(resp.StatusCode)
	msg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	se := status.Error(code, msg)
	if isCreate {
		// For a create, a non-2xx transport response means the request bytes were
		// placed on the wire (request was sent), so classify definitively.
		return sdkerrors.MapCreateError(se, op, true)
	}
	return sdkerrors.MapRPCError(se, op)
}

// mapErr maps a GraphQL error entry into the SDK's canonical error model.
func (t *Transport) mapErr(op string, ge gqlError, isCreate, sent bool) error {
	code := codes.Unknown
	msg := ge.Message

	if c, ok := ge.Extensions["code"].(string); ok {
		switch c {
		case "PAYMENT_PENDING_RECONCILIATION":
			return sdkerrors.NewPendingReconciliation(op, msg)
		case "IDEMPOTENCY_CONFLICT", "POLICY_REVISION_CONFLICT":
			code = codes.AlreadyExists
		case "PAYMENT_LIMIT":
			code = codes.InvalidArgument
		}
	}
	if cls, ok := ge.Extensions["classification"].(string); ok {
		switch cls {
		case "unauthorized":
			code = codes.Unauthenticated
		case "forbidden":
			code = codes.PermissionDenied
		case "not_found":
			code = codes.NotFound
		case "bad_request":
			code = codes.InvalidArgument
		case "conflict":
			code = codes.AlreadyExists
		case "accepted":
			return sdkerrors.NewPendingReconciliation(op, msg)
		case "internal_error", "data_fetching_error", "operation_not_supported":
			code = codes.Unknown
		}
	}

	se := status.Error(code, msg)
	if isCreate {
		return sdkerrors.MapCreateError(se, op, sent)
	}
	return sdkerrors.MapRPCError(se, op)
}

// parseResponse returns the operation's data node (raw JSON) and, if present, the
// first GraphQL error. An empty data node with no errors yields (nil, nil).
func parseResponse(op string, body []byte) (json.RawMessage, *gqlError) {
	var gr gqlResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, &gqlError{Message: "malformed GraphQL response: " + err.Error()}
	}
	if len(gr.Errors) > 0 {
		return nil, &gr.Errors[0]
	}
	if len(gr.Data) == 0 {
		return nil, nil
	}
	var dataObj map[string]json.RawMessage
	if err := json.Unmarshal(gr.Data, &dataObj); err != nil {
		return nil, &gqlError{Message: "malformed GraphQL data: " + err.Error()}
	}
	raw, ok := dataObj[op]
	if !ok {
		return nil, nil
	}
	return raw, nil
}

func invalidArg(op, msg string) error { return sdkerrors.NewInvalidArgument(op, msg) }

func netErrToOp(op string, netErr error, isCreate, sent bool) error {
	se := status.Error(codes.Unavailable, "tupago GraphQL network error: "+netErr.Error())
	if isCreate {
		return sdkerrors.MapCreateError(se, op, sent)
	}
	return sdkerrors.MapRPCError(se, op)
}

// ---- GraphQL operation documents ----

const (
	opCliente   = "cliente"
	opCatalogo  = "catalogoInstitucion"
	opQrStatus  = "pagoQrEstatusByCuenta"
	opTelStatus = "pagoTelefonicoEstatusByCuenta"
	opCreateQr  = "createPagoQr"
	opCreateTel = "createPagoTelefonico"

	queryCliente = `query Cliente($id: ID!) {
  cliente(id: $id) {
    cliente { id nombre claveInstitucion key }
    catalogoInstitucion { id claveInstitucion nombreCorto }
  }
}`

	queryCatalogo = `query Catalogo($claveInstitucion: String!) {
  catalogoInstitucion(claveInstitucion: $claveInstitucion) {
    id claveInstitucion nombreCorto
  }
}`

	queryQrStatus = `query PagoQrEstatusByCuenta($idc: String!, $idCuenta: ID!) {
  pagoQrEstatusByCuenta(idc: $idc, idCuenta: $idCuenta)
}`

	queryTelStatus = `query PagoTelefonicoEstatusByCuenta($idc: String!, $idCuenta: ID!) {
  pagoTelefonicoEstatusByCuenta(idc: $idc, idCuenta: $idCuenta)
}`

	mutationCreateQr = `mutation CreatePagoQr($input: PagoQrInput!, $idempotencyKey: String) {
  createPagoQr(input: $input, idempotencyKey: $idempotencyKey)
}`

	mutationCreateTel = `mutation CreatePagoTelefonico($input: PagoTelefonicoInput!, $idempotencyKey: String) {
  createPagoTelefonico(input: $input, idempotencyKey: $idempotencyKey)
}`
)

// ---- response DTOs (int64 law via i64) ----

type i64 int64

func (i i64) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(i), 10)), nil
}

func (i *i64) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		*i = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return stderrors.New("tupago: invalid int64 JSON: " + string(b))
	}
	*i = i64(n)
	return nil
}

type gqlCliente struct {
	ID               i64    `json:"id"`
	Nombre           string `json:"nombre"`
	ClaveInstitucion string `json:"claveInstitucion"`
	Key              string `json:"key"`
}

type gqlCatalogo struct {
	ID               i64    `json:"id"`
	ClaveInstitucion string `json:"claveInstitucion"`
	NombreCorto      string `json:"nombreCorto"`
}

type gqlClientePerfil struct {
	Cliente             *gqlCliente  `json:"cliente"`
	CatalogoInstitucion *gqlCatalogo `json:"catalogoInstitucion"`
}

// ---- Transport interface implementation ----

// GetCliente fetches the owned client profile and composes the institution
// catalog (mirroring the gRPC/REST composition from backend3).
func (t *Transport) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if req == nil {
		return nil, invalidArg("GetCliente", "nil request")
	}
	resp, body, sent, netErr := t.call(ctx, opCliente, queryCliente, map[string]interface{}{
		"id": strconv.FormatInt(req.Id, 10),
	})
	if netErr != nil {
		return nil, netErrToOp("GetCliente", netErr, false, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("GetCliente", resp, body, false)
	}
	raw, ge := parseResponse(opCliente, body)
	if ge != nil {
		return nil, t.mapErr("GetCliente", *ge, false, false)
	}
	if len(raw) == 0 {
		return nil, sdkerrors.MapRPCError(status.Error(codes.NotFound, "cliente not found"), "GetCliente")
	}
	var perfil gqlClientePerfil
	if err := json.Unmarshal(raw, &perfil); err != nil {
		return nil, sdkerrors.MapRPCError(status.Error(codes.InvalidArgument, "malformed cliente JSON: "+err.Error()), "GetCliente")
	}
	if perfil.Cliente == nil || perfil.Cliente.ID == 0 {
		return nil, sdkerrors.MapRPCError(status.Error(codes.NotFound, "cliente missing mandatory id"), "GetCliente")
	}
	out := &v1.ClientePerfil{
		Cliente: &v1.Cliente{
			Id:               int64(perfil.Cliente.ID),
			Nombre:           perfil.Cliente.Nombre,
			ClaveInstitucion: perfil.Cliente.ClaveInstitucion,
			Key:              perfil.Cliente.Key,
		},
	}
	if perfil.CatalogoInstitucion != nil {
		out.CatalogoInstitucion = &v1.CatalogoInstitucion{
			Id:               int64(perfil.CatalogoInstitucion.ID),
			ClaveInstitucion: perfil.CatalogoInstitucion.ClaveInstitucion,
			NombreCorto:      perfil.CatalogoInstitucion.NombreCorto,
		}
	}
	return out, nil
}

// GetCatalogo fetches the institution catalog by Banxico clave.
func (t *Transport) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	if req == nil {
		return nil, invalidArg("GetCatalogo", "nil request")
	}
	if req.ClaveInstitucion == "" {
		return nil, invalidArg("GetCatalogo", "clave_institucion is required")
	}
	resp, body, sent, netErr := t.call(ctx, opCatalogo, queryCatalogo, map[string]interface{}{
		"claveInstitucion": req.ClaveInstitucion,
	})
	if netErr != nil {
		return nil, netErrToOp("GetCatalogo", netErr, false, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("GetCatalogo", resp, body, false)
	}
	raw, ge := parseResponse(opCatalogo, body)
	if ge != nil {
		return nil, t.mapErr("GetCatalogo", *ge, false, false)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, sdkerrors.MapRPCError(status.Error(codes.NotFound, "catalogo not found"), "GetCatalogo")
	}
	var cat gqlCatalogo
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, sdkerrors.MapRPCError(status.Error(codes.InvalidArgument, "malformed catalogo JSON: "+err.Error()), "GetCatalogo")
	}
	if cat.ID == 0 || cat.ClaveInstitucion == "" {
		return nil, sdkerrors.MapRPCError(status.Error(codes.NotFound, "catalogo missing mandatory id or clave"), "GetCatalogo")
	}
	return &v1.CatalogoInstitucion{
		Id:               int64(cat.ID),
		ClaveInstitucion: cat.ClaveInstitucion,
		NombreCorto:      cat.NombreCorto,
	}, nil
}

// GetQrStatus returns the raw Banxico QR status payload.
func (t *Transport) GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("GetQrStatus", "nil request")
	}
	resp, body, sent, netErr := t.call(ctx, opQrStatus, queryQrStatus, map[string]interface{}{
		"idc":      req.Idc,
		"idCuenta": idString(req.IdCuenta),
	})
	if netErr != nil {
		return nil, netErrToOp("GetQrStatus", netErr, false, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("GetQrStatus", resp, body, false)
	}
	raw, ge := parseResponse(opQrStatus, body)
	if ge != nil {
		return nil, t.mapErr("GetQrStatus", *ge, false, false)
	}
	return &v1.JsonResponse{Json: string(raw)}, nil
}

// GetTelefonicoStatus returns the raw Banxico telefonico status payload.
func (t *Transport) GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("GetTelefonicoStatus", "nil request")
	}
	resp, body, sent, netErr := t.call(ctx, opTelStatus, queryTelStatus, map[string]interface{}{
		"idc":      req.Idc,
		"idCuenta": idString(req.IdCuenta),
	})
	if netErr != nil {
		return nil, netErrToOp("GetTelefonicoStatus", netErr, false, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("GetTelefonicoStatus", resp, body, false)
	}
	raw, ge := parseResponse(opTelStatus, body)
	if ge != nil {
		return nil, t.mapErr("GetTelefonicoStatus", *ge, false, false)
	}
	return &v1.JsonResponse{Json: string(raw)}, nil
}

// CreateQr creates a QR payment. EXACTLY ONE outbound attempt; never retried.
// The idempotency_key is preserved verbatim (GraphQL idempotencyKey argument).
func (t *Transport) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("CreateQr", "nil request")
	}
	if req.IdempotencyKey == "" {
		return nil, invalidArg("CreateQr", "idempotency_key is required and must be preserved verbatim")
	}
	input := map[string]interface{}{
		"idCuenta":           idString(req.IdCuenta),
		"monto":              req.Monto,
		"concepto":           req.Concepto,
		"referenciaNumerica": req.ReferenciaNumerica,
		"nombreCliente":      req.NombreCliente,
		"email":              req.Email,
		"tipoPago":           req.TipoPago,
		"vigencia":           req.Vigencia,
	}
	resp, body, sent, netErr := t.call(ctx, opCreateQr, mutationCreateQr, map[string]interface{}{
		"input":          input,
		"idempotencyKey": req.IdempotencyKey,
	})
	if netErr != nil {
		return nil, netErrToOp("CreateQr", netErr, true, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("CreateQr", resp, body, true)
	}
	raw, ge := parseResponse(opCreateQr, body)
	if ge != nil {
		return nil, t.mapErr("CreateQr", *ge, true, true)
	}
	if len(raw) == 0 {
		return nil, sdkerrors.MapCreateError(status.Error(codes.Unknown, "empty GraphQL create response"), "CreateQr", true)
	}
	return &v1.JsonResponse{Json: string(raw)}, nil
}

// CreateTelefonico creates a telefonico payment. EXACTLY ONE outbound attempt;
// never retried; idempotency_key preserved verbatim.
func (t *Transport) CreateTelefonico(ctx context.Context, req *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("CreateTelefonico", "nil request")
	}
	if req.IdempotencyKey == "" {
		return nil, invalidArg("CreateTelefonico", "idempotency_key is required and must be preserved verbatim")
	}
	var celular interface{}
	if req.NumeroCelular != "" {
		celular = req.NumeroCelular
	}
	input := map[string]interface{}{
		"key":                req.Key,
		"monto":              req.Monto,
		"concepto":           req.Concepto,
		"referenciaNumerica": req.ReferenciaNumerica,
		"numeroCelular":      celular,
		"vigencia":           req.Vigencia,
	}
	resp, body, sent, netErr := t.call(ctx, opCreateTel, mutationCreateTel, map[string]interface{}{
		"input":          input,
		"idempotencyKey": req.IdempotencyKey,
	})
	if netErr != nil {
		return nil, netErrToOp("CreateTelefonico", netErr, true, sent)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, t.errorFromHTTP("CreateTelefonico", resp, body, true)
	}
	raw, ge := parseResponse(opCreateTel, body)
	if ge != nil {
		return nil, t.mapErr("CreateTelefonico", *ge, true, true)
	}
	if len(raw) == 0 {
		return nil, sdkerrors.MapCreateError(status.Error(codes.Unknown, "empty GraphQL create response"), "CreateTelefonico", true)
	}
	return &v1.JsonResponse{Json: string(raw)}, nil
}
