// Package rest implements the REST/JSON peer adapter for the TUPAGO3 Go SDK.
// It is a structural peer of the gRPC adapter: every capability maps to a
// backend3 REST route (discovered from the authoritative backend3 source), uses
// the standard library net/http + encoding/json, propagates context deadlines,
// injects the Bearer JWT from the existing auth.TokenProvider, enforces the same
// int64 identity law, exactly-once create, idempotency, read-retry classification
// and UnknownOutcome / PendingReconciliation semantics as the gRPC transport.
//
// No third-party HTTP dependency is used; the transport is idiomatic Go.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client/internal/transportutil"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Routes are the REST paths for each capability. All relative to BaseURL. The
// defaults are derived from backend3 (src/main/java/click/tupago/web/rest).
type Routes struct {
	CreateQr            string // POST
	CreateTelefonico    string // POST
	GetQrStatus         string // POST
	GetTelefonicoStatus string // POST
	GetCliente          string // GET (appended with the numeric id)
	GetCatalogo         string // GET (appended with the URL-escaped clave)
}

// DefaultRoutes returns the backend3-derived default route table.
func DefaultRoutes() Routes {
	return Routes{
		CreateQr:            "/api/payments/msjpagoqrusuario",
		CreateTelefonico:    "/api/payments/msjpagotelefonicousuario",
		GetQrStatus:         "/api/payments/estatusmsjqr",
		GetTelefonicoStatus: "/api/payments/estatusmsjcobrotelefonico",
		GetCliente:          "/api/clientes/",
		GetCatalogo:         "/api/catalogo-institucions/clave/",
	}
}

// Options configures the REST transport.
//
// The HTTP client is ALWAYS built by the SDK from the supplied TLS/Insecure
// configuration. A caller-supplied *http.Client is deliberately NOT accepted: an
// arbitrary client could carry InsecureSkipVerify, a redirect-following policy, a
// custom RoundTripper, or proxy to an unrelated endpoint, all of which would
// bypass the SDK-authoritative TLS, redirect and send-tracking controls. This is a
// fail-closed posture (P0-HTTP-03).
type Options struct {
	BaseURL string
	Routes  *Routes

	// TLS, when non-nil, provides the verified TLS configuration (fail-closed;
	// server certificate verification can never be disabled). Insecure is only
	// honoured for loopback targets by the caller (client.NewClient).
	TLS *security.TLSConfig
	// Insecure selects plaintext HTTP (loopback-only, enforced by client.NewClient).
	Insecure bool
	// Credentials supplies the per-request Bearer JWT (never logged).
	Credentials auth.TokenProvider
}

// Transport is the REST/JSON implementation of the SDK's PaymentService
// capabilities. It satisfies the client.Transport interface structurally.
type Transport struct {
	base   string
	routes Routes
	creds  auth.TokenProvider
	hc     *http.Client
}

// NewTransport builds a REST Transport. The *http.Client is ALWAYS constructed by
// the SDK from the TLS/Insecure configuration with a fail-closed redirect policy
// (no automatic following) so the SDK stays authoritative for destination, TLS and
// financial send tracking (P0-HTTP-02/03). The scheme/TLS authority law
// (P0-HTTP-04) is enforced HERE so a direct caller of rest.NewTransport cannot
// bypass the security gate that client.NewClient also applies.
func NewTransport(o *Options) (*Transport, error) {
	if o == nil {
		return nil, sdkerrors.NewConfigError("REST", "nil options")
	}
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		return nil, sdkerrors.NewConfigError("REST", "BaseURL is required")
	}
	// Scheme/TLS authority law. Security is derived from the ACTUAL URL scheme+host,
	// never from cfg.TLS alone (P0-HTTP-04). Defense in depth with client.NewClient.
	if err := transportutil.ValidateSchemeTLS(base, o.TLS, o.Insecure); err != nil {
		return nil, sdkerrors.NewConfigError("REST", err.Error())
	}
	routes := DefaultRoutes()
	if o.Routes != nil {
		if o.Routes.CreateQr != "" {
			routes.CreateQr = o.Routes.CreateQr
		}
		if o.Routes.CreateTelefonico != "" {
			routes.CreateTelefonico = o.Routes.CreateTelefonico
		}
		if o.Routes.GetQrStatus != "" {
			routes.GetQrStatus = o.Routes.GetQrStatus
		}
		if o.Routes.GetTelefonicoStatus != "" {
			routes.GetTelefonicoStatus = o.Routes.GetTelefonicoStatus
		}
		if o.Routes.GetCliente != "" {
			routes.GetCliente = o.Routes.GetCliente
		}
		if o.Routes.GetCatalogo != "" {
			routes.GetCatalogo = o.Routes.GetCatalogo
		}
	}

	tr := &http.Transport{}
	// Defensive ownership: clone the caller-supplied TLS config so later mutation of
	// the original *tls.Config cannot downgrade the already-constructed transport.
	if cloned := transportutil.CloneTLSConfig(o.TLS); cloned != nil {
		tr.TLSClientConfig = cloned
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		// Fail-closed: never automatically follow redirects. A 3xx is returned to
		// the caller as a non-success response without issuing a second request
		// (preserves single financial dispatch; no bearer/idempotency leakage).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Transport{base: base, routes: routes, creds: o.Credentials, hc: hc}, nil
}

// ---- request / response helpers ----

func (t *Transport) newReq(ctx context.Context, method, path, idempotencyKey string, body []byte) (*http.Request, error) {
	u := t.base + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
		// P0-HTTP-07: a financial CREATE must not be transparently replayed by the
		// standard net/http Transport. Because the body is built from a *bytes.Reader,
		// http.NewRequestWithContext auto-populates req.GetBody; combined with the
		// Idempotency-Key header, net/http classifies the POST as replayable and may
		// silently resend it on a reused connection that fails after the first write
		// (a transparent retry beneath our no-retry policy). Nulling GetBody makes the
		// request non-replayable while preserving the body, Content-Length, the
		// Idempotency-Key header and the Authorization header. Reads (idempotencyKey=="")
		// are intentionally left replayable so SDK-level read retries keep working.
		req.GetBody = nil
	}
	if t.creds == nil {
		return nil, sdkerrors.NewConfigError("Credentials", "a TokenProvider is required (fail-closed)")
	}
	tok, e := t.creds.Token(ctx)
	if e != nil {
		return nil, sdkerrors.NewConfigError("Credentials", "token provider error: "+e.Error())
	}
	if tok == "" {
		return nil, sdkerrors.NewConfigError("Credentials", "empty bearer token (fail-closed)")
	}
	// Token is never written to any log.
	req.Header.Set("Authorization", "Bearer "+tok)
	return req, nil
}

// sentTracker provides authoritative HTTP send tracking: it records whether the
// request bytes were actually written to the wire (via httptrace.WroteRequest),
// independent of the Go error returned by http.Client.Do. This is the HTTP analogue
// of the gRPC rpcstats send tracker and is required to correctly classify financial
// create outcomes (P0-HTTP-01). If the request was written (or we cannot prove it
// was not), the conservative financial rule applies: any subsequent failure is an
// UnknownOutcome (reconcile), NEVER request-not-sent.
type sentTracker struct {
	wroteRequest atomic.Bool
}

func (s *sentTracker) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { s.wroteRequest.Store(true) },
	}
}

func (s *sentTracker) wrote() bool { return s.wroteRequest.Load() }

// do executes a request. It returns the response, the response body bytes, a
// network error (nil on an HTTP-level response), a body-read error (nil when the
// full body was read), and whether the request bytes were placed on the wire
// (authoritative, via httptrace), used for the UnknownOutcome vs request-not-sent
// classification.
func (t *Transport) do(ctx context.Context, method, path, idempotencyKey string, body []byte) (*http.Response, []byte, error, error, bool) {
	req, err := t.newReq(ctx, method, path, idempotencyKey, body)
	if err != nil {
		return nil, nil, err, nil, false
	}
	var sent sentTracker
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), sent.trace()))
	resp, netErr := t.hc.Do(req)
	if netErr != nil {
		// A generic network error (EOF, connection reset, broken pipe, server closed
		// after reading the request) may occur AFTER the POST bytes reached the
		// server, which may have accepted/reserved/submitted the payment. The only
		// safe classification is UnknownOutcome (sent). request-not-sent is reserved
		// for the objective pre-dispatch case where WroteRequest never fired.
		return nil, nil, netErr, nil, sent.wrote()
	}
	defer resp.Body.Close()
	rb, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		// Headers were received but the body could not be completely read (truncated
		// chunked response, unexpected EOF, connection reset mid-body). The server may
		// already have processed a financial create, so the outcome is not safely
		// known. The caller must treat this as UnknownOutcome (create) or a transient
		// read failure (reads). (P0-HTTP-06)
		return resp, nil, nil, readErr, sent.wrote()
	}
	return resp, rb, nil, nil, sent.wrote()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
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
		// process a payment. This is a definite, non-retryable client policy outcome,
		// not an ambiguous financial UnknownOutcome, and must not trigger a resend.
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

func (t *Transport) readError(op string, resp *http.Response, body []byte) error {
	code := httpStatusToCode(resp.StatusCode)
	msg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	if code == codes.OK {
		return nil
	}
	se := status.Error(code, msg)
	if code == codes.Aborted {
		se = status.Error(codes.Aborted, sdkerrors.PendingReconciliationMarker+": "+msg)
	}
	return sdkerrors.MapRPCError(se, op)
}

func (t *Transport) createError(op string, resp *http.Response, body []byte, sent bool) error {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// The create POST reached the origin; a 3xx does NOT prove the origin performed
		// no financial effect before returning the redirect. Fail closed to
		// UnknownOutcome (reconcile). No auto-follow, no auto-resend. (P0-HTTP-04/13)
		msg := fmt.Sprintf("HTTP %d: create received redirect (no-follow), outcome indeterminate: %s",
			resp.StatusCode, truncate(string(body), 200))
		return sdkerrors.MapCreateError(status.Error(codes.Unknown, msg), op, true)
	}
	code := httpStatusToCode(resp.StatusCode)
	msg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	se := status.Error(code, msg)
	if code == codes.Aborted {
		se = status.Error(codes.Aborted, sdkerrors.PendingReconciliationMarker+": "+msg)
	}
	return sdkerrors.MapCreateError(se, op, sent)
}

func (t *Transport) netReadError(op string, netErr error) error {
	return sdkerrors.MapRPCError(status.Error(codes.Unavailable, "tupago REST network error: "+netErr.Error()), op)
}

func (t *Transport) netCreateError(op string, netErr error, sent bool) error {
	return sdkerrors.MapCreateError(status.Error(codes.Unavailable, "tupago REST network error: "+netErr.Error()), op, sent)
}

// ---- request/response DTOs (int64 law via i64) ----

type qrCreateBody struct {
	IDCuenta           i64     `json:"idCuenta"`
	Monto              float64 `json:"monto"`
	Concepto           string  `json:"concepto"`
	ReferenciaNumerica int32   `json:"referenciaNumerica"`
	NombreCliente      string  `json:"nombreCliente"`
	Email              string  `json:"email"`
	TipoPago           int32   `json:"tipoPago"`
	Vigencia           int32   `json:"vigencia"`
}

type telCreateBody struct {
	Key                string  `json:"key"`
	Monto              float64 `json:"monto"`
	Concepto           string  `json:"concepto"`
	ReferenciaNumerica int32   `json:"referenciaNumerica"`
	NumeroCelular      i64     `json:"numeroCelular"`
	Vigencia           int32   `json:"vigencia"`
}

type qrStatusBody struct {
	Dv          string `json:"dv,omitempty"`
	Idc         string `json:"idc,omitempty"`
	Certificado string `json:"certificado,omitempty"`
	Tpg1        int32  `json:"tpg1,omitempty"`
	Npg1        int32  `json:"npg1,omitempty"`
	IDCuenta    i64    `json:"idCuenta"`
}

type telStatusBody struct {
	IDCuenta     i64    `json:"idCuenta"`
	IDMsjdeCobro string `json:"idMsjdeCobro"`
}

type clienteDTO struct {
	ID               i64    `json:"id"`
	Key              string `json:"key"`
	Nombre           string `json:"nombre"`
	ClaveInstitucion string `json:"claveInstitucion"`
}

type catalogoDTO struct {
	ID               i64    `json:"id"`
	ClaveInstitucion string `json:"claveInstitucion"`
	NombreCorto      string `json:"nombreCorto"`
}

// extractQRPayload returns the raw Banxico payload from the QR create response.
// backend3 wraps the service result as {"mensaje": <result>, "emisor", "banco"};
// gRPC returns the raw result, so we extract "mensaje" to preserve parity. If the
// wrapper is absent, the whole body is treated as the payload.
func extractQRPayload(b []byte) string {
	var wrap struct {
		Mensaje json.RawMessage `json:"mensaje"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && len(wrap.Mensaje) > 0 && string(wrap.Mensaje) != "null" {
		return string(wrap.Mensaje)
	}
	return string(b)
}

func invalidArg(op, msg string) error { return sdkerrors.NewInvalidArgument(op, msg) }

// ---- Transport interface implementation ----

// GetCliente fetches the owned client profile and composes the institution
// catalog (mirroring the gRPC getOwnedClienteWithInstitucion composition).
func (t *Transport) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if req == nil {
		return nil, invalidArg("GetCliente", "nil request")
	}
	cd, err := t.getClienteDTO(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	cat, err := t.getCatalogoByClave(ctx, cd.ClaveInstitucion)
	if err != nil {
		return nil, err
	}
	return &v1.ClientePerfil{
		Cliente: &v1.Cliente{
			Id:               int64(cd.ID),
			Nombre:           cd.Nombre,
			ClaveInstitucion: cd.ClaveInstitucion,
			Key:              cd.Key,
		},
		CatalogoInstitucion: cat,
	}, nil
}

func (t *Transport) getClienteDTO(ctx context.Context, id int64) (*clienteDTO, error) {
	path := t.routes.GetCliente + strconv.FormatInt(id, 10)
	resp, body, netErr, readErr, _ := t.do(ctx, http.MethodGet, path, "", nil)
	if netErr != nil {
		return nil, t.netReadError("GetCliente", netErr)
	}
	if readErr != nil {
		return nil, t.netReadError("GetCliente", readErr)
	}
	if e := t.readError("GetCliente", resp, body); e != nil {
		return nil, e
	}
	var dto clienteDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, t.readErrorFromStatus("GetCliente", codes.InvalidArgument, "malformed cliente JSON: "+err.Error())
	}
	if dto.ID == 0 {
		return nil, t.readErrorFromStatus("GetCliente", codes.Internal, "cliente response missing mandatory id")
	}
	return &dto, nil
}

// GetCatalogo fetches the institution catalog by Banxico clave.
func (t *Transport) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	if req == nil {
		return nil, invalidArg("GetCatalogo", "nil request")
	}
	if req.ClaveInstitucion == "" {
		return nil, invalidArg("GetCatalogo", "clave_institucion is required")
	}
	return t.getCatalogoByClave(ctx, req.ClaveInstitucion)
}

func (t *Transport) getCatalogoByClave(ctx context.Context, clave string) (*v1.CatalogoInstitucion, error) {
	path := t.routes.GetCatalogo + url.PathEscape(clave)
	resp, body, netErr, readErr, _ := t.do(ctx, http.MethodGet, path, "", nil)
	if netErr != nil {
		return nil, t.netReadError("GetCatalogo", netErr)
	}
	if readErr != nil {
		return nil, t.netReadError("GetCatalogo", readErr)
	}
	if e := t.readError("GetCatalogo", resp, body); e != nil {
		return nil, e
	}
	var dto catalogoDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, t.readErrorFromStatus("GetCatalogo", codes.InvalidArgument, "malformed catalogo JSON: "+err.Error())
	}
	if dto.ID == 0 || dto.ClaveInstitucion == "" {
		return nil, t.readErrorFromStatus("GetCatalogo", codes.Internal, "catalogo response missing mandatory id or clave")
	}
	return &v1.CatalogoInstitucion{
		Id:               int64(dto.ID),
		ClaveInstitucion: dto.ClaveInstitucion,
		NombreCorto:      dto.NombreCorto,
	}, nil
}

func (t *Transport) readErrorFromStatus(op string, code codes.Code, msg string) error {
	se := status.Error(code, msg)
	if code == codes.Aborted {
		se = status.Error(codes.Aborted, sdkerrors.PendingReconciliationMarker+": "+msg)
	}
	return sdkerrors.MapRPCError(se, op)
}

// GetQrStatus returns the raw Banxico QR status payload.
func (t *Transport) GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("GetQrStatus", "nil request")
	}
	body, _ := json.Marshal(qrStatusBody{Idc: req.Idc, IDCuenta: i64(req.IdCuenta)})
	resp, rb, netErr, readErr, _ := t.do(ctx, http.MethodPost, t.routes.GetQrStatus, "", body)
	if netErr != nil {
		return nil, t.netReadError("GetQrStatus", netErr)
	}
	if readErr != nil {
		return nil, t.netReadError("GetQrStatus", readErr)
	}
	if e := t.readError("GetQrStatus", resp, rb); e != nil {
		return nil, e
	}
	return &v1.JsonResponse{Json: string(rb)}, nil
}

// GetTelefonicoStatus returns the raw Banxico telefonico status payload.
func (t *Transport) GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("GetTelefonicoStatus", "nil request")
	}
	body, _ := json.Marshal(telStatusBody{IDCuenta: i64(req.IdCuenta), IDMsjdeCobro: req.Idc})
	resp, rb, netErr, readErr, _ := t.do(ctx, http.MethodPost, t.routes.GetTelefonicoStatus, "", body)
	if netErr != nil {
		return nil, t.netReadError("GetTelefonicoStatus", netErr)
	}
	if readErr != nil {
		return nil, t.netReadError("GetTelefonicoStatus", readErr)
	}
	if e := t.readError("GetTelefonicoStatus", resp, rb); e != nil {
		return nil, e
	}
	return &v1.JsonResponse{Json: string(rb)}, nil
}

// CreateQr creates a QR payment. EXACTLY ONE outbound attempt; never retried.
// The idempotency_key is preserved verbatim in the Idempotency-Key header.
func (t *Transport) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	if req == nil {
		return nil, invalidArg("CreateQr", "nil request")
	}
	if req.IdempotencyKey == "" {
		return nil, invalidArg("CreateQr", "idempotency_key is required and must be preserved verbatim")
	}
	body, _ := json.Marshal(qrCreateBody{
		IDCuenta:           i64(req.IdCuenta),
		Monto:              req.Monto,
		Concepto:           req.Concepto,
		ReferenciaNumerica: req.ReferenciaNumerica,
		NombreCliente:      req.NombreCliente,
		Email:              req.Email,
		TipoPago:           req.TipoPago,
		Vigencia:           req.Vigencia,
	})
	resp, rb, netErr, readErr, sent := t.do(ctx, http.MethodPost, t.routes.CreateQr, req.IdempotencyKey, body)
	if netErr != nil {
		return nil, t.netCreateError("CreateQr", netErr, sent)
	}
	if readErr != nil {
		// Request was placed on the wire but the response body could not be read
		// completely: the financial outcome is not safely known. UnknownOutcome.
		return nil, t.netCreateError("CreateQr", readErr, sent)
	}
	if e := t.createError("CreateQr", resp, rb, true); e != nil {
		return nil, e
	}
	return &v1.JsonResponse{Json: extractQRPayload(rb)}, nil
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
	var num i64
	if req.NumeroCelular != "" {
		n, err := strconv.ParseInt(req.NumeroCelular, 10, 64)
		if err != nil {
			return nil, invalidArg("CreateTelefonico", "numero_celular must be a numeric value: "+err.Error())
		}
		num = i64(n)
	}
	body, _ := json.Marshal(telCreateBody{
		Key:                req.Key,
		Monto:              req.Monto,
		Concepto:           req.Concepto,
		ReferenciaNumerica: req.ReferenciaNumerica,
		NumeroCelular:      num,
		Vigencia:           req.Vigencia,
	})
	resp, rb, netErr, readErr, sent := t.do(ctx, http.MethodPost, t.routes.CreateTelefonico, req.IdempotencyKey, body)
	if netErr != nil {
		return nil, t.netCreateError("CreateTelefonico", netErr, sent)
	}
	if readErr != nil {
		return nil, t.netCreateError("CreateTelefonico", readErr, sent)
	}
	if e := t.createError("CreateTelefonico", resp, rb, true); e != nil {
		return nil, e
	}
	return &v1.JsonResponse{Json: string(rb)}, nil
}
