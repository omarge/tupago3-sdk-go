// Package transport provides REST and GraphQL implementations for the TUPAGO3 Go SDK.
// Routes verified against backend3 anchor bbf06c02.
// Creates are single-attempt / no-blind-retry.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RestPaymentTransport implements the six canonical capabilities over HTTP/REST.
type RestPaymentTransport struct {
	BaseURL       string
	HTTPClient    *http.Client
	TokenProvider func(context.Context) (string, error)
}

func NewRestPaymentTransport(baseURL string, tokenProvider func(context.Context) (string, error)) *RestPaymentTransport {
	return &RestPaymentTransport{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		TokenProvider: tokenProvider,
	}
}

func (r *RestPaymentTransport) do(ctx context.Context, method, path string, body any, idempotencyKey string) ([]byte, error) {
	reqBody := []byte(nil)
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, r.BaseURL+path, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if r.TokenProvider != nil {
		token, err := r.TokenProvider(ctx)
		if err != nil {
			return nil, err
		}
		if token == "" {
			return nil, fmt.Errorf("token provider returned a blank token")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("REST %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// CreateQr posts to /api/payments/msjpagoqrusuario and unwraps "mensaje".
func (r *RestPaymentTransport) CreateQr(ctx context.Context, idCuenta int64, monto float64, concepto string, idempotencyKey string) ([]byte, error) {
	body := map[string]any{
		"idCuenta": idCuenta,
		"monto":    monto,
		"concepto": concepto,
	}
	raw, err := r.do(ctx, http.MethodPost, "/api/payments/msjpagoqrusuario", body, idempotencyKey)
	if err != nil {
		return nil, err
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return raw, nil
	}
	if msg, ok := wrapper["mensaje"]; ok {
		return msg, nil
	}
	return raw, nil
}

// CreateTelefonico posts to /api/payments/msjpagotelefonico.
func (r *RestPaymentTransport) CreateTelefonico(ctx context.Context, key string, monto float64, concepto string, idempotencyKey string) ([]byte, error) {
	body := map[string]any{
		"key":      key,
		"monto":    monto,
		"concepto": concepto,
	}
	return r.do(ctx, http.MethodPost, "/api/payments/msjpagotelefonico", body, idempotencyKey)
}

// GetQrStatus posts to /api/payments/estatusmsjqr (ByCuenta).
func (r *RestPaymentTransport) GetQrStatus(ctx context.Context, idc string, idCuenta int64) ([]byte, error) {
	body := map[string]any{"idc": idc, "idCuenta": idCuenta}
	return r.do(ctx, http.MethodPost, "/api/payments/estatusmsjqr", body, "")
}
