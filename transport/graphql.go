// GraphQL transport for TUPAGO3 Go SDK.
// Operations verified against backend3 GraphQL controller (anchor bbf06c02):
// - pagoQrEstatusByCuenta / pagoTelefonicoEstatusByCuenta
// - createPagoQr / createPagoTelefonico
// Errors carry extensions.code.
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

// GraphQlPaymentTransport implements the six canonical capabilities over GraphQL.
type GraphQlPaymentTransport struct {
	BaseURL       string
	HTTPClient    *http.Client
	TokenProvider func(context.Context) (string, error)
}

func NewGraphQlPaymentTransport(baseURL string, tokenProvider func(context.Context) (string, error)) *GraphQlPaymentTransport {
	return &GraphQlPaymentTransport{
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

func (g *GraphQlPaymentTransport) execute(ctx context.Context, query string, variables map[string]any) ([]byte, error) {
	payload := map[string]any{"query": query, "variables": variables}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.BaseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if g.TokenProvider != nil {
		token, err := g.TokenProvider(ctx)
		if err != nil {
			return nil, err
		}
		if token == "" {
			return nil, fmt.Errorf("token provider returned a blank token")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GraphQL HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return respBody, nil
	}
	if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
		if first, ok := errs[0].(map[string]any); ok {
			code := "UNKNOWN"
			if ext, ok := first["extensions"].(map[string]any); ok {
				if c, ok := ext["code"].(string); ok {
					code = c
				}
			}
			return nil, fmt.Errorf("GraphQL %s: %v", code, first["message"])
		}
	}
	return respBody, nil
}

// GetQrStatus uses ByCuenta query.
func (g *GraphQlPaymentTransport) GetQrStatus(ctx context.Context, idc string, idCuenta int64) ([]byte, error) {
	query := `query($idc: String!, $idCuenta: ID!) { pagoQrEstatusByCuenta(idc: $idc, idCuenta: $idCuenta) }`
	return g.execute(ctx, query, map[string]any{"idc": idc, "idCuenta": fmt.Sprintf("%d", idCuenta)})
}

// CreateQr mutation.
func (g *GraphQlPaymentTransport) CreateQr(ctx context.Context, idCuenta int64, monto float64, concepto string, idempotencyKey string) ([]byte, error) {
	query := `mutation($input: PagoQrInput!, $key: String) { createPagoQr(input: $input, idempotencyKey: $key) }`
	variables := map[string]any{
		"input": map[string]any{
			"idCuenta": fmt.Sprintf("%d", idCuenta),
			"monto":    monto,
			"concepto": concepto,
		},
		"key": idempotencyKey,
	}
	return g.execute(ctx, query, variables)
}
