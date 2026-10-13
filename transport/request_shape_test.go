package transport

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRestCreateQr_RequestShape(t *testing.T) {
	var capturedPath string
	var capturedHeader string
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedHeader = r.Header.Get("Idempotency-Key")
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"mensaje":{"ok":true}}`))
	}))
	defer server.Close()

	r := NewRestPaymentTransport(server.URL, nil)
	_, err := r.CreateQr(context.Background(), 1, 100.0, "test", "key-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedPath != "/api/payments/msjpagoqrusuario" {
		t.Errorf("path = %s, want /api/payments/msjpagoqrusuario", capturedPath)
	}
	if capturedHeader != "key-123" {
		t.Errorf("Idempotency-Key = %s, want key-123", capturedHeader)
	}
	if !strings.Contains(capturedBody, "idCuenta") || !strings.Contains(capturedBody, "monto") {
		t.Errorf("body missing expected fields: %s", capturedBody)
	}
}

func TestRestGetQrStatus_RequestShape(t *testing.T) {
	var capturedPath string
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	r := NewRestPaymentTransport(server.URL, nil)
	_, err := r.GetQrStatus(context.Background(), "idc-1", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedPath != "/api/payments/estatusmsjqr" {
		t.Errorf("path = %s, want /api/payments/estatusmsjqr", capturedPath)
	}
	if !strings.Contains(capturedBody, "idc") || !strings.Contains(capturedBody, "idCuenta") {
		t.Errorf("body missing idc/idCuenta: %s", capturedBody)
	}
}

func TestGraphQlCreateQr_RequestShape(t *testing.T) {
	var capturedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Write([]byte(`{"data":{"createPagoQr":{}}}`))
	}))
	defer server.Close()

	g := NewGraphQlPaymentTransport(server.URL, nil)
	_, err := g.CreateQr(context.Background(), 1, 100.0, "test", "key-456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(capturedBody, "createPagoQr") {
		t.Errorf("body missing createPagoQr: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, "key-456") {
		t.Errorf("body missing idempotency key: %s", capturedBody)
	}
}
