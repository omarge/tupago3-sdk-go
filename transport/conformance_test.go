package transport

import (
	"testing"
)

func TestRestTransportCanBeConstructed(t *testing.T) {
	r := NewRestPaymentTransport("http://127.0.0.1:8080", nil)
	if r == nil {
		t.Fatal("expected non-nil RestPaymentTransport")
	}
}

func TestGraphQlTransportCanBeConstructed(t *testing.T) {
	g := NewGraphQlPaymentTransport("http://127.0.0.1:8080", nil)
	if g == nil {
		t.Fatal("expected non-nil GraphQlPaymentTransport")
	}
}

func TestRestHasCanonicalMethods(t *testing.T) {
	r := NewRestPaymentTransport("http://127.0.0.1:8080", nil)
	// Compile-time presence check via method set.
	_ = r.CreateQr
	_ = r.CreateTelefonico
	_ = r.GetQrStatus
}
