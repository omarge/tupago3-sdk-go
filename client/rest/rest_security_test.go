package rest_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
	"github.com/stretchr/testify/require"
)

// restRawResetServer accepts a connection, reads the COMPLETE HTTP request
// (headers + body), increments an authoritative server-side receive counter, then
// closes/resets WITHOUT sending a valid HTTP response. This models a server that
// accepted/reserved/submitted the payment but whose response was lost.
func restRawResetServer(t *testing.T) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var received int32
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				s := string(buf[:n])
				cl := 0
				if i := strings.Index(s, "Content-Length:"); i >= 0 {
					line := s[i:]
					if j := strings.IndexByte(line, '\n'); j >= 0 {
						line = line[:j]
					}
					fmt.Sscanf(line, "Content-Length: %d", &cl)
				}
				he := strings.Index(s, "\r\n\r\n")
				if he < 0 {
					he = strings.Index(s, "\n\n")
					if he >= 0 {
						he += 2
					}
				} else {
					he += 4
				}
				got := 0
				if he >= 0 {
					got = n - he
				}
				for got < cl {
					m, e2 := c.Read(buf)
					if m > 0 {
						got += m
					}
					if e2 != nil {
						break
					}
				}
				atomic.AddInt32(&received, 1)
				// Deliberately close WITHOUT writing any HTTP response.
				c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), &received
}

func restClientOn(t *testing.T, baseURL string) *client.PaymentClient {
	t.Helper()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      baseURL,
		Insecure:    true,
		Transport:   "rest",
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: baseURL},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// P0-HTTP-01: a generic connection error AFTER the POST bytes reached the server
// MUST be classified as UnknownOutcome, never request-not-sent. Server received
// exactly one request and the SDK issues no second POST.
func TestREST_CreateQr_PostSendReset_UnknownOutcome(t *testing.T) {
	url, received := restRawResetServer(t)
	c := restClientOn(t, url)

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err), "post-send failure must NOT be request-not-sent")
	require.Equal(t, int32(1), atomic.LoadInt32(received), "server must receive exactly one POST; SDK must not resubmit")
}

func TestREST_CreateTelefonico_PostSendReset_UnknownOutcome(t *testing.T) {
	url, received := restRawResetServer(t)
	c := restClientOn(t, url)

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err))
	require.Equal(t, int32(1), atomic.LoadInt32(received), "server must receive exactly one POST; SDK must not resubmit")
}

// P0-HTTP-02: the SDK must NOT follow redirects. Origin is hit exactly once; the
// redirect target must receive ZERO requests and thus no Bearer / Idempotency-Key.
func TestREST_CreateQr_Redirect_NoFollow(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprintf("status-%d", code), func(t *testing.T) {
			var targetHits int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&targetHits, 1)
				t.Errorf("redirect target received a request: %s %s", r.Method, r.URL.Path)
			}))
			defer target.Close()

			var originHits int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&originHits, 1)
				w.Header().Set("Location", target.URL)
				w.WriteHeader(code)
			}))
			defer origin.Close()

			c := restClientOn(t, origin.URL)
			_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-r"})
			require.Error(t, err)
			require.Equal(t, int32(1), atomic.LoadInt32(&originHits), "origin must be hit exactly once")
			require.Equal(t, int32(0), atomic.LoadInt32(&targetHits), "redirect target must receive ZERO requests (no second POST)")
			require.False(t, sdkerrors.IsUnknownOutcome(err), "redirect refusal is definite, not UnknownOutcome")
		})
	}
}

// P0-HTTP-02 (READ): reads must also refuse redirects without following.
func TestREST_Read_Redirect_NoFollow(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		t.Errorf("redirect target received a read request")
	}))
	defer target.Close()
	var originHits int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&originHits, 1)
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := restClientOn(t, origin.URL)
	_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&originHits))
	require.Equal(t, int32(0), atomic.LoadInt32(&targetHits))
}

// P0-HTTP-01 (control): a genuinely pre-dispatch error (no credential) is NOT an
// UnknownOutcome and is provably before any wire write. Missing credentials are
// rejected at config validation, before any connection is opened.
func TestREST_PreDispatch_NotUnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:    srv.URL,
		Insecure:  true,
		Transport: "rest",
		REST:      &client.RESTOptions{BaseURL: srv.URL},
	})
	require.Error(t, err, "missing credential must fail before dispatch")
	require.False(t, sdkerrors.IsUnknownOutcome(err), "pre-dispatch error must not be UnknownOutcome")
}

// P0-HTTP-03: an arbitrary caller-supplied *http.Client can no longer bypass
// SDK-authoritative TLS. The public RESTOptions no longer exposes HTTPClient, and
// an InsecureSkipVerify TLS config is rejected at construction (fail-closed).
func TestREST_TLS_Authority_NoBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// InsecureSkipVerify must be rejected even when explicitly supplied via cfg.TLS.
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Transport:   "rest",
		TLS:         &security.TLSConfig{Config: &tls.Config{InsecureSkipVerify: true}},
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: srv.URL},
	})
	require.Error(t, err, "InsecureSkipVerify must be rejected (SDK-authoritative TLS)")

	// Non-loopback plaintext remains rejected.
	_, err = client.NewClient(context.Background(), &client.Config{
		Target:      "pay.tupago.mx:443",
		Insecure:    true,
		Transport:   "rest",
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: "http://pay.tupago.mx"},
	})
	require.Error(t, err, "non-loopback plaintext must be rejected")
}
