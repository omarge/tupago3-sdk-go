package graphql_test

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
	"github.com/omarge/tupago3-sdk-go/client/graphql"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
	"github.com/stretchr/testify/require"
)

// graphqlRawResetServer mirrors the REST raw reset server: reads the COMPLETE HTTP
// request then closes without responding, simulating a server that accepted the
// payment but whose response was lost.
func graphqlRawResetServer(t *testing.T) (string, *int32) {
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
				c.Close() // close WITHOUT a valid HTTP response
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), &received
}

func graphqlClientOn(t *testing.T, baseURL string) *client.PaymentClient {
	t.Helper()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      baseURL,
		Insecure:    true,
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: baseURL},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// P0-HTTP-01: generic connection error AFTER the POST bytes reached the server must
// be UnknownOutcome, never request-not-sent. Server receives exactly one request.
func TestGraphQL_CreateQr_PostSendReset_UnknownOutcome(t *testing.T) {
	url, received := graphqlRawResetServer(t)
	c := graphqlClientOn(t, url)

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err), "post-send failure must NOT be request-not-sent")
	require.Equal(t, int32(1), atomic.LoadInt32(received), "server must receive exactly one POST; SDK must not resubmit")
}

func TestGraphQL_CreateTelefonico_PostSendReset_UnknownOutcome(t *testing.T) {
	url, received := graphqlRawResetServer(t)
	c := graphqlClientOn(t, url)

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err))
	require.Equal(t, int32(1), atomic.LoadInt32(received), "server must receive exactly one POST; SDK must not resubmit")
}

// P0-HTTP-02: SDK must NOT follow redirects. Origin hit once; redirect target
// receives ZERO requests (no Bearer / idempotency / variables leakage).
func TestGraphQL_CreateQr_Redirect_NoFollow(t *testing.T) {
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

			c := graphqlClientOn(t, origin.URL)
			_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-r"})
			require.Error(t, err)
			require.Equal(t, int32(1), atomic.LoadInt32(&originHits), "origin must be hit exactly once")
			require.Equal(t, int32(0), atomic.LoadInt32(&targetHits), "redirect target must receive ZERO requests")
			// CREATE + 3xx: the financial request already reached the origin, so its effect is
			// not contractually known -> fail closed to UnknownOutcome (not a definite error).
			require.True(t, sdkerrors.IsUnknownOutcome(err), "create 3xx must be UnknownOutcome (outcome indeterminate), got %v", err)
			require.False(t, sdkerrors.IsRequestNotSent(err), "redirect create must not be request-not-sent")
		})
	}
}

// P0-HTTP-02 (READ): reads must also refuse redirects without following.
func TestGraphQL_Read_Redirect_NoFollow(t *testing.T) {
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

	c := graphqlClientOn(t, origin.URL)
	_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&originHits))
	require.Equal(t, int32(0), atomic.LoadInt32(&targetHits))
}

// P0-HTTP-01 (control): a genuinely pre-dispatch error (no credential) is NOT an
// UnknownOutcome.
func TestGraphQL_PreDispatch_NotUnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:    srv.URL,
		Insecure:  true,
		Transport: "graphql",
		GraphQL:   &client.GraphQLOptions{EndpointURL: srv.URL},
	})
	require.Error(t, err, "missing credential must fail before dispatch")
	require.False(t, sdkerrors.IsUnknownOutcome(err), "pre-dispatch error must not be UnknownOutcome")
}

// P0-HTTP-03: caller-supplied *http.Client can no longer bypass SDK-authoritative
// TLS. InsecureSkipVerify is rejected; non-loopback plaintext is rejected.
func TestGraphQL_TLS_Authority_NoBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Transport:   "graphql",
		TLS:         &security.TLSConfig{Config: &tls.Config{InsecureSkipVerify: true}},
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: srv.URL},
	})
	require.Error(t, err, "InsecureSkipVerify must be rejected (SDK-authoritative TLS)")

	_, err = client.NewClient(context.Background(), &client.Config{
		Target:      "pay.tupago.mx:443",
		Insecure:    true,
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: "http://pay.tupago.mx"},
	})
	require.Error(t, err, "non-loopback plaintext must be rejected")
}

// P0-HTTP-04: SCHEME/TLS AUTHORITY LAW via the direct public constructor. No caller
// invoking graphql.NewTransport directly may bypass the scheme/TLS gate.
func graphqlValidTLS(t *testing.T) *security.TLSConfig {
	t.Helper()
	c, err := security.NewTLSConfig()
	require.NoError(t, err)
	return c
}

func graphqlSkipVerifyTLS(t *testing.T) *security.TLSConfig {
	t.Helper()
	c, err := security.NewTLSConfig()
	require.NoError(t, err)
	c.Config.InsecureSkipVerify = true
	return c
}

func TestGraphQL_SchemeTLS_Matrix_Direct(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		tls      *security.TLSConfig
		insecure bool
		wantErr  bool
	}{
		{"remote https + tls", "https://pay.tupago.mx", graphqlValidTLS(t), false, false},
		{"remote http + tls", "http://pay.tupago.mx", graphqlValidTLS(t), false, true},
		{"remote http + no tls", "http://pay.tupago.mx", nil, false, true},
		{"remote http + insecure", "http://pay.tupago.mx", nil, true, true},
		{"unsupported scheme", "ftp://pay.tupago.mx", graphqlValidTLS(t), false, true},
		{"loopback http + insecure", "http://127.0.0.1:8080", nil, true, false},
		{"loopback http + no insecure", "http://127.0.0.1:8080", nil, false, true},
		{"loopback https + tls", "https://localhost:8080", graphqlValidTLS(t), false, false},
		{"insecureskipverify", "https://pay.tupago.mx", graphqlSkipVerifyTLS(t), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := graphql.NewTransport(&graphql.Options{
				BaseURL:     tc.baseURL,
				TLS:         tc.tls,
				Insecure:    tc.insecure,
				Credentials: auth.StaticTokenProvider("tok"),
			})
			if tc.wantErr {
				require.Error(t, err, "expected rejection for %s", tc.baseURL)
			} else {
				require.NoError(t, err, "expected allowance for %s", tc.baseURL)
			}
		})
	}
}

// P0-HTTP-04: same scheme/TLS law enforced through client.NewClient (defense in depth).
func TestGraphQL_SchemeTLS_Matrix_Client(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		tls      *security.TLSConfig
		insecure bool
		wantErr  bool
	}{
		{"remote https + tls", "https://pay.tupago.mx", graphqlValidTLS(t), false, false},
		{"remote http + tls", "http://pay.tupago.mx", graphqlValidTLS(t), false, true},
		{"remote http + no tls", "http://pay.tupago.mx", nil, false, true},
		{"remote http + insecure", "http://pay.tupago.mx", nil, true, true},
		{"unsupported scheme", "ftp://pay.tupago.mx", graphqlValidTLS(t), false, true},
		{"loopback http + insecure", "http://127.0.0.1:8080", nil, true, false},
		{"loopback http + no insecure", "http://127.0.0.1:8080", nil, false, true},
		{"loopback https + tls", "https://localhost:8080", graphqlValidTLS(t), false, false},
		{"insecureskipverify", "https://pay.tupago.mx", graphqlSkipVerifyTLS(t), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.NewClient(context.Background(), &client.Config{
				Target:      tc.baseURL,
				Transport:   "graphql",
				TLS:         tc.tls,
				Insecure:    tc.insecure,
				Credentials: auth.StaticTokenProvider("tok"),
				GraphQL:     &client.GraphQLOptions{EndpointURL: tc.baseURL},
			})
			if tc.wantErr {
				require.Error(t, err, "expected rejection for %s", tc.baseURL)
			} else {
				require.NoError(t, err, "expected allowance for %s", tc.baseURL)
			}
		})
	}
}

// P0-HTTP-05 (§5): the SDK-owned TLS config is a CLONE of the caller's; mutating the
// original after construction must NOT affect the already-built transport.
func TestGraphQL_TLSConfig_CloneImmutable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tlsCfg := graphqlValidTLS(t) // no CA -> server self-signed cert remains untrusted
	tr, err := graphql.NewTransport(&graphql.Options{
		BaseURL:     srv.URL,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)

	_, errBefore := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, errBefore, "request must fail TLS verification before mutation")
	require.Contains(t, strings.ToLower(errBefore.Error()), "certificate",
		"verification failure must be the cause")

	// Mutate the CALLER-OWNED original after construction.
	tlsCfg.Config.InsecureSkipVerify = true

	// The already-constructed transport holds a clone, so it stays unaffected.
	_, errAfter := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, errAfter, "SDK transport must remain unaffected by caller TLS mutation")
	require.Contains(t, strings.ToLower(errAfter.Error()), "certificate",
		"verification failure must persist despite caller mutation")
}

// P0-HTTP-06: a truncated HTTP response body on a CREATE must be UnknownOutcome, never a
// successful/partial JsonResponse and never request-not-sent. Exactly one POST occurs.
func graphqlTruncatedServer(t *testing.T, status int, prefix string, recv *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(recv, 1)
		w.Header().Set("Content-Length", "100") // promise more than we send
		w.WriteHeader(status)
		_, _ = w.Write([]byte(prefix)) // truncated body
	}))
}

func TestGraphQL_CreateQr_TruncatedBody_UnknownOutcome(t *testing.T) {
	var recv int32
	srv := graphqlTruncatedServer(t, http.StatusOK, `{"data":{"createPagoQr":`, &recv)
	defer srv.Close()
	c := graphqlClientOn(t, srv.URL)

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "truncated create response must be UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err), "truncated create must not be request-not-sent")
	require.Equal(t, int32(1), atomic.LoadInt32(&recv), "exactly one POST")
}

func TestGraphQL_CreateTelefonico_TruncatedBody_UnknownOutcome(t *testing.T) {
	var recv int32
	srv := graphqlTruncatedServer(t, http.StatusOK, `{`, &recv)
	defer srv.Close()
	c := graphqlClientOn(t, srv.URL)

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "truncated create response must be UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err))
	require.Equal(t, int32(1), atomic.LoadInt32(&recv), "exactly one POST")
}

// P0-HTTP-06 (READ): a truncated response body on a READ is a transient transport
// failure, so the bounded retry policy applies and attempt count stays bounded.
func TestGraphQL_GetCatalogo_TruncatedBody_BoundedRetry(t *testing.T) {
	var recv int32
	srv := graphqlTruncatedServer(t, http.StatusOK, `{"data":{"catalogoInstitucion":`, &recv)
	defer srv.Close()
	c := graphqlClientOn(t, srv.URL)

	_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsRetryable(err), "truncated read must be a transient/retryable error, got %v", err)
	attempts := atomic.LoadInt32(&recv)
	require.GreaterOrEqual(t, attempts, int32(2), "body-read failure must trigger bounded retry")
	require.LessOrEqual(t, attempts, int32(4), "retry must be bounded (MaxAttempts=4)")
}
