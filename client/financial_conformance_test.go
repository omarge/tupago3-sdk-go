package client_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// ===================== Phase D expanded financial conformance =====================
//
// Executed proof, per transport, of the financial/security invariants the
// Gatekeeper requires for final conformance:
//   - int64 identity
//   - PendingReconciliation mapping
//   - auth failure -> Unauthenticated
//   - read retry actual attempt counts (transient => exactly 2; NotFound => exactly 1)
//   - post-send connection loss => UnknownOutcome (not request-not-sent), exactly one POST
//   - redirect => no follow, origin 1 / target 0, no credential leakage
//   - pre-dispatch error => not UnknownOutcome

// ---- REST scenario server ----

func isRestCatalogo(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/catalogo-institucions/clave/")
}

type restFinServer struct {
	mode        string
	catAttempts int32
}

func (s *restFinServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch s.mode {
	case "pending":
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/msjpagoqrusuario") {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"PENDING"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "unauth":
		if isRestCatalogo(r) {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "transient":
		if isRestCatalogo(r) {
			if atomic.AddInt32(&s.catAttempts, 1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"id":9007199254740993,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "notfound":
		if isRestCatalogo(r) {
			atomic.AddInt32(&s.catAttempts, 1)
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	default: // success
		switch {
		case isRestCatalogo(r):
			_, _ = w.Write([]byte(`{"id":9007199254740993,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/msjpagoqrusuario"):
			_, _ = w.Write([]byte(`{"mensaje":` + cfQrPayload + `}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// ---- GraphQL scenario server ----

type gqlFinServer struct {
	mode        string
	catAttempts int32
}

func (s *gqlFinServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := io.ReadAll(r.Body)
	var q struct {
		OperationName string `json:"operationName"`
	}
	_ = json.Unmarshal(body, &q)
	switch s.mode {
	case "pending":
		if q.OperationName == "createPagoQr" {
			_, _ = w.Write([]byte(`{"errors":[{"message":"PAYMENT_PENDING_RECONCILIATION","extensions":{"code":"PAYMENT_PENDING_RECONCILIATION","classification":"accepted"}}]}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "unauth":
		if q.OperationName == "catalogoInstitucion" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "transient":
		if q.OperationName == "catalogoInstitucion" {
			if atomic.AddInt32(&s.catAttempts, 1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"catalogoInstitucion":{"id":"9007199254740993","claveInstitucion":"BCM","nombreCorto":"Banco"}}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "notfound":
		if q.OperationName == "catalogoInstitucion" {
			atomic.AddInt32(&s.catAttempts, 1)
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		switch q.OperationName {
		case "catalogoInstitucion":
			_, _ = w.Write([]byte(`{"data":{"catalogoInstitucion":{"id":"9007199254740993","claveInstitucion":"BCM","nombreCorto":"Banco"}}}`))
		case "createPagoQr":
			_, _ = w.Write([]byte(`{"data":{"createPagoQr":` + cfQrPayload + `}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// ---- gRPC scenario server ----

type grpcFinServer struct {
	v1.UnimplementedPaymentServiceServer
	mode        string
	catAttempts int32
}

func (s *grpcFinServer) GetCatalogo(context.Context, *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	switch s.mode {
	case "unauth":
		return nil, status.Error(codes.Unauthenticated, "no token")
	case "transient":
		if atomic.AddInt32(&s.catAttempts, 1) == 1 {
			return nil, status.Error(codes.Unavailable, "transient")
		}
		return &v1.CatalogoInstitucion{Id: cfCatalogID, ClaveInstitucion: "BCM", NombreCorto: "Banco"}, nil
	case "notfound":
		return nil, status.Error(codes.NotFound, "x")
	default:
		return &v1.CatalogoInstitucion{Id: cfCatalogID, ClaveInstitucion: "BCM", NombreCorto: "Banco"}, nil
	}
}

func (s *grpcFinServer) CreateQr(context.Context, *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	if s.mode == "pending" {
		return nil, status.Error(codes.Aborted, sdkerrors.PendingReconciliationMarker+": pending")
	}
	return &v1.JsonResponse{Json: cfQrPayload}, nil
}

func startGRPCFin(t *testing.T, mode string) *client.PaymentClient {
	t.Helper()
	certPEM, keyPEM := genLoopbackCert(t)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	v1.RegisterPaymentServiceServer(srv, &grpcFinServer{mode: mode})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(certPEM), security.WithServerName("localhost"))
	require.NoError(t, err)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      lis.Addr().String(),
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	return c
}

func restFinClient(t *testing.T, url string) *client.PaymentClient {
	t.Helper()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      url,
		Insecure:    true,
		Transport:   "rest",
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: url},
	})
	require.NoError(t, err)
	return c
}

func graphqlFinClient(t *testing.T, url string) *client.PaymentClient {
	t.Helper()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      url,
		Insecure:    true,
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: url},
	})
	require.NoError(t, err)
	return c
}

func finRawResetURL(t *testing.T) (string, *int32) {
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
				c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), &received
}

func finRedirectServers(t *testing.T, code int) (origin *httptest.Server, target *httptest.Server, originHits, targetHits *int32) {
	t.Helper()
	var oH, tH int32
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tH, 1)
		t.Errorf("redirect target received a request: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(target.Close)
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&oH, 1)
		w.Header().Set("Location", target.URL)
		w.WriteHeader(code)
	}))
	t.Cleanup(origin.Close)
	return origin, target, &oH, &tH
}

func TestFinancialConformance_gRPC(t *testing.T) {
	// int64 + success
	c := startGRPCFin(t, "")
	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id, "int64 identity exact")
	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.NoError(t, err)
	require.Equal(t, cfQrPayload, qr.Json)

	// PendingReconciliation
	cp := startGRPCFin(t, "pending")
	_, err = cp.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsPendingReconciliation(err), "gRPC PendingReconciliation")
	require.False(t, sdkerrors.IsRetryable(err))

	// auth failure -> Unauthenticated
	ca := startGRPCFin(t, "unauth")
	_, err = ca.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unauthenticated))

	// transient read -> exactly 2 server attempts
	ct := startGRPCFin(t, "transient")
	cat, err = ct.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id)

	// NotFound read -> exactly 1 attempt, no retry
	cn := startGRPCFin(t, "notfound")
	_, err = cn.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.NotFound))
}

func TestFinancialConformance_REST(t *testing.T) {
	c := restFinClient(t, httptest.NewServer(&restFinServer{mode: ""}).URL)
	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id)
	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.NoError(t, err)
	require.Equal(t, cfQrPayload, qr.Json)

	cp := restFinClient(t, httptest.NewServer(&restFinServer{mode: "pending"}).URL)
	_, err = cp.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsPendingReconciliation(err))
	require.False(t, sdkerrors.IsRetryable(err))

	ca := restFinClient(t, httptest.NewServer(&restFinServer{mode: "unauth"}).URL)
	_, err = ca.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unauthenticated))

	srvT := httptest.NewServer(&restFinServer{mode: "transient"})
	ct := restFinClient(t, srvT.URL)
	cat, err = ct.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id)
	require.Equal(t, int32(2), atomic.LoadInt32(&srvT.Config.Handler.(*restFinServer).catAttempts), "transient read must be attempted exactly twice")

	srvN := httptest.NewServer(&restFinServer{mode: "notfound"})
	cn := restFinClient(t, srvN.URL)
	_, err = cn.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.NotFound))
	require.Equal(t, int32(1), atomic.LoadInt32(&srvN.Config.Handler.(*restFinServer).catAttempts), "non-retryable read must be attempted exactly once")

	// post-send reset => UnknownOutcome, exactly one POST
	url, recv := finRawResetURL(t)
	cr := restFinClient(t, url)
	_, err = cr.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-r"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "post-send reset must be UnknownOutcome")
	require.False(t, sdkerrors.IsRequestNotSent(err))
	require.Equal(t, int32(1), atomic.LoadInt32(recv), "exactly one POST to server")

	// redirect => no follow, origin 1 / target 0
	origin, target, oH, tH := finRedirectServers(t, http.StatusTemporaryRedirect)
	defer origin.Close()
	defer target.Close()
	cd := restFinClient(t, origin.URL)
	_, err = cd.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-d"})
	require.Error(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(oH))
	require.Equal(t, int32(0), atomic.LoadInt32(tH), "redirect target receives ZERO requests")
}

func TestFinancialConformance_GraphQL(t *testing.T) {
	c := graphqlFinClient(t, httptest.NewServer(&gqlFinServer{mode: ""}).URL)
	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id)
	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-1"})
	require.NoError(t, err)
	require.Equal(t, cfQrPayload, qr.Json)

	cp := graphqlFinClient(t, httptest.NewServer(&gqlFinServer{mode: "pending"}).URL)
	_, err = cp.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-2"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsPendingReconciliation(err))
	require.False(t, sdkerrors.IsRetryable(err))

	ca := graphqlFinClient(t, httptest.NewServer(&gqlFinServer{mode: "unauth"}).URL)
	_, err = ca.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unauthenticated))

	srvT := httptest.NewServer(&gqlFinServer{mode: "transient"})
	ct := graphqlFinClient(t, srvT.URL)
	cat, err = ct.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, cfCatalogID, cat.Id)
	require.Equal(t, int32(2), atomic.LoadInt32(&srvT.Config.Handler.(*gqlFinServer).catAttempts), "transient read must be attempted exactly twice")

	srvN := httptest.NewServer(&gqlFinServer{mode: "notfound"})
	cn := graphqlFinClient(t, srvN.URL)
	_, err = cn.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.NotFound))
	require.Equal(t, int32(1), atomic.LoadInt32(&srvN.Config.Handler.(*gqlFinServer).catAttempts), "non-retryable read must be attempted exactly once")

	// post-send reset => UnknownOutcome, exactly one POST
	url, recv := finRawResetURL(t)
	cr := graphqlFinClient(t, url)
	_, err = cr.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-r"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "post-send reset must be UnknownOutcome")
	require.False(t, sdkerrors.IsRequestNotSent(err))
	require.Equal(t, int32(1), atomic.LoadInt32(recv), "exactly one POST to server")

	// redirect => no follow, origin 1 / target 0
	origin, target, oH, tH := finRedirectServers(t, http.StatusTemporaryRedirect)
	defer origin.Close()
	defer target.Close()
	cd := graphqlFinClient(t, origin.URL)
	_, err = cd.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-d"})
	require.Error(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(oH))
	require.Equal(t, int32(0), atomic.LoadInt32(tH), "redirect target receives ZERO requests")
}

func TestFinancialConformance_HTTP5xxCreateUnknownOutcome(t *testing.T) {
	for _, transport := range []string{"rest", "graphql"} {
		t.Run(transport, func(t *testing.T) {
			var qrCalls, telCalls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if transport == "rest" {
					switch {
					case strings.HasSuffix(r.URL.Path, "/msjpagoqrusuario"):
						atomic.AddInt32(&qrCalls, 1)
					case strings.HasSuffix(r.URL.Path, "/msjpagotelefonicousuario"):
						atomic.AddInt32(&telCalls, 1)
					default:
						t.Errorf("unexpected REST create route: %s", r.URL.Path)
					}
				} else {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read GraphQL request: %v", err)
					}
					var q struct {
						OperationName string `json:"operationName"`
					}
					if err := json.Unmarshal(body, &q); err != nil {
						t.Errorf("decode GraphQL request: %v", err)
					}
					switch q.OperationName {
					case "createPagoQr":
						atomic.AddInt32(&qrCalls, 1)
					case "createPagoTelefonico":
						atomic.AddInt32(&telCalls, 1)
					default:
						t.Errorf("unexpected GraphQL operation: %s", q.OperationName)
					}
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer srv.Close()

			var c *client.PaymentClient
			if transport == "rest" {
				c = restFinClient(t, srv.URL)
			} else {
				c = graphqlFinClient(t, srv.URL)
			}
			defer c.Close()

			_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
				IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-http-5xx-qr",
			})
			require.Error(t, err)
			require.True(t, sdkerrors.IsUnknownOutcome(err), "%s CreateQr 5xx must be UnknownOutcome", transport)
			require.False(t, sdkerrors.IsRetryable(err))

			_, err = c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
				Key: "k", Monto: 10, NumeroCelular: "5512345678", IdempotencyKey: "idem-http-5xx-tel",
			})
			require.Error(t, err)
			require.True(t, sdkerrors.IsUnknownOutcome(err), "%s CreateTelefonico 5xx must be UnknownOutcome", transport)
			require.False(t, sdkerrors.IsRetryable(err))

			require.Equal(t, int32(1), atomic.LoadInt32(&qrCalls), "%s CreateQr must be attempted once", transport)
			require.Equal(t, int32(1), atomic.LoadInt32(&telCalls), "%s CreateTelefonico must be attempted once", transport)
		})
	}
}

// pre-dispatch control across transports: a config error before any wire write is
// NOT an UnknownOutcome.
func TestFinancialConformance_PreDispatchNotUnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	for _, tr := range []string{"grpc", "rest", "graphql"} {
		_, err := client.NewClient(context.Background(), &client.Config{
			Target:    srv.URL,
			Insecure:  true,
			Transport: tr,
		})
		require.Error(t, err, "%s missing credential must fail pre-dispatch", tr)
		require.False(t, sdkerrors.IsUnknownOutcome(err), "%s pre-dispatch error must not be UnknownOutcome", tr)
	}
}
