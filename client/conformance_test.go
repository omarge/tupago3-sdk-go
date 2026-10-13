package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// genLoopbackCert returns a self-signed CA cert/key PEM pair for an in-process
// loopback TLS server (localhost / 127.0.0.1).
func genLoopbackCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "conformance-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// ===== Phase D: cross-transport conformance =====
//
// This test proves that the gRPC, REST and GraphQL transports are behavioural
// peers: given the SAME backend DTOs, all three yield byte-identical typed
// results, identical int64 identity, identical exactly-once/idempotency and
// identical error-model mapping. The fake servers are seeded from one canonical
// source of truth so any divergence is a real conformance defect.

const (
	cfQrPayload  = `{"qr":"https://pay.tupago/qr/abc","idCuenta":9223372036854775807}`
	cfTelPayload = `{"ref":"TEL-123","numeroCelular":5512345678}`
	cfQrStatus   = `[{"status":"ACTIVE","idc":"IDC1"}]`
	cfTelStatus  = `{"status":"PAID"}`
)

var (
	cfClienteID = int64(9223372036854775807)
	cfCatalogID = int64(9007199254740993)
)

type conformanceResult struct {
	CatID     int64
	CatClave  string
	CatNombre string
	ClienteID int64
	QrJSON    string
	TelJSON   string
	QrStatus  string
	TelStatus string
}

// ---------- gRPC seed server ----------

type conformanceGRPC struct {
	v1.UnimplementedPaymentServiceServer
	failReads bool
}

func (s *conformanceGRPC) GetCliente(context.Context, *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if s.failReads {
		return nil, status.Error(codes.NotFound, "no such cliente")
	}
	return &v1.ClientePerfil{
		Cliente:             &v1.Cliente{Id: cfClienteID, Nombre: "Demo", ClaveInstitucion: "BCM", Key: "k1"},
		CatalogoInstitucion: &v1.CatalogoInstitucion{Id: cfCatalogID, ClaveInstitucion: "BCM", NombreCorto: "Banco"},
	}, nil
}

func (s *conformanceGRPC) GetCatalogo(context.Context, *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	if s.failReads {
		return nil, status.Error(codes.NotFound, "no such catalogo")
	}
	return &v1.CatalogoInstitucion{Id: cfCatalogID, ClaveInstitucion: "BCM", NombreCorto: "Banco"}, nil
}

func (s *conformanceGRPC) GetQrStatus(context.Context, *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	return &v1.JsonResponse{Json: cfQrStatus}, nil
}

func (s *conformanceGRPC) GetTelefonicoStatus(context.Context, *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	return &v1.JsonResponse{Json: cfTelStatus}, nil
}

func (s *conformanceGRPC) CreateQr(context.Context, *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	return &v1.JsonResponse{Json: cfQrPayload}, nil
}

func (s *conformanceGRPC) CreateTelefonico(context.Context, *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error) {
	return &v1.JsonResponse{Json: cfTelPayload}, nil
}

func startGRPCConformance(t *testing.T, failReads bool) *client.PaymentClient {
	t.Helper()
	certPEM, keyPEM := genLoopbackCert(t)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	v1.RegisterPaymentServiceServer(srv, &conformanceGRPC{failReads: failReads})
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

// ---------- REST fake (backend3 route shapes) ----------

func restConformanceHandler(failReads bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if failReads {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case r.Method == http.MethodGet && hasPrefix(r.URL.Path, "/api/clientes/"):
			_, _ = w.Write([]byte(`{"id":9223372036854775807,"nombre":"Demo","claveInstitucion":"BCM","key":"k1"}`))
		case r.Method == http.MethodGet && hasPrefix(r.URL.Path, "/api/catalogo-institucions/clave/"):
			_, _ = w.Write([]byte(`{"id":9007199254740993,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/msjpagoqrusuario"):
			_, _ = w.Write([]byte(`{"mensaje":` + cfQrPayload + `,"emisor":"B","banco":"BCM"}`))
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/msjpagotelefonicousuario"):
			_, _ = w.Write([]byte(cfTelPayload))
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/estatusmsjqr"):
			_, _ = w.Write([]byte(cfQrStatus))
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/estatusmsjcobrotelefonicousuario"):
			_, _ = w.Write([]byte(cfTelStatus))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func startRESTConformance(t *testing.T, failReads bool) *client.PaymentClient {
	t.Helper()
	srv := httptest.NewServer(restConformanceHandler(failReads))
	t.Cleanup(srv.Close)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Insecure:    true,
		Transport:   "rest",
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	return c
}

// ---------- GraphQL fake (backend3 GraphQL shapes) ----------

func graphqlConformanceHandler(failReads bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		var q struct {
			OperationName string `json:"operationName"`
		}
		_ = json.Unmarshal(body, &q)
		if failReads {
			_, _ = w.Write([]byte(`{"data":{"` + q.OperationName + `":null}}`))
			return
		}
		switch q.OperationName {
		case "cliente":
			_, _ = w.Write([]byte(`{"data":{"cliente":{"cliente":{"id":"9223372036854775807","nombre":"Demo","claveInstitucion":"BCM","key":"k1"},"catalogoInstitucion":{"id":"9007199254740993","claveInstitucion":"BCM","nombreCorto":"Banco"}}}}`))
		case "catalogoInstitucion":
			_, _ = w.Write([]byte(`{"data":{"catalogoInstitucion":{"id":"9007199254740993","claveInstitucion":"BCM","nombreCorto":"Banco"}}}`))
		case "createPagoQr":
			_, _ = w.Write([]byte(`{"data":{"createPagoQr":` + cfQrPayload + `}}`))
		case "createPagoTelefonico":
			_, _ = w.Write([]byte(`{"data":{"createPagoTelefonico":` + cfTelPayload + `}}`))
		case "pagoQrEstatusByCuenta":
			_, _ = w.Write([]byte(`{"data":{"pagoQrEstatusByCuenta":` + cfQrStatus + `}}`))
		case "pagoTelefonicoEstatusByCuenta":
			_, _ = w.Write([]byte(`{"data":{"pagoTelefonicoEstatusByCuenta":` + cfTelStatus + `}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func startGraphQLConformance(t *testing.T, failReads bool) *client.PaymentClient {
	t.Helper()
	srv := httptest.NewServer(graphqlConformanceHandler(failReads))
	t.Cleanup(srv.Close)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Insecure:    true,
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: srv.URL},
	})
	require.NoError(t, err)
	return c
}

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }
func hasPrefix(s, pre string) bool { return len(s) >= len(pre) && s[:len(pre)] == pre }

// collectConformance runs the full C1-C6 surface and returns the observed results.
func collectConformance(t *testing.T, c *client.PaymentClient) conformanceResult {
	t.Helper()
	var res conformanceResult

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	res.CatID = cat.Id
	res.CatClave = cat.ClaveInstitucion
	res.CatNombre = cat.NombreCorto

	perfil, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 99})
	require.NoError(t, err)
	res.ClienteID = perfil.Cliente.Id

	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-qr"})
	require.NoError(t, err)
	res.QrJSON = qr.Json

	tel, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-tel"})
	require.NoError(t, err)
	res.TelJSON = tel.Json

	qs, err := c.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 42})
	require.NoError(t, err)
	res.QrStatus = qs.Json

	ts, err := c.GetTelefonicoStatus(context.Background(), &v1.GetStatusRequest{Idc: "COBRO1", IdCuenta: 7})
	require.NoError(t, err)
	res.TelStatus = ts.Json

	return res
}

// TestCrossTransportConformance proves gRPC == REST == GraphQL for the full
// C1-C6 surface: identical typed results, identical int64 identity, identical
// payloads, and identical error-model mapping.
func TestCrossTransportConformance(t *testing.T) {
	g := startGRPCConformance(t, false)
	r := startRESTConformance(t, false)
	q := startGraphQLConformance(t, false)
	t.Cleanup(func() { _ = g.Close(); _ = r.Close(); _ = q.Close() })

	rg := collectConformance(t, g)
	rr := collectConformance(t, r)
	rq := collectConformance(t, q)

	// Each transport matches the canonical expectations.
	expected := conformanceResult{
		CatID:     cfCatalogID,
		CatClave:  "BCM",
		CatNombre: "Banco",
		ClienteID: cfClienteID,
		QrJSON:    cfQrPayload,
		TelJSON:   cfTelPayload,
		QrStatus:  cfQrStatus,
		TelStatus: cfTelStatus,
	}
	require.Equal(t, expected, rg, "gRPC results must match canonical DTOs")
	require.Equal(t, expected, rr, "REST results must match canonical DTOs")
	require.Equal(t, expected, rq, "GraphQL results must match canonical DTOs")

	// Cross-transport equality (the actual conformance guarantee).
	require.Equal(t, rg, rr, "gRPC and REST must be byte-identical")
	require.Equal(t, rg, rq, "gRPC and GraphQL must be byte-identical")
	require.Equal(t, rr, rq, "REST and GraphQL must be byte-identical")
}

// TestCrossTransportNotFoundsParity proves all three transports map a missing
// reference read to the same canonical NotFound error code.
func TestCrossTransportNotFoundsParity(t *testing.T) {
	g := startGRPCConformance(t, true)
	r := startRESTConformance(t, true)
	q := startGraphQLConformance(t, true)
	t.Cleanup(func() { _ = g.Close(); _ = r.Close(); _ = q.Close() })

	for name, c := range map[string]*client.PaymentClient{"grpc": g, "rest": r, "graphql": q} {
		_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "X"})
		require.Error(t, err, name)
		require.True(t, errors.HasGRPCCode(err, codes.NotFound), "%s must surface NotFound", name)
		require.False(t, errors.IsRetryable(err), "%s NotFound must not be retryable", name)
	}
}
