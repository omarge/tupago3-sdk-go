// Command consumer is an INDEPENDENT application that consumes the published
// tupago3-sdk-go module. It builds a PaymentClient with TLS and a dynamic JWT
// TokenProvider and performs reads against a (test/staging) endpoint.
//
// It intentionally imports ONLY public SDK packages:
//
//	github.com/omarge/tupago3-sdk-go/client
//	github.com/omarge/tupago3-sdk-go/auth
//	github.com/omarge/tupago3-sdk-go/errors
//	github.com/omarge/tupago3-sdk-go/security
//	github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1
//
// It does NOT import any internal/ package.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

// dynamicTokenProvider is a stand-in for a real auth service that mints JWTs.
func dynamicTokenProvider(ctx context.Context) (string, error) {
	// In production this would call your IdP / auth service.
	return os.Getenv("TUPAGO_JWT"), nil
}

func main() {
	target := os.Getenv("TUPAGO_TARGET")
	if target == "" {
		target = "pay.tupago.mx:443"
	}
	caPath := os.Getenv("TUPAGO_CA_PATH")
	if caPath == "" {
		caPath = "/etc/tupago/ca.pem"
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(caPEM))
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	provider := auth.NewJWTTokenProvider(dynamicTokenProvider)
	cfg := &client.Config{
		Target:         target,
		TLS:            tlsCfg,
		Credentials:    provider,
		ConnectTimeout: 10 * time.Second,
	}

	// TUPAGO_TRANSPORT selects the wire protocol: "grpc" (default) or "rest".
	// For "rest" the SDK talks to the REST/JSON backend at TUPAGO_REST_URL
	// (default https://pay.tupago.mx), reusing the same TLS + Bearer identity.
	if transport := os.Getenv("TUPAGO_TRANSPORT"); transport == "rest" {
		restURL := os.Getenv("TUPAGO_REST_URL")
		if restURL == "" {
			restURL = "https://pay.tupago.mx"
		}
		cfg.Transport = "rest"
		cfg.REST = &client.RESTOptions{BaseURL: restURL}
		log.Printf("using REST/JSON transport at %s", restURL)
	}

	c, err := client.NewClient(context.Background(), cfg)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer c.Close()

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	if err != nil {
		if errors.HasGRPCCode(err, 5 /* NotFound */) {
			log.Printf("catalogo not found (expected for unknown institution)")
			return
		}
		log.Fatalf("GetCatalogo: %v", err)
	}
	fmt.Printf("catalogo: %+v\n", cat)
}
