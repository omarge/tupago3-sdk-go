// Command example demonstrates building a TUPAGO3 PaymentClient with TLS and a
// dynamic JWT TokenProvider and performing a read against a (test/staging)
// endpoint. It is buildable as part of `go build ./...`; it does not perform any
// financial Create and never contacts production Banxico/PSP endpoints.
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

func main() {
	target := env("TUPAGO_TARGET", "pay.tupago.mx:443")
	caPEM, err := os.ReadFile(env("TUPAGO_CA_PATH", "/etc/tupago/ca.pem"))
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(caPEM))
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	// Dynamic JWT rotation: the provider is invoked per call and the SDK caches
	// the token until its `exp` claim.
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: target,
		TLS:    tlsCfg,
		Credentials: auth.NewJWTTokenProvider(func(ctx context.Context) (string, error) {
			return os.Getenv("TUPAGO_JWT"), nil
		}),
		ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer c.Close()

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	if err != nil {
		if errors.HasGRPCCode(err, 5 /* NotFound */) {
			log.Printf("institution not found (acceptable for demo)")
			return
		}
		log.Fatalf("GetCatalogo: %v", err)
	}
	fmt.Printf("catalogo: %+v\n", cat)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
