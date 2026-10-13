# TUPAGO3 SDK — Go

Cliente Go idiomático y thread-safe para el contrato gRPC `tupago.api.v1.PaymentService` de **TUPAGO3**.

* Seis RPCs: `GetCliente`, `GetCatalogo`, `GetQrStatus`, `GetTelefonicoStatus`, `CreateQr`, `CreateTelefonico`.
* TLS verificado con soporte de CA personalizada; plaintext permitido **solo** para loopback.
* JWT dinámico por RPC (`Authorization: Bearer`), nunca logueado.
* Retry acotado **solo para lecturas**; `CreateQr`/`CreateTelefonico` son **single-attempt / no-blind-retry**.
* Errores tipados y detectables (`errors.IsUnknownOutcome`, `errors.IsPendingReconciliation`, etc.).
* Deadlines/cancellation vía `context.Context`, sin estado global mutable, seguro para uso concurrente.

> **Invariante financiera:** un `Create` se intenta como máximo una vez. Un error transitorio detectado *después* de que la request pudo haber salido se reporta como `UnknownOutcomeError` (reconciliar, **no** reintentar a ciegas). `TUPAGO_PENDING_RECONCILIATION` se preserva como error no-transitorio detectable.

## Instalación

```bash
go get github.com/omarge/tupago3-sdk-go
```

## Inicio rápido

```go
package main

import (
	"context"
	"log"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/security"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

func main() {
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(caPEM))
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      "pay.tupago.mx:443",
		TLS:         tlsCfg,
		Credentials: auth.NewJWTTokenProvider(fetchJWT),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	if err != nil {
		log.Fatal(err)
	}
	_ = cat
}
```

## Estado

Actualmente solo gRPC. REST y GraphQL están pendientes de implementación alineada con backend3.

## Licencia

Propietaria — ver `LICENSE`. Distribución interna controlada únicamente.
