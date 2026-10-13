# TUPAGO3 SDK — Go

Cliente Go idiomático y thread-safe para el contrato `tupago.api.v1.PaymentService` de **TUPAGO3**.

* Seis capacidades: `GetCliente`, `GetCatalogo`, `GetQrStatus`, `GetTelefonicoStatus`, `CreateQr`, `CreateTelefonico`.
* Transportes: **gRPC** (default), **REST** y **GraphQL**.
* TLS verificado con soporte de CA personalizada; plaintext permitido **solo** para loopback.
* JWT dinámico por llamada (`Authorization: Bearer`), nunca logueado.
* **Auth fail-closed**: credenciales requeridas por defecto.
* Retry acotado **solo para lecturas**; creates son **single-attempt / no-blind-retry**.
* Errores tipados (`errors.IsUnknownOutcome`, `errors.IsPendingReconciliation`, etc.).
* Deadlines/cancellation vía `context.Context`, seguro para uso concurrente.

> **Invariante financiera:** un `Create` se intenta como máximo una vez. Un error transitorio detectado *después* de que la request pudo haber salido se reporta como `UnknownOutcomeError` (reconciliar, **no** reintentar a ciegas).

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

## Transportes

Selecciona el transporte con `Config.Transport` (`"grpc"`, `"rest"`, `"graphql"`).
REST y GraphQL requieren `Config.REST` / `Config.GraphQL` con la URL base.

## Licencia

Propietaria — ver `LICENSE`. Distribución interna controlada únicamente.
