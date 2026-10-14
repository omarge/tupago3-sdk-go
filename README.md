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

## C2 CreateTelefonico — endpoint canónico

REST: `POST /api/payments/msjpagotelefonicousuario`

Usa `resolveSingleOwnedCliente()` — misma autoridad que gRPC/GraphQL.

**NO** usar `/msjpagotelefonico` (usa `requireOwnedClienteByKey`, autoridad diferente).

## ByCuenta en consultas de estatus

El backend3 ofrece dos formas de consultar el estatus de un pago:

| Variante | Cuándo usarla | Qué envía el SDK |
|----------|-----------------|-------------------|
| **ByCuenta** | El caller conoce la cuenta | `idCuenta` explícito en el body |
| **Usuario** | El backend resuelve la cuenta del JWT | Solo `idc` |

**Política del SDK:** si el request incluye `idCuenta` > 0, se usa **ByCuenta** automáticamente.

```go
// ByCuenta (recomendado)
status, err := c.GetQrStatus(ctx, &v1.GetStatusRequest{
    Idc:      "abc123",
    IdCuenta: 42,   // activa ByCuenta
})

// Rutas usadas:
// REST:  POST /api/payments/estatusmsjqr
// GraphQL: pagoQrEstatusByCuenta(idc, idCuenta)
```

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


---

# Implementation manual / Manual de implementación

## Manual ES — Implementación paso a paso

**Índice:** [1. Requisitos](#manual-es--implementación-paso-a-paso) · [2. Instalación](#manual-es--implementación-paso-a-paso) · [3. Configuración](#manual-es--implementación-paso-a-paso) · [4. Ejemplo](#manual-es--implementación-paso-a-paso) · [5. Contrato C1–C6](#contrato-de-referencia--reference-contract) · [6. Seguridad y errores](#reglas-financieras--financial-safety-rules) · [7. Pruebas y distribución](#pruebas-y-aceptación--testing-and-acceptance)

1. **Requisitos:** Go / immutable module. Disponer de acceso autorizado a backend3, credenciales JWT válidas y ambiente HTTPS, o laboratorio loopback explícitamente habilitado.
2. **Instalación:** `go test ./... && go test -race ./... && go vet ./...`. In a separate Go module, use `go get github.com/omarge/tupago3-sdk-go@7c5d891296f4fad5d357d44e2861b05be3f1209e` or an explicitly certified immutable revision; **no local replace**.
3. **Configuración:** seleccionar el transporte soportado; suministrar endpoint real y JWT mediante variable de entorno o proveedor de credenciales. No usar puertos de laboratorio como defaults productivos.
4. **Ejemplo de inicio:** ejecutar el ejemplo de abajo con los imports/exports públicos propios del SDK; sustituir los hostnames de ejemplo y consultar primero C5/C6.
5. **Contrato:** consultar tabla C1–C6; en C3 y C4 conservar `idc` e `idCuenta`, y en C5 exigir perfil compuesto.
6. **Errores y seguridad:** diferenciar `UnknownOutcome`, `PendingReconciliation`, `NOT_FOUND`, autenticación y permisos. Nunca reintentar creaciones automáticamente.
7. **Validación:** `go test ./...`, `go test -race ./...`, `go vet ./...`; verify independently resolved module in `go.mod`/`go.sum` and no source-tree `replace`. Go is distributed as a module, not a NuGet/JAR equivalent.

### Ejemplo / Example (Go / immutable module)

\`\`\`go
package main
import (
  "context"
  "log"
  "os"
  "github.com/omarge/tupago3-sdk-go/client"
  "github.com/omarge/tupago3-sdk-go/auth"
)
func main() {
  cfg := &client.Config{Target:"127.0.0.1:9091", Transport:"grpc",
    Insecure:true, Credentials:auth.StaticTokenProvider(os.Getenv("TUPAGO_JWT"))}
  c, err := client.NewClient(context.Background(), cfg)
  if err != nil { log.Fatal(err) }
  defer c.Close()
  // Use GetCliente / GetCatalogo / status methods; do not run Create against live accounts.
}
\`\`\`

## Manual EN — Step-by-step implementation

**Contents:** [1. Prerequisites](#manual-en--step-by-step-implementation) · [2. Install](#manual-en--step-by-step-implementation) · [3. Configure](#manual-en--step-by-step-implementation) · [4. Example](#manual-en--step-by-step-implementation) · [5. C1–C6 wire contract](#contrato-de-referencia--reference-contract) · [6. Safety and errors](#reglas-financieras--financial-safety-rules) · [7. Verify and distribute](#pruebas-y-aceptación--testing-and-acceptance)

1. **Prerequisites:** Go / immutable module; authorized backend3 credentials and a TLS-enabled endpoint (or explicitly authorized loopback lab).
2. **Install:** `go test ./... && go test -race ./... && go vet ./...`. In a separate Go module, use `go get github.com/omarge/tupago3-sdk-go@7c5d891296f4fad5d357d44e2861b05be3f1209e` or an explicitly certified immutable revision; **no local replace**.
3. **Configure:** choose a supported transport; supply the endpoint and JWT through environment-backed credential providers. Do not copy lab hosts or ports into production.
4. **Minimal example:** follow the SDK-specific example below. Replace placeholder endpoints and start with a C5/C6 read.
5. **Contract:** consult the exact C1–C6 wire table. Preserve `idc`/`idCuenta` and require the full composed C5 profile.
6. **Errors and security:** distinguish unknown financial outcomes, pending reconciliation, not-found and auth/ownership failures. Never automatically replay creates.
7. **Verification:** `go test ./...`, `go test -race ./...`, `go vet ./...`; verify independently resolved module in `go.mod`/`go.sum` and no source-tree `replace`. Go is distributed as a module, not a NuGet/JAR equivalent.

## Contrato de referencia / Reference contract

**ES.** Autoridad: backend3 `omarge/tupagoback3` `bbf06c02bda06221b2f214075a4bf2bdf3345eb0`. El JWT determina identidad y alcance de propietario; jamás hardcodear secretos. `idc`, `idCuenta` y claves bancarias son identificadores: conservar su representación y ceros iniciales.

**EN.** Authority: backend3 at the pinned commit above. JWT determines caller identity/ownership. Never hardcode credentials. Preserve IDs and leading zeros; do not coerce long IDs through floating-point numbers.

| Operación / Operation | REST backend3 | GraphQL backend3 | gRPC |
|---|---|---|---|
| C1 CreateQr | `POST /api/payments/msjpagoqrusuario` | `createPagoQr` | `CreateQr` |
| C2 CreateTelefonico | `POST /api/payments/msjpagotelefonicousuario` | `createPagoTelefonico` | `CreateTelefonico` |
| C3 GetQrStatus | `POST /api/payments/estatusmsjqr` JSON `{"idc":"...","idCuenta":42}` | `pagoQrEstatusByCuenta(idc,idCuenta)` | `GetQrStatus` |
| C4 GetTelefonicoStatus | `POST /api/payments/estatusmsjcobrotelefonico` JSON `{"idCuenta":42,"idMsjdeCobro":"..."}` | `pagoTelefonicoEstatusByCuenta(idc,idCuenta)` | `GetTelefonicoStatus` |
| C5 GetCliente | `GET /api/clientes/{id}` **then** `GET /api/catalogo-institucions/clave/{claveInstitucion}` | `getCliente`/equivalent schema query | `GetCliente` |
| C6 GetCatalogo | `GET /api/catalogo-institucions/clave/{clave}` | `catalogoInstitucion` | `GetCatalogo` |

**ES.** En C4, `idMsjdeCobro` corresponde al `idc` público. C5 debe devolver `ClientePerfil` **compuesto**, no solamente el `ClienteDTO`. Los nombres de métodos del SDK pueden diferir de los nombres wire; usar las APIs públicas mostradas abajo.

**EN.** In C4, `idMsjdeCobro` is the public request's `idc`. C5 must return the **composed** `ClientePerfil`, not just `ClienteDTO`. SDK method names and wire operation names may differ.

### Reglas financieras / Financial safety rules

1. **ES:** C1/C2 tienen **un solo intento** por llamada; nunca activar reintentos automáticos de creación. **EN:** C1/C2 are single-attempt; never enable automatic creation retries.
2. **ES:** Guardar la clave de idempotencia original de cada pago. Un timeout, corte de conexión, 5xx, redirección o respuesta de éxito inválida después del posible envío es `UnknownOutcome`: **consultar estado/reconciliar**, no reenviar ciegamente ni generar otra clave. **EN:** Persist the caller-owned idempotency key. Post-dispatch ambiguity is `UnknownOutcome`: reconcile with the original identity, never blindly resend or mint a different key.
3. **ES:** `PendingReconciliation` (REST 202 autorizado, GraphQL `PAYMENT_PENDING_RECONCILIATION`, gRPC `ABORTED` + `TUPAGO_PENDING_RECONCILIATION`) no significa éxito ni autoriza reintento. **EN:** Pending is neither success nor permission to retry.
4. **ES:** C3–C6 son lecturas; sólo los errores transitorios elegibles pueden reintentarse dentro del límite de política. Errores de JWT, permisos, validación, conflicto o inexistencia no. **EN:** Only eligible transient read errors may be retried within a bounded policy; deterministic failures must not.
5. **ES:** TLS con verificación de identidad fuera de loopback; plaintext únicamente en laboratorio local explícito cuando el adaptador lo permita. Tokens sólo por proveedor seguro/entorno. **EN:** Verify TLS identity for remote targets; explicit local loopback lab exceptions only. Never ship lab keys or tokens.
6. **ES:** Backend3/PostgreSQL sigue siendo la autoridad financiera; el SDK no confirma liquidaciones. **EN:** Backend3/PostgreSQL remains the financial authority; an SDK response is not settlement proof.

### Pruebas y aceptación / Testing and acceptance

**ES — Secuencia:** (1) compilar y ejecutar tests, (2) construir paquete exacto, (3) instalarlo en consumidor **fuera del árbol fuente**, (4) probar JWT válido/ausente/inválido y C3–C6 contra backend3 aislado, (5) verificar ownership y `NOT_FOUND`, (6) C1/C2 solamente en sandbox aprobado sin pagos reales, (7) registrar HEAD, CI y SHA256. No afirmar E2E de transportes no probados.

**EN — Sequence:** (1) build and test, (2) produce the exact artifact, (3) install into a separate **out-of-tree** consumer, (4) verify valid/missing/invalid JWT and C3–C6 against an isolated real backend3, (5) verify ownership and typed `NOT_FOUND`, (6) test C1/C2 only in an explicitly approved non-production financial sandbox, (7) record HEAD, CI and SHA256. Do not claim untested transports as E2E-certified.

**Estado / Status:** local and read-only E2E certificates cover their **documented transports**, not production financial writes, Banxico/STP external calls, or real Microsoft Office host validation.

