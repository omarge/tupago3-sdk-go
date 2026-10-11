# TUPAGO3 SDK — Go

Idiomatic, thread-safe Go client for the **TUPAGO3 `tupago.api.v1.PaymentService`** gRPC contract.

* Six RPCs: `GetCliente`, `GetCatalogo`, `GetQrStatus`, `GetTelefonicoStatus`, `CreateQr`, `CreateTelefonico`.
* Verified TLS with custom-CA support; plaintext permitted **only** for loopback.
* Dynamic per-RPC JWT (`Authorization: Bearer`), never logged.
* Bounded retry **for reads only**; `CreateQr`/`CreateTelefonico` are **exactly-once, never auto-retried**.
* Typed, machine-detectable errors (`errors.IsUnknownOutcome`, `errors.IsPendingReconciliation`, `errors.HasGRPCCode`, `errors.IsRetryable`) compatible with `errors.Is`/`errors.As`.
* `context.Context` deadlines/cancellation, no global mutable state, safe for concurrent use.

> **Financial invariant:** a `Create` is attempted at most once. A transient error detected *after* the request left the wire is surfaced as `UnknownOutcomeError` (reconcile, do **not** blind-retry). `TUPAGO_PENDING_RECONCILIATION` is preserved as a non-transient, detectable error.

## Install

```bash
go get github.com/omarge/tupago3-sdk-go
```

## Quick start

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

A complete, dependency-free consumer application lives at `../tupago3-sdk-go-consumer`
(see `TestConsumerVerifiesSDK` for NOT_FOUND / UNAUTHENTICATED / UnknownOutcome checks).

## Packages (stable public API)

| Import | Purpose |
| --- | --- |
| `github.com/omarge/tupago3-sdk-go` | Root re-exports of the common entry points. |
| `.../client` | `PaymentClient`, `Config`, `NewClient`, `Close`, the six RPCs, `ValidateMonto`. |
| `.../auth` | `TokenProvider`, `StaticTokenProvider`, `NewJWTTokenProvider`, `NewBearerCredentials`. |
| `.../security` | `NewTLSConfig`, `WithCACertPEM`, `IsLoopback`, `RequireTLSForTarget`. |
| `.../errors` | `TupagoError`, `UnknownOutcomeError`, `PendingReconciliationError`, mappers, predicates. |
| `.../retry` | `NoRetry`, `BoundedReadBackoff`, `IsRetryableRead`. |
| `.../proto/tupago/api/v1` | Frozen, generated gRPC/Protobuf bindings (immutable contract). |
| `.../internal/rpcstats` | Internal: per-RPC wire-send tracker (not part of the stable API). |

## Security model

* **TLS:** required for every non-loopback target (fail-closed). Plaintext is
  allowed **only** for `127.0.0.1`, `::1` and `localhost`, and only when
  `Config.Insecure` is set (loopback-only; non-loopback plaintext is always
  rejected). Transport credentials are derived solely from `Config.TLS` /
  `Config.Insecure` and are appended last and authoritatively — no public option
  can downgrade TLS to plaintext or override the peer's transport security.
  Server-certificate verification is ALWAYS enforced: `InsecureSkipVerify` is not
  supported by the public API and any attempt to disable it (helper or raw
  `*tls.Config`) is rejected. Private CAs and a verified `ServerName` are
  supported. Tests use an in-process, real-loopback server rather than a
  configurable public dialer, so no caller can redirect the connection to a
  remote plaintext peer.
* **JWT:** injected per RPC via `PerRPCCredentials`. Tokens are never written to
  logs or returned in errors.
* **Create safety:** `Create*` RPCs are invoked exactly once; transient post-send
  failures map to `UnknownOutcomeError`.

## Monetary validation

The protobuf field is `double monto`. The SDK does **not** assume exact decimal
wire semantics. Use `client.ValidateMonto` to reject `NaN`, `Inf`, non-positive,
sub-minimum and over-maximum values with no silent rounding. The `idempotency_key`
is preserved verbatim and never regenerated.

## Testing & certification

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -l .
```

See `TUPAGO3-SDK-GO-FINAL-CERTIFICATION.001.txt` for the consolidated certification
record (gates, evidence, SHA256, and any CONDITIONAL findings).

## License

Proprietary — see `LICENSE`. Internal controlled distribution only.
