// Package errors defines the typed, machine-detectable error model for the
// TUPAGO3 Go SDK. Every error surfaced by the client implements error and is
// inspectable with errors.Is / errors.As. gRPC status codes are preserved and
// the two financial invariants are modelled explicitly:
//
//   - UnknownOutcomeError: a Create whose remote result is indeterminate.
//     MUST NOT be retried blindly and requires reconciliation.
//   - PendingReconciliationError: the backend returned ABORTED carrying the
//     TUPAGO_PENDING_RECONCILIATION marker. Non-transient and detectable.
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omarge/tupago3-sdk-go/retry"
)

// PendingReconciliationMarker is the backend signal (carried on an ABORTED
// status) that the operation is queued/duplicated and must be reconciled.
const PendingReconciliationMarker = "TUPAGO_PENDING_RECONCILIATION"

// TupagoError is the base typed error for all SDK failures.
type TupagoError struct {
	// Operation is the RPC name (e.g. "CreateQr").
	Operation string
	// GRPCCode is the originating gRPC status code (preserved verbatim).
	GRPCCode codes.Code
	// Message is the gRPC status message (preserved verbatim).
	Message string
	// Retryable is false for every financial/definite outcome and for
	// unknown outcomes. Only bounded read retries set this true.
	Retryable bool
	// sentSet is true only when we have a definitive wire-send observation.
	// It is set for Create calls (via the rpcstats tracker); read calls leave
	// it false so we never assert a send state we did not measure.
	sentSet bool
	// Sent is meaningful only when sentSet is true: the request bytes were
	// placed on the wire. For Create calls Sent=false means the request
	// provably did not reach the server.
	Sent bool
}

func (e *TupagoError) Error() string {
	qual := ""
	if e.sentSet && !e.Sent {
		qual = " [request-not-sent]"
	}
	return fmt.Sprintf("tupago: %s: %s: %s%s", e.Operation, e.GRPCCode, e.Message, qual)
}

// Is makes TupagoError comparable. A target with a non-zero Operation or
// GRPCCode narrows the match.
func (e *TupagoError) Is(target error) bool {
	t, ok := target.(*TupagoError)
	if !ok {
		return false
	}
	if t.Operation != "" && t.Operation != e.Operation {
		return false
	}
	if t.GRPCCode != codes.OK && t.GRPCCode != e.GRPCCode {
		return false
	}
	return true
}

func (e *TupagoError) Unwrap() error { return status.Error(e.GRPCCode, e.Message) }

func (e *TupagoError) GRPCStatus() *status.Status { return status.New(e.GRPCCode, e.Message) }

// UnknownOutcomeError indicates a financial Create whose remote result is
// indeterminate. It MUST NOT be retried and requires reconciliation.
type UnknownOutcomeError struct {
	TupagoError
	Reconcile bool
}

// NewUnknownOutcome builds an UnknownOutcomeError. grpcCode is the original
// gRPC code observed after the (sent) Create request.
func NewUnknownOutcome(operation string, grpcCode codes.Code, detail string) *UnknownOutcomeError {
	return &UnknownOutcomeError{
		TupagoError: TupagoError{
			Operation: operation,
			GRPCCode:  grpcCode,
			Message: fmt.Sprintf(
				"resultado desconocido tras %s (grpc=%s): %s; reconciliar; NO reintentar ciegamente",
				operation, grpcCode, detail),
			Retryable: false,
			sentSet:   true,
			Sent:      true,
		},
		Reconcile: true,
	}
}

func (e *UnknownOutcomeError) Is(target error) bool {
	if _, ok := target.(*UnknownOutcomeError); ok {
		return true
	}
	return e.TupagoError.Is(target)
}

// PendingReconciliationError is raised when the backend answers ABORTED with
// the TUPAGO_PENDING_RECONCILIATION marker. It is non-transient and safe to
// machine-detect.
type PendingReconciliationError struct {
	TupagoError
}

func NewPendingReconciliation(operation string, detail string) *PendingReconciliationError {
	return &PendingReconciliationError{
		TupagoError: TupagoError{
			Operation: operation,
			GRPCCode:  codes.Aborted,
			Message:   fmt.Sprintf("%s: %s", PendingReconciliationMarker, detail),
			Retryable: false,
			sentSet:   true,
			Sent:      true,
		},
	}
}

func (e *PendingReconciliationError) Is(target error) bool {
	if _, ok := target.(*PendingReconciliationError); ok {
		return true
	}
	return e.TupagoError.Is(target)
}

// ConfigError indicates an invalid client configuration.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("tupago: config: %s", e.Message)
	}
	return fmt.Sprintf("tupago: config.%s: %s", e.Field, e.Message)
}

// NewConfigError builds a ConfigError.
func NewConfigError(field, msg string) *ConfigError { return &ConfigError{Field: field, Message: msg} }

// NewInvalidArgument builds a TupagoError with code InvalidArgument, used when
// client-side validation (e.g. monto, idempotency_key) rejects a request
// before it touches the network.
func NewInvalidArgument(operation, msg string) *TupagoError {
	return &TupagoError{Operation: operation, GRPCCode: codes.InvalidArgument, Message: msg, Retryable: false}
}

func isRetryableReadCode(code codes.Code) bool {
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Internal, codes.Unknown:
		return true
	default:
		return false
	}
}

// isDefiniteCreateOutcome reports codes that prove the server processed (or
// definitively rejected) the Create, so a non-retryable typed error is enough.
func isDefiniteCreateOutcome(code codes.Code) bool {
	switch code {
	case codes.NotFound, codes.InvalidArgument, codes.AlreadyExists,
		codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
		codes.OutOfRange, codes.Canceled:
		return true
	default:
		return false
	}
}

// MapRPCError maps a grpc error returned by a read RPC into a typed TupagoError,
// preserving the gRPC code/message and classifying PendingReconciliation.
func MapRPCError(err error, operation string) error {
	if err == nil {
		return nil
	}
	var te *TupagoError
	if stderrors.As(err, &te) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return &TupagoError{Operation: operation, GRPCCode: codes.Unknown, Message: err.Error(), Retryable: false}
	}
	code := st.Code()
	msg := st.Message()
	if code == codes.Aborted && strings.Contains(strings.ToUpper(msg), PendingReconciliationMarker) {
		return NewPendingReconciliation(operation, msg)
	}
	return &TupagoError{Operation: operation, GRPCCode: code, Message: msg, Retryable: isRetryableReadCode(code)}
}

// MapCreateError maps a grpc error returned by a Create RPC. requestSent must
// be true only when the request bytes were placed on the wire (see rpcstats).
//
// Rules:
//   - PendingReconciliation (ABORTED + marker) -> PendingReconciliationError.
//   - Definite server outcomes -> typed TupagoError (no retry).
//   - Transient/indeterminate + sent -> UnknownOutcomeError (no retry).
//   - Transient/indeterminate + not sent -> typed TupagoError [request-not-sent].
func MapCreateError(err error, operation string, requestSent bool) error {
	if err == nil {
		return nil
	}
	var te *TupagoError
	if stderrors.As(err, &te) {
		return err
	}
	code := codes.Unknown
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		code = st.Code()
		msg = st.Message()
	}
	if code == codes.Aborted && strings.Contains(strings.ToUpper(msg), PendingReconciliationMarker) {
		return NewPendingReconciliation(operation, msg)
	}
	if isDefiniteCreateOutcome(code) {
		return &TupagoError{Operation: operation, GRPCCode: code, Message: msg, Retryable: false, sentSet: true, Sent: requestSent}
	}
	if requestSent {
		return NewUnknownOutcome(operation, code, msg)
	}
	return &TupagoError{
		Operation: operation,
		GRPCCode:  code,
		Message:   "request not sent: " + msg,
		Retryable: false,
		sentSet:   true,
		Sent:      false,
	}
}

// Predicates for machine detection.

func IsTupagoError(err error) bool {
	var te *TupagoError
	return stderrors.As(err, &te)
}

func IsUnknownOutcome(err error) bool {
	var ue *UnknownOutcomeError
	return stderrors.As(err, &ue)
}

func IsPendingReconciliation(err error) bool {
	var pe *PendingReconciliationError
	return stderrors.As(err, &pe)
}

func IsRequestNotSent(err error) bool {
	var te *TupagoError
	if stderrors.As(err, &te) {
		return te.sentSet && !te.Sent
	}
	return false
}

// HasGRPCCode reports whether err (or any wrapped TupagoError) carries code.
func HasGRPCCode(err error, code codes.Code) bool {
	var te *TupagoError
	if stderrors.As(err, &te) {
		return te.GRPCCode == code
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == code
	}
	return false
}

// IsRetryable reports whether err is a retryable transient failure. TupagoError
// carries an explicit Retryable flag; for bare gRPC errors it defers to the read
// transient classification. UnknownOutcome and PendingReconciliation are NEVER
// retryable.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if IsUnknownOutcome(err) || IsPendingReconciliation(err) {
		return false
	}
	var te *TupagoError
	if stderrors.As(err, &te) {
		return te.Retryable
	}
	return retry.IsRetryableRead(err)
}
