package client

import (
	"errors"
	"math"
)

// Monetary limits for double monto (documented SDK bounds). The protobuf field
// is `double`; we intentionally do NOT assume exact decimal wire semantics and
// reject values that cannot be represented/validated safely.
const (
	// MaxMonto is the documented upper bound for a single payment (MXN pesos).
	MaxMonto = 1_000_000_000.0
	// MinMonto is the documented lower bound (strictly positive).
	MinMonto = 0.01
)

// ValidateMonto rejects NaN, Inf, non-positive, sub-minimum and over-maximum
// amounts without any silent rounding.
func ValidateMonto(m float64) error {
	if math.IsNaN(m) {
		return errors.New("monto is NaN")
	}
	if math.IsInf(m, 0) {
		return errors.New("monto is Inf")
	}
	if m < MinMonto {
		return errors.New("monto below minimum allowed")
	}
	if m > MaxMonto {
		return errors.New("monto above maximum allowed")
	}
	return nil
}
