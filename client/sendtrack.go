package client

import (
	"context"

	"github.com/omarge/tupago3-sdk-go/internal/rpcstats"
)

// withSendTracking attaches a per-call wire-send tracker and returns a function
// reporting whether the request bytes were placed on the wire. Used by Create
// RPCs to distinguish "not sent" from "indeterminate result".
func withSendTracking(ctx context.Context) (context.Context, func() bool) {
	return rpcstats.WithState(ctx)
}
