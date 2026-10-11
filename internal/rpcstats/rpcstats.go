// Package rpcstats provides a per-RPC wire-send tracker via the gRPC stats
// handler. It lets the client distinguish "request never reached the server"
// from "request was sent but the result is indeterminate" — the distinction
// that drives the financial UnknownOutcome mapping for Create RPCs.
package rpcstats

import (
	"context"
	"sync"

	"google.golang.org/grpc/stats"
)

type stateKey struct{}
type trackerKey struct{}

type sendState struct {
	mu       sync.Mutex
	wireSent bool
}

func (s *sendState) markSent() {
	s.mu.Lock()
	s.wireSent = true
	s.mu.Unlock()
}

func (s *sendState) sent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wireSent
}

// Tracker owns a gRPC stats.Handler and per-call send states.
type Tracker struct{}

// NewTracker returns a Tracker.
func NewTracker() *Tracker { return &Tracker{} }

// Handler returns a stats.Handler to be installed with grpc.WithStatsHandler.
func (t *Tracker) Handler() stats.Handler { return &handler{} }

// WithState attaches a fresh per-call send tracker to ctx and returns the
// (possibly modified) ctx plus a function that reports whether the request was
// placed on the wire.
func WithState(ctx context.Context) (context.Context, func() bool) {
	s := &sendState{}
	return context.WithValue(ctx, stateKey{}, s), s.sent
}

type handler struct{}

func (h *handler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	if s, ok := ctx.Value(stateKey{}).(*sendState); ok {
		return context.WithValue(ctx, trackerKey{}, s)
	}
	return ctx
}

func (h *handler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	st, ok := ctx.Value(trackerKey{}).(*sendState)
	if !ok || st == nil {
		return
	}
	if _, ok := s.(*stats.OutPayload); ok {
		st.markSent()
	}
}

func (h *handler) TagConn(context.Context, *stats.ConnTagInfo) context.Context {
	return context.Background()
}

func (h *handler) HandleConn(context.Context, stats.ConnStats) {}
