// Package oauthtelem records OAuth2 lifecycle telemetry: per-endpoint
// domain spans (so token / introspect / revoke / userinfo each carry
// their grant-type and outcome) and per-operation counters / histograms.
//
// Handlers obtain a Recorder once and call its Start* helpers to open a
// child span of the HTTP server span, then RecordTokenIssued etc. on the
// way out. When telemetry is disabled the Recorder is a no-op: every
// helper short-circuits and returns immediately.
//
// Token values, refresh tokens, and client secrets are never recorded.
// Only stable identifiers (client_id, grant_type, scope, token_type) and
// the resolved OAuth error code make it onto spans or metrics.
package oauthtelem

import (
	"context"
	"strings"
	"time"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName identifies this instrumentation library in emitted telemetry.
const ScopeName = "github.com/RichardKnop/go-oauth2-server/telemetry/oauthtelem"

// Attribute keys used on both spans and metrics.
const (
	AttrGrantType     = "oauth.grant_type"
	AttrClientID      = "oauth.client_id"
	AttrScope         = "oauth.scope"
	AttrTokenType     = "oauth.token_type"
	AttrErrorCode     = "oauth.error_code"
	AttrOutcome       = "outcome"
	AttrTokenTypeHint = "oauth.token_type_hint"
	AttrActive        = "active"
)

// Outcome values used as the "outcome" label on counters and histograms.
const (
	OutcomeSuccess = "success"
	OutcomeError   = "error"
)

// Recorder buffers tracer + meter handles and the resolved
// IncludeClientID flag so handler code can stay terse. Construct via New;
// it's safe to share a Recorder across goroutines.
type Recorder struct {
	enabled         bool
	includeClientID bool

	tracer trace.Tracer

	issued        metric.Int64Counter
	refreshed     metric.Int64Counter
	revoked       metric.Int64Counter
	introspectReq metric.Int64Counter
	userinfoReq   metric.Int64Counter
	grantDuration metric.Float64Histogram
}

// New returns a Recorder. When cfg.Enabled is false the Recorder is a
// total no-op (its methods return immediately without touching OTel).
func New(cfg telemetry.Config) *Recorder {
	if !cfg.Enabled {
		return &Recorder{}
	}
	includeClient := true
	if cfg.OAuth.IncludeClientID != nil {
		includeClient = *cfg.OAuth.IncludeClientID
	}

	tracer := otel.Tracer(ScopeName)
	meter := otel.Meter(ScopeName)

	issued, _ := meter.Int64Counter(
		"oauth.token.issued",
		metric.WithDescription("Access tokens issued by the OAuth2 token endpoint."),
	)
	refreshed, _ := meter.Int64Counter(
		"oauth.token.refreshed",
		metric.WithDescription("Refresh token exchanges (refresh_token grant)."),
	)
	revoked, _ := meter.Int64Counter(
		"oauth.token.revoked",
		metric.WithDescription("Tokens revoked via the RFC 7009 endpoint."),
	)
	introspectReq, _ := meter.Int64Counter(
		"oauth.introspect.requests",
		metric.WithDescription("RFC 7662 token introspection requests."),
	)
	userinfoReq, _ := meter.Int64Counter(
		"oauth.userinfo.requests",
		metric.WithDescription("OpenID userinfo requests."),
	)
	grantDur, _ := meter.Float64Histogram(
		"oauth.grant.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Duration of an OAuth2 grant-type handler."),
	)

	return &Recorder{
		enabled:         true,
		includeClientID: includeClient,
		tracer:          tracer,
		issued:          issued,
		refreshed:       refreshed,
		revoked:         revoked,
		introspectReq:   introspectReq,
		userinfoReq:     userinfoReq,
		grantDuration:   grantDur,
	}
}

func (r *Recorder) startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !r.enabled {
		return ctx, noopSpan{}
	}
	return r.tracer.Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
}

// StartTokens opens the top-level "oauth.tokens" span around the
// dispatcher. Grant-specific child spans should be opened via StartGrant.
func (r *Recorder) StartTokens(ctx context.Context) (context.Context, trace.Span) {
	return r.startSpan(ctx, "oauth.tokens")
}

// StartGrant opens "oauth.grant.<grantType>" as a child of the current
// span. grantType is recorded as the oauth.grant_type attribute.
func (r *Recorder) StartGrant(ctx context.Context, grantType string) (context.Context, trace.Span) {
	return r.startSpan(ctx, "oauth.grant."+grantType, attribute.String(AttrGrantType, grantType))
}

// StartIntrospect opens "oauth.introspect".
func (r *Recorder) StartIntrospect(ctx context.Context) (context.Context, trace.Span) {
	return r.startSpan(ctx, "oauth.introspect")
}

// StartRevoke opens "oauth.revoke".
func (r *Recorder) StartRevoke(ctx context.Context) (context.Context, trace.Span) {
	return r.startSpan(ctx, "oauth.revoke")
}

// StartUserinfo opens "oauth.userinfo".
func (r *Recorder) StartUserinfo(ctx context.Context) (context.Context, trace.Span) {
	return r.startSpan(ctx, "oauth.userinfo")
}

// SetClient annotates span with oauth.client_id when the recorder is
// configured to include it. Empty clientID is a no-op.
func (r *Recorder) SetClient(span trace.Span, clientID string) {
	if !r.enabled || !r.includeClientID || clientID == "" {
		return
	}
	span.SetAttributes(attribute.String(AttrClientID, clientID))
}

// SetScope annotates span with oauth.scope. Empty scope is a no-op.
func (r *Recorder) SetScope(span trace.Span, scope string) {
	if !r.enabled || scope == "" {
		return
	}
	span.SetAttributes(attribute.String(AttrScope, scope))
}

// SetTokenType annotates span with oauth.token_type (e.g. "Bearer").
func (r *Recorder) SetTokenType(span trace.Span, tokenType string) {
	if !r.enabled || tokenType == "" {
		return
	}
	span.SetAttributes(attribute.String(AttrTokenType, tokenType))
}

// FinishWithError records err on span (if non-nil) with oauth.error_code
// and sets status to Error. End is NOT called — callers should still
// `defer span.End()`.
func (r *Recorder) FinishWithError(span trace.Span, err error, errCode string) {
	if !r.enabled || err == nil {
		return
	}
	if errCode != "" {
		span.SetAttributes(attribute.String(AttrErrorCode, errCode))
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

func (r *Recorder) addCounter(ctx context.Context, c metric.Int64Counter, attrs ...attribute.KeyValue) {
	if !r.enabled || c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenIssued bumps oauth.token.issued. Pass err=nil and errCode=""
// for the success path.
func (r *Recorder) RecordTokenIssued(ctx context.Context, grantType, clientID string, err error, errCode string) {
	r.addCounter(ctx, r.issued, r.tokenAttrs(grantType, clientID, err, errCode)...)
}

// RecordTokenRefreshed bumps oauth.token.refreshed for refresh_token grants.
func (r *Recorder) RecordTokenRefreshed(ctx context.Context, clientID string, err error, errCode string) {
	r.addCounter(ctx, r.refreshed, r.tokenAttrs("refresh_token", clientID, err, errCode)...)
}

// RecordTokenRevoked bumps oauth.token.revoked. tokenTypeHint may be
// "", "access_token", or "refresh_token" per RFC 7009.
func (r *Recorder) RecordTokenRevoked(ctx context.Context, clientID, tokenTypeHint string) {
	if !r.enabled {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String(AttrTokenTypeHint, tokenTypeHint),
	}
	if r.includeClientID && clientID != "" {
		attrs = append(attrs, attribute.String(AttrClientID, clientID))
	}
	r.addCounter(ctx, r.revoked, attrs...)
}

// RecordIntrospect bumps oauth.introspect.requests with the active flag.
func (r *Recorder) RecordIntrospect(ctx context.Context, clientID string, active bool, err error, errCode string) {
	if !r.enabled {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.Bool(AttrActive, active),
		attribute.String(AttrOutcome, outcome(err)),
	}
	if err != nil && errCode != "" {
		attrs = append(attrs, attribute.String(AttrErrorCode, errCode))
	}
	if r.includeClientID && clientID != "" {
		attrs = append(attrs, attribute.String(AttrClientID, clientID))
	}
	r.addCounter(ctx, r.introspectReq, attrs...)
}

// RecordUserinfo bumps oauth.userinfo.requests with outcome only.
func (r *Recorder) RecordUserinfo(ctx context.Context, err error, errCode string) {
	if !r.enabled {
		return
	}
	attrs := []attribute.KeyValue{attribute.String(AttrOutcome, outcome(err))}
	if err != nil && errCode != "" {
		attrs = append(attrs, attribute.String(AttrErrorCode, errCode))
	}
	r.addCounter(ctx, r.userinfoReq, attrs...)
}

// RecordGrantDuration records the elapsed time of a grant-type handler
// with grant_type + outcome (no client_id — cardinality + bucketing).
func (r *Recorder) RecordGrantDuration(ctx context.Context, grantType string, start time.Time, err error) {
	if !r.enabled || r.grantDuration == nil {
		return
	}
	elapsedMs := float64(time.Since(start)) / float64(time.Millisecond)
	r.grantDuration.Record(ctx, elapsedMs, metric.WithAttributes(
		attribute.String(AttrGrantType, grantType),
		attribute.String(AttrOutcome, outcome(err)),
	))
}

func (r *Recorder) tokenAttrs(grantType, clientID string, err error, errCode string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(AttrGrantType, grantType),
		attribute.String(AttrOutcome, outcome(err)),
	}
	if err != nil && errCode != "" {
		attrs = append(attrs, attribute.String(AttrErrorCode, errCode))
	}
	if r.includeClientID && clientID != "" {
		attrs = append(attrs, attribute.String(AttrClientID, clientID))
	}
	return attrs
}

func outcome(err error) string {
	if err == nil {
		return OutcomeSuccess
	}
	return OutcomeError
}

// JoinScopes is a convenience that mirrors the canonical OAuth scope
// representation: space-separated, deduplicated, trimmed.
func JoinScopes(scopes ...string) string {
	var nonEmpty []string
	seen := map[string]struct{}{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		nonEmpty = append(nonEmpty, s)
	}
	return strings.Join(nonEmpty, " ")
}

// noopSpan implements trace.Span for the disabled path so callers can
// uniformly defer span.End() without nil-checks. Every method is a no-op.
type noopSpan struct{ trace.Span }

func (noopSpan) End(...trace.SpanEndOption)              {}
func (noopSpan) AddEvent(string, ...trace.EventOption)   {}
func (noopSpan) AddLink(trace.Link)                      {}
func (noopSpan) IsRecording() bool                       { return false }
func (noopSpan) RecordError(error, ...trace.EventOption) {}
func (noopSpan) SpanContext() trace.SpanContext          { return trace.SpanContext{} }
func (noopSpan) SetStatus(codes.Code, string)            {}
func (noopSpan) SetName(string)                          {}
func (noopSpan) SetAttributes(...attribute.KeyValue)     {}
func (noopSpan) TracerProvider() trace.TracerProvider    { return otel.GetTracerProvider() }
