// Package dbtelem opens an OTel-instrumented *sql.DB for the application's
// database connections. It is a thin convenience wrapper around
// github.com/XSAM/otelsql that:
//
//   - returns a plain (un-instrumented) *sql.DB when telemetry is disabled,
//     so the disabled path is identical to the pre-telemetry baseline;
//   - applies sensible defaults for go-oauth2-server (semconv 1.40 db.system
//     attribute, query captured by default with bind values never recorded);
//   - exposes RegisterPoolMetrics so callers can attach db.client.connections
//     gauges after the pool size has been configured.
//
// The returned *sql.DB is intended to be handed to GORM v1 via
// gorm.Open(dialect, sqlDB); GORM continues to drive the dialect-specific
// SQL while every driver call flows through the otelsql wrapper.
package dbtelem

import (
	"database/sql"
	"fmt"

	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/XSAM/otelsql"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Open opens a *sql.DB for driverName / dsn. When cfg.Enabled is true the
// connection is wrapped by otelsql with semconv attributes; otherwise a
// plain sql.Open is returned so disabled-telemetry deployments see zero
// behavioral change.
//
// dbSystem is one of the semconv db.system values ("postgresql", "sqlite",
// etc.) and is attached to every emitted span and metric so dashboards
// can split by backend.
func Open(cfg telemetry.Config, driverName, dsn, dbSystem string) (*sql.DB, error) {
	if !cfg.Enabled {
		return sql.Open(driverName, dsn)
	}

	opts := []otelsql.Option{
		otelsql.WithAttributes(semconv.DBSystemNameKey.String(dbSystem)),
		otelsql.WithSpanOptions(otelsql.SpanOptions{
			DisableQuery: cfg.Database.DisableStatement,
		}),
	}
	db, err := otelsql.Open(driverName, dsn, opts...)
	if err != nil {
		return nil, fmt.Errorf("dbtelem: open %s: %w", driverName, err)
	}
	return db, nil
}

// RegisterPoolMetrics attaches db.client.connections.* gauges to db. It is
// a no-op (returning nil) when telemetry is disabled.
//
// dbSystem and any extra attributes are added to every emitted measurement
// so multiple pools can be distinguished.
func RegisterPoolMetrics(cfg telemetry.Config, db *sql.DB, dbSystem string, extra ...attribute.KeyValue) error {
	if !cfg.Enabled {
		return nil
	}
	attrs := append([]attribute.KeyValue{semconv.DBSystemNameKey.String(dbSystem)}, extra...)
	if _, err := otelsql.RegisterDBStatsMetrics(db, otelsql.WithAttributes(attrs...)); err != nil {
		return fmt.Errorf("dbtelem: register pool metrics: %w", err)
	}
	return nil
}
