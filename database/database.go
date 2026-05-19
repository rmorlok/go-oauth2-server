package database

import (
	"fmt"
	"time"

	"github.com/RichardKnop/go-oauth2-server/config"
	"github.com/RichardKnop/go-oauth2-server/telemetry/dbtelem"
	"github.com/jinzhu/gorm"

	// Drivers
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func init() {
	gorm.NowFunc = func() time.Time {
		return time.Now().UTC()
	}
}

// NewDatabase returns a gorm.DB struct, gorm.DB.DB() returns a database handle
// see http://golang.org/pkg/database/sql/#DB
//
// Connection opening goes through telemetry/dbtelem so every SQL call flows
// through an OTel-instrumented wrapper when cnf.Telemetry.Enabled is true.
// GORM v1 accepts a *sql.DB as its source, so the wrapper sits transparently
// beneath the dialect-specific SQL generator.
func NewDatabase(cnf *config.Config) (*gorm.DB, error) {
	switch cnf.Database.Type {
	case "postgres":
		// see https://godoc.org/github.com/lib/pq#hdr-Connection_String_Parameters
		args := fmt.Sprintf(
			"sslmode=disable host=%s port=%d user=%s password='%s' dbname=%s",
			cnf.Database.Host,
			cnf.Database.Port,
			cnf.Database.User,
			cnf.Database.Password,
			cnf.Database.DatabaseName,
		)

		sqlDB, err := dbtelem.Open(cnf.Telemetry, "postgres", args, "postgresql")
		if err != nil {
			return nil, err
		}

		db, err := gorm.Open("postgres", sqlDB)
		if err != nil {
			return db, err
		}

		db.DB().SetMaxIdleConns(cnf.Database.MaxIdleConns)
		db.DB().SetMaxOpenConns(cnf.Database.MaxOpenConns)
		db.LogMode(cnf.IsDevelopment)

		if err := dbtelem.RegisterPoolMetrics(cnf.Telemetry, db.DB(), "postgresql"); err != nil {
			return db, err
		}
		return db, nil

	case "sqlite3":
		// cnf.Database.DatabaseName carries the file path or ":memory:"
		sqlDB, err := dbtelem.Open(cnf.Telemetry, "sqlite3", cnf.Database.DatabaseName, "sqlite")
		if err != nil {
			return nil, err
		}

		// SQLite serializes writes anyway; with ":memory:" each pooled
		// connection would also get its own private database, which makes
		// concurrent test traffic see partial state. Cap the pool at 1
		// before any query lands so PRAGMA and migrations share the DB.
		sqlDB.SetMaxOpenConns(1)

		db, err := gorm.Open("sqlite3", sqlDB)
		if err != nil {
			return db, err
		}

		// Enforce foreign keys in SQLite (off by default)
		if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return db, err
		}

		db.LogMode(cnf.IsDevelopment)

		if err := dbtelem.RegisterPoolMetrics(cnf.Telemetry, db.DB(), "sqlite"); err != nil {
			return db, err
		}
		return db, nil
	}

	return nil, fmt.Errorf("Database type %s not suppported", cnf.Database.Type)
}
