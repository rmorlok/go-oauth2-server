package database

import (
	"fmt"
	"time"

	"github.com/RichardKnop/go-oauth2-server/config"
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
func NewDatabase(cnf *config.Config) (*gorm.DB, error) {
	// Postgres
	if cnf.Database.Type == "postgres" {
		// Connection args
		// see https://godoc.org/github.com/lib/pq#hdr-Connection_String_Parameters
		args := fmt.Sprintf(
			"sslmode=disable host=%s port=%d user=%s password='%s' dbname=%s",
			cnf.Database.Host,
			cnf.Database.Port,
			cnf.Database.User,
			cnf.Database.Password,
			cnf.Database.DatabaseName,
		)

		db, err := gorm.Open(cnf.Database.Type, args)
		if err != nil {
			return db, err
		}

		// Max idle connections
		db.DB().SetMaxIdleConns(cnf.Database.MaxIdleConns)

		// Max open connections
		db.DB().SetMaxOpenConns(cnf.Database.MaxOpenConns)

		// Database logging
		db.LogMode(cnf.IsDevelopment)

		return db, nil
	}

	// SQLite
	if cnf.Database.Type == "sqlite3" {
		// cnf.Database.DatabaseName carries the file path or ":memory:"
		db, err := gorm.Open("sqlite3", cnf.Database.DatabaseName)
		if err != nil {
			return db, err
		}

		// Enforce foreign keys in SQLite (off by default)
		if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return db, err
		}

		// SQLite serializes writes anyway; with ":memory:" each pooled
		// connection would also get its own private database, which makes
		// concurrent test traffic see partial state. Cap the pool at 1 so
		// every query lands on the same connection and the same DB.
		db.DB().SetMaxOpenConns(1)

		db.LogMode(cnf.IsDevelopment)
		return db, nil
	}

	// Database type not supported
	return nil, fmt.Errorf("Database type %s not suppported", cnf.Database.Type)
}
