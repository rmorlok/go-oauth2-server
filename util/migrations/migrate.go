package migrations

import (
	"fmt"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/jinzhu/gorm"
)

// MigrationStage ...
type MigrationStage struct {
	Name     string
	Function func(db *gorm.DB, name string) error
}

// Migrate ...
func Migrate(db *gorm.DB, migrations []MigrationStage) error {
	for _, m := range migrations {
		if MigrationExists(db, m.Name) {
			continue
		}

		if err := m.Function(db, m.Name); err != nil {
			return err
		}

		if err := SaveMigration(db, m.Name); err != nil {
			return err
		}
	}

	return nil
}

// MigrateAll runs bootstrap, then all migration functions listed against
// the specified database and logs any errors
func MigrateAll(db *gorm.DB, migrationFunctions []func(*gorm.DB) error) {
	if err := Bootstrap(db); err != nil {
		log.Error("migration bootstrap failed", "err", err)
	}

	for _, m := range migrationFunctions {
		if err := m(db); err != nil {
			log.Error("migration step failed", "err", err)
		}
	}
}

// MigrationExists checks if the migration called migrationName has been run already
func MigrationExists(db *gorm.DB, migrationName string) bool {
	migration := new(Migration)
	found := !db.Where("name = ?", migrationName).First(migration).RecordNotFound()

	if found {
		log.Info("skipping migration", "name", migrationName)
	} else {
		log.Info("running migration", "name", migrationName)
	}

	return found
}

// SaveMigration saves a migration to the migration table
func SaveMigration(db *gorm.DB, migrationName string) error {
	migration := new(Migration)
	migration.Name = migrationName

	if err := db.Create(migration).Error; err != nil {
		log.Error("save migration record failed", "name", migrationName, "err", err)
		return fmt.Errorf("Error saving record to migrations table: %s", err)
	}

	return nil
}
