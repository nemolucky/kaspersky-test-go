package postgres_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	postgrescontainer "github.com/testcontainers/testcontainers-go/modules/postgres"

	dbpostgres "github.com/nemolucky/kaspersky-test-go/internal/adapter/postgres"

	"github.com/golang-migrate/migrate/v4"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func setupTestDB(t *testing.T) *dbpostgres.Postgres {
	t.Helper()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		60*time.Second,
	)
	defer cancel()

	container, err := postgrescontainer.Run(
		ctx,
		"postgres:18-alpine",
		postgrescontainer.WithDatabase("threats_test"),
		postgrescontainer.WithUsername("test"),
		postgrescontainer.WithPassword("test"),
		postgrescontainer.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Errorf("terminate container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(
		ctx,
		"sslmode=disable",
	)
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	applyMigrations(t, dsn)

	db, err := dbpostgres.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test postgres: %v", err)
	}

	t.Cleanup(db.Close)

	return db
}

func applyMigrations(t *testing.T, dsn string) {
	t.Helper()

	migrationsPath, err := filepath.Abs("../../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	sourceURL := "file://" + filepath.ToSlash(migrationsPath)

	m, err := migrate.New(sourceURL, dsn)
	if err != nil {
		t.Fatalf("initialize migrations: %v", err)
	}

	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil || databaseErr != nil {
			t.Errorf(
				"close migrations: source=%v, database=%v",
				sourceErr,
				databaseErr,
			)
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply migrations: %v", err)
	}
}
