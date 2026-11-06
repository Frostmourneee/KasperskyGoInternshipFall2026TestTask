//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/storage/postgres"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/migrations"
)

func TestRepositoryIntegration(t *testing.T) {
	repository := newTestRepository(t)
	ctx := t.Context()
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	const missingMD5 = "00000000000000000000000000000000"
	size := int64(0)
	input := threat.Input{
		Name: "sample'; DROP TABLE threats; --", Description: "Example threat",
		ThreatType: "trojan", Severity: "low", FileSize: &size,
	}

	created, err := repository.Create(ctx, md5, input)
	if err != nil {
		t.Fatalf("create threat: %v", err)
	}
	if created.MD5 != md5 || created.Name != input.Name || created.Description != input.Description ||
		created.ThreatType != input.ThreatType || created.Severity != input.Severity ||
		created.FileSize == nil || *created.FileSize != 0 {
		t.Fatalf("unexpected created threat: %+v", created)
	}
	if created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("unexpected creation timestamps: %+v", created)
	}
	fetched, err := repository.Get(ctx, md5)
	if err != nil || !reflect.DeepEqual(fetched, created) {
		t.Fatalf("get threat: got %+v, error %v; want %+v", fetched, err, created)
	}
	if _, err := repository.Create(ctx, md5, input); !errors.Is(err, threat.ErrConflict) {
		t.Fatalf("duplicate create: got %v, want ErrConflict", err)
	}
	if _, err := repository.Get(ctx, missingMD5); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing get: got %v, want ErrNotFound", err)
	}
	if _, err := repository.Update(ctx, missingMD5, input); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing update: got %v, want ErrNotFound", err)
	}

	unchanged, err := repository.Update(ctx, md5, input)
	if err != nil || !reflect.DeepEqual(unchanged, created) {
		t.Fatalf("identical update: got %+v, error %v; want %+v", unchanged, err, created)
	}
	replacement := threat.Input{Name: "Updated threat", ThreatType: "unknown", Severity: "unknown"}
	updated, err := repository.Update(ctx, md5, replacement)
	if err != nil {
		t.Fatalf("update threat: %v", err)
	}
	if updated.MD5 != md5 || updated.Name != replacement.Name || updated.Description != "" ||
		updated.ThreatType != "unknown" || updated.Severity != "unknown" || updated.FileSize != nil ||
		!updated.CreatedAt.Equal(created.CreatedAt) || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("unexpected updated threat: %+v", updated)
	}
	fetched, err = repository.Get(ctx, md5)
	if err != nil || !reflect.DeepEqual(fetched, updated) {
		t.Fatalf("get updated threat: got %+v, error %v; want %+v", fetched, err, updated)
	}
}

func newTestRepository(t *testing.T) *postgres.Repository {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL must point to a PostgreSQL test database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	// Отдельная схема изолирует тест и не затрагивает существующие данные.
	schema := pgx.Identifier{"test_threats_" + rand.Text()}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatalf("create migration provider: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("apply test migrations: %v", err)
	}
	return postgres.New(pool)
}
