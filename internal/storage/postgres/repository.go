// Package postgres реализует хранение угроз в PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/storage/postgres/sqlc"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
)

// Repository выполняет типизированные параметризованные SQL-запросы.
type Repository struct {
	queries *db.Queries
}

var _ threat.Repository = (*Repository)(nil)

// New создаёт хранилище поверх общего пула соединений.
func New(pool *pgxpool.Pool) *Repository {
	return &Repository{queries: db.New(pool)}
}

func (r *Repository) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	row, err := r.queries.GetThreat(ctx, md5)
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	if err != nil {
		return threat.Threat{}, fmt.Errorf("get threat: %w", err)
	}
	return toThreat(row), nil
}

func (r *Repository) Create(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	row, err := r.queries.CreateThreat(ctx, db.CreateThreatParams{
		Md5:         md5,
		Name:        input.Name,
		Description: input.Description,
		ThreatType:  input.ThreatType,
		Severity:    input.Severity,
		FileSize:    input.FileSize,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threats_pkey" {
		return threat.Threat{}, threat.ErrConflict
	}
	if err != nil {
		return threat.Threat{}, fmt.Errorf("create threat: %w", err)
	}
	return toThreat(row), nil
}

func (r *Repository) Update(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	row, err := r.queries.UpdateThreat(ctx, db.UpdateThreatParams{
		Md5:         md5,
		Name:        input.Name,
		Description: input.Description,
		ThreatType:  input.ThreatType,
		Severity:    input.Severity,
		FileSize:    input.FileSize,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	if err != nil {
		return threat.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return toThreat(row), nil
}

func toThreat(row db.Threat) threat.Threat {
	return threat.Threat{
		MD5:         row.Md5,
		Name:        row.Name,
		Description: row.Description,
		ThreatType:  row.ThreatType,
		Severity:    row.Severity,
		FileSize:    row.FileSize,
		CreatedAt:   row.CreatedAt.UTC(),
		UpdatedAt:   row.UpdatedAt.UTC(),
	}
}
