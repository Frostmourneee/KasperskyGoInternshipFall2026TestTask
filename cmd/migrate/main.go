package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/config"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	level, err := config.LoadLogLevel()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], logger); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	if len(args) != 1 || (args[0] != "up" && args[0] != "down" && args[0] != "status") {
		return errors.New("usage: migrate up|down|status")
	}
	cfg, err := config.LoadDatabase()
	if err != nil {
		return err
	}
	connConfig, err := pgx.ParseConfig(cfg.URL)
	if err != nil {
		return errors.New("invalid DATABASE_URL")
	}
	connConfig.ConnectTimeout = cfg.ConnectTimeout
	db := stdlib.OpenDB(*connConfig)
	defer db.Close()
	db.SetMaxOpenConns(1)
	connectCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	err = db.PingContext(connectCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	// Блокировка исключает одновременное применение миграций разными процессами.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithSessionLocker(locker), goose.WithSlog(logger))
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()
	switch args[0] {
	case "up":
		_, err = provider.Up(ctx)
	case "down":
		_, err = provider.Down(ctx)
	case "status":
		statuses, statusErr := provider.Status(ctx)
		if statusErr != nil {
			return statusErr
		}
		for _, status := range statuses {
			logger.Info("migration status", "version", status.Source.Version, "state", status.State)
		}
	}
	if err != nil {
		return err
	}
	logger.Info("migration command completed", "command", args[0])
	return nil
}
