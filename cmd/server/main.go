package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/config"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/storage/postgres"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/transport/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		// Ошибка парсера может содержать строку подключения с паролем.
		return errors.New("invalid DATABASE_URL")
	}
	poolConfig.MaxConns = cfg.Database.MaxConns
	poolConfig.ConnConfig.ConnectTimeout = cfg.Database.ConnectTimeout
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("create database pool: %w", err)
	}
	defer pool.Close()
	connectCtx, cancel := context.WithTimeout(ctx, cfg.Database.ConnectTimeout)
	err = pool.Ping(connectCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	service := threat.NewService(postgres.New(pool))
	handler, err := httpapi.New(service, httpapi.Options{
		APIKey: cfg.APIKey, MaxBodyBytes: cfg.MaxBodyBytes,
		RateLimit: cfg.RateLimit, RateBurst: cfg.RateBurst,
		RequestTimeout: cfg.RequestTimeout,
	}, logger)
	if err != nil {
		return fmt.Errorf("create HTTP handler: %w", err)
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadTimeout: cfg.ReadTimeout, ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("server starting", "address", cfg.HTTPAddr)
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Info("server shutting down")
	}
	// Текущие запросы завершаются до закрытия пула соединений.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("shut down HTTP server: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.Info("server stopped")
	return nil
}
