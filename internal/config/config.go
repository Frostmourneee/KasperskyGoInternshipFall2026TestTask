// Package config читает и проверяет настройки из переменных окружения.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

type Database struct {
	URL            string
	ConnectTimeout time.Duration
	MaxConns       int32
}

type Config struct {
	Database          Database
	APIKey            string
	HTTPAddr          string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	RequestTimeout    time.Duration
	ShutdownTimeout   time.Duration
	MaxBodyBytes      int64
	RateLimit         float64
	RateBurst         int
	LogLevel          slog.Level
}

func Load() (Config, error) {
	var cfg Config
	var err error
	cfg.Database, err = LoadDatabase()
	if err != nil {
		return cfg, err
	}
	cfg.APIKey = os.Getenv("API_KEY")
	if len(cfg.APIKey) < 32 || len(cfg.APIKey) > 512 {
		return cfg, errors.New("API_KEY must contain 32 to 512 printable ASCII characters without spaces")
	}
	for _, ch := range cfg.APIKey {
		if ch < '!' || ch > '~' {
			return cfg, errors.New("API_KEY must contain printable ASCII characters without spaces")
		}
	}
	cfg.HTTPAddr = value("HTTP_ADDR", "127.0.0.1:8080")
	_, port, err := net.SplitHostPort(cfg.HTTPAddr)
	if err != nil {
		return cfg, errors.New("HTTP_ADDR must be a host:port address")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return cfg, errors.New("HTTP_ADDR must use a port between 1 and 65535")
	}
	for _, setting := range []struct {
		name     string
		fallback time.Duration
		target   *time.Duration
	}{
		{"HTTP_READ_TIMEOUT", 5 * time.Second, &cfg.ReadTimeout},
		{"HTTP_READ_HEADER_TIMEOUT", 5 * time.Second, &cfg.ReadHeaderTimeout},
		{"HTTP_WRITE_TIMEOUT", 15 * time.Second, &cfg.WriteTimeout},
		{"HTTP_IDLE_TIMEOUT", 60 * time.Second, &cfg.IdleTimeout},
		{"REQUEST_TIMEOUT", 10 * time.Second, &cfg.RequestTimeout},
		{"SHUTDOWN_TIMEOUT", 10 * time.Second, &cfg.ShutdownTimeout},
	} {
		*setting.target, err = duration(setting.name, setting.fallback)
		if err != nil {
			return cfg, err
		}
	}
	if cfg.WriteTimeout <= cfg.RequestTimeout {
		return cfg, errors.New("HTTP_WRITE_TIMEOUT must exceed REQUEST_TIMEOUT")
	}
	cfg.MaxBodyBytes, err = integer("MAX_BODY_BYTES", 16384, 1, 1<<20)
	if err != nil {
		return cfg, err
	}
	burst, err := integer("RATE_BURST", 20, 1, math.MaxInt32)
	if err != nil {
		return cfg, err
	}
	cfg.RateBurst = int(burst)
	cfg.RateLimit, err = strconv.ParseFloat(value("RATE_LIMIT", "10"), 64)
	if err != nil || math.IsNaN(cfg.RateLimit) || math.IsInf(cfg.RateLimit, 0) || cfg.RateLimit <= 0 {
		return cfg, errors.New("RATE_LIMIT must be a positive finite number")
	}
	cfg.LogLevel, err = LoadLogLevel()
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadLogLevel() (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(value("LOG_LEVEL", "info"))); err != nil {
		return 0, errors.New("LOG_LEVEL must be a valid slog level")
	}
	return level, nil
}

// LoadDatabase позволяет запускать миграции без HTTP-настроек и API-ключа.
func LoadDatabase() (Database, error) {
	cfg := Database{URL: os.Getenv("DATABASE_URL")}
	if cfg.URL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	var err error
	cfg.ConnectTimeout, err = duration("DB_CONNECT_TIMEOUT", 10*time.Second)
	if err != nil {
		return cfg, err
	}
	maxConns, err := integer("DB_MAX_CONNS", 10, 1, math.MaxInt32)
	if err != nil {
		return cfg, err
	}
	cfg.MaxConns = int32(maxConns)
	return cfg, nil
}

func value(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	v, err := time.ParseDuration(value(name, fallback.String()))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return v, nil
}

func integer(name string, fallback, min, max int64) (int64, error) {
	v, err := strconv.ParseInt(value(name, strconv.FormatInt(fallback, 10)), 10, 64)
	if err != nil || v < min || v > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return v, nil
}
