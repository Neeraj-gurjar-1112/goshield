// Package config loads and validates application configuration from environment
// variables. Nothing else in the app reads os.Getenv directly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every tunable value for the server. It is built once at startup
// and passed down by constructor injection.
type Config struct {
	AppEnv          string
	AppPort         int
	DatabaseURL     string
	RedisURL        string
	WorkerCount     int
	QueueSize       int
	CacheTTL        time.Duration
	RateLimit       int
	RateLimitWindow time.Duration
	CORSOrigins     []string
}

// Addr returns the listen address for the HTTP server.
func (c Config) Addr() string {
	return fmt.Sprintf(":%d", c.AppPort)
}

// Load reads configuration from the environment, applying defaults and failing
// fast when a value is present but unusable.
func Load() (Config, error) {
	cfg := Config{
		AppEnv:      env("APP_ENV", "development"),
		DatabaseURL: env("DATABASE_URL", "postgres://goshield:goshield@localhost:5432/goshield?sslmode=disable"),
		RedisURL:    env("REDIS_URL", "redis://localhost:6379"),
		// The dashboard runs on its own origin: nginx in compose, the Vite dev
		// server locally.
		CORSOrigins: splitList(env("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")),
	}

	var err error
	if cfg.AppPort, err = intEnv("APP_PORT", 8080, 1, 65535); err != nil {
		return Config{}, err
	}
	if cfg.WorkerCount, err = intEnv("WORKER_COUNT", 10, 1, 1024); err != nil {
		return Config{}, err
	}
	if cfg.QueueSize, err = intEnv("QUEUE_SIZE", 100, 1, 100000); err != nil {
		return Config{}, err
	}
	ttl, err := intEnv("CACHE_TTL_SECONDS", 3600, 1, 86400*7)
	if err != nil {
		return Config{}, err
	}
	cfg.CacheTTL = time.Duration(ttl) * time.Second

	if cfg.RateLimit, err = intEnv("RATE_LIMIT", 100, 1, 1000000); err != nil {
		return Config{}, err
	}
	window, err := intEnv("RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimitWindow = time.Duration(window) * time.Second

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL must not be empty")
	}
	if cfg.RedisURL == "" {
		return Config{}, fmt.Errorf("config: REDIS_URL must not be empty")
	}
	return cfg, nil
}

// splitList parses a comma separated env var into trimmed, non-empty values.
func splitList(raw string) []string {
	parts := strings.Split(raw, ",")

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback, min, max int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, raw)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("config: %s must be between %d and %d, got %d", key, min, max, v)
	}
	return v, nil
}
