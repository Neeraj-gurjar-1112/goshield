// Command server starts the GoShield HTTP API.
//
//	@title			GoShield API
//	@version		1.0.0
//	@description	Offline URL security scanner. Every verdict is derived from the
//	@description	URL string alone: the service never sends traffic to the URL it is
//	@description	scanning, which keeps scans fast and rules out SSRF.
//	@description	Scans are cached in Redis and stored in PostgreSQL.
//	@host			localhost:8080
//	@BasePath		/
//	@schemes		http
//	@tag.name		scans
//	@tag.description	URL scanning and scan history
//	@tag.name		system
//	@tag.description	Health and metrics
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/neerajgurjar/goshield/docs" // generated swagger spec
	"github.com/neerajgurjar/goshield/internal/cache"
	"github.com/neerajgurjar/goshield/internal/config"
	"github.com/neerajgurjar/goshield/internal/handler"
	"github.com/neerajgurjar/goshield/internal/middleware"
	"github.com/neerajgurjar/goshield/internal/repository"
	"github.com/neerajgurjar/goshield/internal/service"
)

const (
	shutdownTimeout     = 10 * time.Second
	healthcheckTimeout  = 3 * time.Second
	dbConnectTimout     = 10 * time.Second
	cacheConnectTimeout = 3 * time.Second
)

func main() {
	// The distroless runtime image has no shell or curl, so the binary doubles
	// as its own container healthcheck.
	healthcheck := flag.Bool("healthcheck", false, "probe the local /health endpoint and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(probeHealth())
	}

	logger := slog.New(middleware.NewContextHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
	))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	pool, err := connectDB(cfg.DatabaseURL)
	if err != nil {
		logger.Error("database unavailable", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	logger.Info("connected to postgres")

	scanCache, err := connectCache(cfg, logger)
	if err != nil {
		logger.Error("invalid redis configuration", "error", err)
		os.Exit(1)
	}

	scanSvc := service.NewScanService(repository.NewScanRepository(pool), scanCache)

	bulkSvc := service.NewBulkService(scanSvc, cfg.WorkerCount, cfg.QueueSize)
	bulkSvc.Start(context.Background())
	defer bulkSvc.Stop()
	logger.Info("worker pool started", "workers", cfg.WorkerCount, "queue_size", cfg.QueueSize)

	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           newRouter(handler.NewScanHandler(scanSvc, bulkSvc), cfg, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := run(srv, cfg, logger); err != nil {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

// probeHealth performs the container healthcheck: GET /health against this
// process and report success as an exit code.
func probeHealth() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: invalid configuration:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()

	url := fmt.Sprintf("http://127.0.0.1:%d/health", cfg.AppPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", res.StatusCode)
		return 1
	}
	return 0
}

// connectDB opens the pool and verifies the database is actually reachable, so
// the process fails fast instead of on the first request.
func connectDB(dsn string) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbConnectTimout)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// connectCache builds the Redis-backed cache. An unreachable Redis is logged
// and tolerated: the cache reports misses and the API keeps serving.
func connectCache(cfg config.Config, logger *slog.Logger) (*cache.ScanCache, error) {
	client, err := cache.NewClient(cfg.RedisURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cacheConnectTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		logger.Warn("redis unavailable at startup, running without cache", "error", err)
	} else {
		logger.Info("connected to redis", "cache_ttl", cfg.CacheTTL.String())
	}
	return cache.NewScanCache(client, cfg.CacheTTL), nil
}

// run starts the HTTP server and blocks until a termination signal arrives,
// then shuts the server down gracefully.
func run(srv *http.Server, cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", srv.Addr, "env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections", "timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("graceful shutdown complete")
	return nil
}

// newRouter wires the middleware chain and the HTTP routes served by the API.
func newRouter(scans *handler.ScanHandler, cfg config.Config, logger *slog.Logger) http.Handler {
	health := handler.NewHealthHandler()
	metricsHandler := handler.NewMetricsHandler()
	limiter := middleware.NewRateLimiter(cfg.RateLimit, cfg.RateLimitWindow)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.CORS(cfg.CORSOrigins))
	r.Use(middleware.Logger(logger))
	r.Use(middleware.Recovery(logger))
	r.Use(limiter.Middleware)

	r.Get("/health", health.Health)
	r.Get("/metrics", metricsHandler.Metrics)

	// Swagger UI at /swagger/index.html, spec at /swagger/doc.json.
	r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL("/swagger/doc.json")))

	r.Route("/api/v1", func(api chi.Router) {
		api.Post("/scan", scans.Scan)
		api.Post("/scans/bulk", scans.Bulk)
		api.Get("/scans", scans.List)
		api.Get("/scans/{id}", scans.GetByID)
	})
	return r
}
