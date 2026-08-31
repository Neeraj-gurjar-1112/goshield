// Package cache stores completed scan results in Redis so repeat lookups skip
// the scanner entirely. The cache is an accelerator, never a source of truth:
// every error is reported to the caller as a miss and logged, so a Redis
// outage degrades performance instead of breaking the API.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/neerajgurjar/goshield/backend/internal/model"
)

// keyPrefix namespaces every key this service owns in Redis.
const keyPrefix = "goshield:scan:"

// ScanCache reads and writes scan results in Redis.
type ScanCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewScanCache builds a cache over an existing Redis client.
func NewScanCache(client *redis.Client, ttl time.Duration) *ScanCache {
	return &ScanCache{client: client, ttl: ttl}
}

// NewClient parses a redis:// URL and returns a client. It does not connect;
// call Ping to check reachability.
func NewClient(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	return redis.NewClient(opts), nil
}

// Key returns the cache key for a normalized URL.
func Key(normalizedURL string) string {
	sum := sha256.Sum256([]byte(normalizedURL))
	return keyPrefix + hex.EncodeToString(sum[:])
}

// Get returns the cached scan for a normalized URL. A miss, a malformed entry
// and an unreachable Redis all return (nil, false): callers treat every one of
// them as "scan it again".
func (c *ScanCache) Get(ctx context.Context, normalizedURL string) (*model.Scan, bool) {
	raw, err := c.client.Get(ctx, Key(normalizedURL)).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.WarnContext(ctx, "cache lookup failed, continuing without cache",
				"error", err, "normalized_url", normalizedURL)
		}
		return nil, false
	}

	var scan model.Scan
	if err := json.Unmarshal(raw, &scan); err != nil {
		slog.WarnContext(ctx, "discarding malformed cache entry",
			"error", err, "normalized_url", normalizedURL)
		return nil, false
	}
	return &scan, true
}

// Set stores a scan result under its normalized URL. Failures are logged and
// swallowed: a write that does not land only costs a future cache miss.
func (c *ScanCache) Set(ctx context.Context, normalizedURL string, scan *model.Scan) {
	payload, err := json.Marshal(scan)
	if err != nil {
		slog.WarnContext(ctx, "failed to encode scan for cache", "error", err)
		return
	}
	if err := c.client.Set(ctx, Key(normalizedURL), payload, c.ttl).Err(); err != nil {
		slog.WarnContext(ctx, "cache write failed, continuing without cache",
			"error", err, "normalized_url", normalizedURL)
	}
}
