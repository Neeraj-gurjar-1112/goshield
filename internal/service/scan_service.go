// Package service contains the application logic that ties the scanner engine
// to storage.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/neerajgurjar/goshield/internal/metrics"
	"github.com/neerajgurjar/goshield/internal/model"
	"github.com/neerajgurjar/goshield/internal/repository"
	"github.com/neerajgurjar/goshield/internal/security"
)

// ErrScanNotFound is returned when a scan id matches nothing.
var ErrScanNotFound = errors.New("scan not found")

// ScanRepository is the persistence surface the service needs. Declaring it
// here keeps the service testable without a database.
type ScanRepository interface {
	Create(ctx context.Context, s *model.Scan) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Scan, error)
	List(ctx context.Context, f repository.ListFilter) ([]*model.Scan, int, error)
}

// ScanCache is the caching surface the service needs. Every method is
// best-effort: a cache that is down reports misses rather than errors.
type ScanCache interface {
	Get(ctx context.Context, normalizedURL string) (*model.Scan, bool)
	Set(ctx context.Context, normalizedURL string, scan *model.Scan)
}

// noopCache is used when the service is built without a cache.
type noopCache struct{}

func (noopCache) Get(context.Context, string) (*model.Scan, bool) { return nil, false }
func (noopCache) Set(context.Context, string, *model.Scan)        {}

// ScanService orchestrates parse, score and persist for a URL.
type ScanService struct {
	repo  ScanRepository
	cache ScanCache
	now   func() time.Time
}

// NewScanService builds a ScanService. A nil cache disables caching.
func NewScanService(repo ScanRepository, cache ScanCache) *ScanService {
	if cache == nil {
		cache = noopCache{}
	}
	return &ScanService{repo: repo, cache: cache, now: time.Now}
}

// Scan analyses a URL and stores the result. Parse failures are returned
// wrapped in security.ErrInvalidURL so the handler can map them to
// INVALID_URL.
//
// A cache hit skips the scanner but is still recorded as its own scan, so the
// history and metrics reflect every request that was served.
func (s *ScanService) Scan(ctx context.Context, rawURL string) (*model.Scan, error) {
	start := time.Now()

	parsed, err := security.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}

	scan, fromCache := s.scanFromCache(ctx, parsed, start)
	if !fromCache {
		scan = s.scanFresh(parsed, start)
	}

	if err := s.repo.Create(ctx, scan); err != nil {
		return nil, fmt.Errorf("persist scan: %w", err)
	}
	if !fromCache {
		s.cache.Set(ctx, parsed.Normalized, scan)
	}
	recordMetrics(scan)
	return scan, nil
}

// recordMetrics updates the counters served by GET /metrics.
func recordMetrics(scan *model.Scan) {
	metrics.ScansTotal.Inc()
	if scan.Safe {
		metrics.ScansSafe.Inc()
	}
	if scan.Status == model.StatusBlocked {
		metrics.ScansBlocked.Inc()
	}
	metrics.ScanDuration.Observe(scan.ScanTimeMs)
}

// scanFromCache builds a scan from a cached verdict for the same normalized
// URL. It reports whether the cache actually had one.
func (s *ScanService) scanFromCache(ctx context.Context, parsed security.ParsedURL, start time.Time) (*model.Scan, bool) {
	hit, ok := s.cache.Get(ctx, parsed.Normalized)
	if !ok {
		return nil, false
	}
	metrics.CacheHits.Inc()

	scan := s.newScan(parsed)
	scan.Safe = hit.Safe
	scan.RiskScore = hit.RiskScore
	scan.RiskLevel = hit.RiskLevel
	scan.Status = hit.Status
	scan.Reasons = hit.Reasons
	if scan.Reasons == nil {
		scan.Reasons = []string{}
	}
	scan.Cached = true
	scan.ScanTimeMs = time.Since(start).Milliseconds()
	return scan, true
}

// scanFresh runs the scanner engine over a parsed URL.
func (s *ScanService) scanFresh(parsed security.ParsedURL, start time.Time) *model.Scan {
	assessment := security.Assess(parsed)

	scan := s.newScan(parsed)
	scan.Safe = assessment.Safe
	scan.RiskScore = assessment.Score
	scan.RiskLevel = assessment.Level
	scan.Status = assessment.Status
	scan.Reasons = assessment.Reasons
	scan.Cached = false
	scan.ScanTimeMs = time.Since(start).Milliseconds()
	return scan
}

// newScan fills in the identity and URL fields shared by cached and fresh
// results.
func (s *ScanService) newScan(parsed security.ParsedURL) *model.Scan {
	return &model.Scan{
		ID:            uuid.New(),
		URL:           parsed.Raw,
		NormalizedURL: parsed.Normalized,
		Domain:        parsed.Domain(),
		Protocol:      parsed.Scheme,
		CreatedAt:     s.now().UTC(),
	}
}

// GetByID returns a previously stored scan.
func (s *ScanService) GetByID(ctx context.Context, id uuid.UUID) (*model.Scan, error) {
	scan, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrScanNotFound
		}
		return nil, fmt.Errorf("load scan: %w", err)
	}
	return scan, nil
}

// ListQuery describes a page of scan history to return.
type ListQuery struct {
	Page      int
	Limit     int
	RiskLevel string
	Status    string
	Domain    string
	From      *time.Time
	To        *time.Time
}

// ListResult is a page of scans plus the total row count for the filter.
type ListResult struct {
	Scans []*model.Scan
	Total int
}

// Defaults applied to a listing when the caller omits paging.
const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
)

// List returns a page of scan history, newest first.
func (s *ScanService) List(ctx context.Context, q ListQuery) (ListResult, error) {
	if q.Page < 1 {
		q.Page = DefaultPage
	}
	if q.Limit < 1 {
		q.Limit = DefaultLimit
	}
	if q.Limit > MaxLimit {
		q.Limit = MaxLimit
	}

	scans, total, err := s.repo.List(ctx, repository.ListFilter{
		Page:      q.Page,
		Limit:     q.Limit,
		RiskLevel: q.RiskLevel,
		Status:    q.Status,
		Domain:    q.Domain,
		From:      q.From,
		To:        q.To,
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list scans: %w", err)
	}
	return ListResult{Scans: scans, Total: total}, nil
}
