package service

import (
	"context"
	"fmt"

	"github.com/neerajgurjar/goshield/backend/internal/model"
	"github.com/neerajgurjar/goshield/backend/internal/worker"
)

// MaxBulkURLs is the largest batch a single bulk request may carry.
const MaxBulkURLs = 100

// BulkItem is the outcome of one URL in a bulk request. Exactly one of Scan and
// Err is set, so a single bad URL does not fail the whole batch.
type BulkItem struct {
	URL  string
	Scan *model.Scan
	Err  error
}

// BulkService scans batches of URLs through a bounded worker pool.
type BulkService struct {
	pool *worker.Pool[string, BulkItem]
}

// NewBulkService builds a bulk scanner backed by its own worker pool. Call
// Start before use and Stop on shutdown.
func NewBulkService(scanner *ScanService, workers, queueSize int) *BulkService {
	return &BulkService{
		pool: worker.NewPool(workers, queueSize, func(ctx context.Context, url string) BulkItem {
			scan, err := scanner.Scan(ctx, url)
			return BulkItem{URL: url, Scan: scan, Err: err}
		}),
	}
}

// Start launches the worker pool.
func (b *BulkService) Start(ctx context.Context) { b.pool.Start(ctx) }

// Stop drains the worker pool and waits for the workers to exit.
func (b *BulkService) Stop() { b.pool.Stop() }

// ScanAll scans every URL and returns the results in input order. Duplicate
// URLs are allowed; the later ones are served from cache.
func (b *BulkService) ScanAll(ctx context.Context, urls []string) ([]BulkItem, error) {
	if len(urls) > MaxBulkURLs {
		return nil, fmt.Errorf("bulk scan accepts at most %d urls, got %d", MaxBulkURLs, len(urls))
	}

	items, err := b.pool.Submit(ctx, urls)
	if err != nil {
		return nil, fmt.Errorf("bulk scan: %w", err)
	}
	return items, nil
}
