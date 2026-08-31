package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/neerajgurjar/goshield/internal/security"
)

func newBulkFixture(t *testing.T) (*BulkService, *fakeRepo, *fakeCache) {
	t.Helper()

	repo := &fakeRepo{}
	cache := newFakeCache()
	bulk := NewBulkService(NewScanService(repo, cache), 5, 10)
	bulk.Start(context.Background())
	t.Cleanup(bulk.Stop)

	return bulk, repo, cache
}

func TestScanAll_PreservesOrder(t *testing.T) {
	bulk, repo, _ := newBulkFixture(t)

	urls := []string{
		"https://a.example.com",
		"http://free-money-login.xyz/verify",
		"https://phishing-test.example",
		"https://d.example.com/account",
	}

	items, err := bulk.ScanAll(context.Background(), urls)
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	if len(items) != len(urls) {
		t.Fatalf("len(items) = %d, want %d", len(items), len(urls))
	}
	for i, want := range urls {
		if items[i].URL != want {
			t.Errorf("items[%d].URL = %q, want %q", i, items[i].URL, want)
		}
		if items[i].Err != nil {
			t.Errorf("items[%d].Err = %v", i, items[i].Err)
		}
		if items[i].Scan == nil {
			t.Fatalf("items[%d].Scan is nil", i)
		}
	}
	if repo.count() != len(urls) {
		t.Errorf("stored %d scans, want %d", repo.count(), len(urls))
	}
}

func TestScanAll_DuplicatesAreAccepted(t *testing.T) {
	bulk, repo, cache := newBulkFixture(t)

	// Duplicates inside one batch run concurrently, so which of them wins the
	// race to populate the cache is deliberately not asserted here.
	items, err := bulk.ScanAll(context.Background(), []string{
		"https://dup.example.com", "https://dup.example.com", "https://dup.example.com",
	})
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	for i, item := range items {
		if item.Scan == nil || item.Err != nil {
			t.Fatalf("items[%d] = %+v, want a successful scan", i, item)
		}
	}
	if repo.count() != 3 {
		t.Errorf("stored %d scans, want 3", repo.count())
	}
	if cache.writes() == 0 {
		t.Error("cache was never written")
	}
}

func TestScanAll_SecondBatchIsServedFromCache(t *testing.T) {
	bulk, _, _ := newBulkFixture(t)

	urls := []string{"https://batch.example.com/a", "https://batch.example.com/b"}

	first, err := bulk.ScanAll(context.Background(), urls)
	if err != nil {
		t.Fatalf("first ScanAll() error = %v", err)
	}
	for i, item := range first {
		if item.Scan.Cached {
			t.Errorf("first batch items[%d].Cached = true, want false", i)
		}
	}

	second, err := bulk.ScanAll(context.Background(), urls)
	if err != nil {
		t.Fatalf("second ScanAll() error = %v", err)
	}
	for i, item := range second {
		if !item.Scan.Cached {
			t.Errorf("second batch items[%d].Cached = false, want true", i)
		}
	}
}

func TestScanAll_InvalidURLDoesNotFailBatch(t *testing.T) {
	bulk, _, _ := newBulkFixture(t)

	items, err := bulk.ScanAll(context.Background(), []string{
		"https://good.example.com", "ftp://bad.example.com", "https://also-good.example.com",
	})
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	if items[0].Err != nil || items[2].Err != nil {
		t.Errorf("valid urls failed: %v / %v", items[0].Err, items[2].Err)
	}
	if !errors.Is(items[1].Err, security.ErrInvalidURL) {
		t.Errorf("items[1].Err = %v, want ErrInvalidURL", items[1].Err)
	}
	if items[1].Scan != nil {
		t.Error("items[1].Scan is set for an invalid url")
	}
}

func TestScanAll_AboveLimit(t *testing.T) {
	bulk, _, _ := newBulkFixture(t)

	urls := make([]string, MaxBulkURLs+1)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://example.com/%d", i)
	}
	if _, err := bulk.ScanAll(context.Background(), urls); err == nil {
		t.Fatal("ScanAll() error = nil, want a batch size error")
	}
}

func TestScanAll_FullBatch(t *testing.T) {
	bulk, repo, _ := newBulkFixture(t)

	urls := make([]string, MaxBulkURLs)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://example.com/%d", i)
	}

	items, err := bulk.ScanAll(context.Background(), urls)
	if err != nil {
		t.Fatalf("ScanAll() error = %v", err)
	}
	for i, item := range items {
		if item.URL != urls[i] {
			t.Fatalf("items[%d].URL = %q, want %q", i, item.URL, urls[i])
		}
	}
	if repo.count() != MaxBulkURLs {
		t.Errorf("stored %d scans, want %d", repo.count(), MaxBulkURLs)
	}
}

func TestScanAll_CancelledContext(t *testing.T) {
	bulk, _, _ := newBulkFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := bulk.ScanAll(ctx, []string{"https://example.com"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll() error = %v, want context.Canceled", err)
	}
}

func TestScanAll_AfterStop(t *testing.T) {
	bulk := NewBulkService(NewScanService(&fakeRepo{}, nil), 2, 2)
	bulk.Start(context.Background())
	bulk.Stop()

	if _, err := bulk.ScanAll(context.Background(), []string{"https://example.com"}); err == nil {
		t.Fatal("ScanAll() error = nil, want a stopped-pool error")
	}
}
