package service

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/neerajgurjar/goshield/internal/model"
	"github.com/neerajgurjar/goshield/internal/repository"
	"github.com/neerajgurjar/goshield/internal/security"
)

// fakeRepo is an in-memory stand-in for the PostgreSQL repository. The real
// pgxpool is safe for concurrent use, so this one is too: the worker pool
// drives it from several goroutines at once.
type fakeRepo struct {
	mu        sync.Mutex
	stored    []*model.Scan
	createErr error
	getErr    error
	listErr   error
	gotFilter repository.ListFilter
}

func (f *fakeRepo) Create(_ context.Context, s *model.Scan) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.createErr != nil {
		return f.createErr
	}
	f.stored = append(f.stored, s)
	return nil
}

// count returns how many scans have been persisted.
func (f *fakeRepo) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stored)
}

func (f *fakeRepo) List(_ context.Context, filter repository.ListFilter) ([]*model.Scan, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	f.gotFilter = filter

	var matched []*model.Scan
	for _, s := range f.stored {
		if filter.RiskLevel != "" && string(s.RiskLevel) != filter.RiskLevel {
			continue
		}
		if filter.Status != "" && string(s.Status) != filter.Status {
			continue
		}
		if filter.Domain != "" && s.Domain != filter.Domain {
			continue
		}
		matched = append(matched, s)
	}

	total := len(matched)
	start := (filter.Page - 1) * filter.Limit
	if start > total {
		start = total
	}
	end := start + filter.Limit
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

func (f *fakeRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, s := range f.stored {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, repository.ErrNotFound
}

func TestScan(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewScanService(repo, nil)

	got, err := svc.Scan(context.Background(), "HTTP://Free-Money-Login.XYZ/verify")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if got.NormalizedURL != "http://free-money-login.xyz/verify" {
		t.Errorf("NormalizedURL = %q", got.NormalizedURL)
	}
	if got.Domain != "free-money-login.xyz" || got.Protocol != "http" {
		t.Errorf("domain/protocol = %q/%q", got.Domain, got.Protocol)
	}
	if got.RiskScore != 65 || got.RiskLevel != model.RiskLevelMedium || got.Status != model.StatusSuspicious {
		t.Errorf("verdict = %d/%s/%s, want 65/MEDIUM/SUSPICIOUS", got.RiskScore, got.RiskLevel, got.Status)
	}
	if got.Safe {
		t.Error("Safe = true, want false")
	}
	if got.Cached {
		t.Error("Cached = true, want false on a fresh scan")
	}
	if got.ID == uuid.Nil {
		t.Error("ID is the zero uuid")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if len(repo.stored) != 1 || repo.stored[0].ID != got.ID {
		t.Errorf("stored %d scans, want the returned scan persisted", len(repo.stored))
	}
}

func TestScan_InvalidURL(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewScanService(repo, nil)

	for _, raw := range []string{"", "not a url", "ftp://example.com"} {
		_, err := svc.Scan(context.Background(), raw)
		if !errors.Is(err, security.ErrInvalidURL) {
			t.Errorf("Scan(%q) error = %v, want ErrInvalidURL", raw, err)
		}
	}
	if len(repo.stored) != 0 {
		t.Errorf("stored %d scans, want none for invalid input", len(repo.stored))
	}
}

func TestScan_PersistFailurePropagates(t *testing.T) {
	svc := NewScanService(&fakeRepo{createErr: errors.New("db down")}, nil)

	if _, err := svc.Scan(context.Background(), "https://example.com"); err == nil {
		t.Fatal("Scan() error = nil, want the persistence error")
	}
}

func TestGetByID(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewScanService(repo, nil)

	created, err := svc.Scan(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	got, err := svc.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %s, want %s", got.ID, created.ID)
	}

	if _, err := svc.GetByID(context.Background(), uuid.New()); !errors.Is(err, ErrScanNotFound) {
		t.Errorf("GetByID(unknown) error = %v, want ErrScanNotFound", err)
	}
}

func TestList_DefaultsAndFilters(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewScanService(repo, nil)

	for _, raw := range []string{
		"https://example.com",                 // SAFE
		"http://free-money-login.xyz/verify",  // SUSPICIOUS
		"https://phishing-test.example/login", // BLOCKED
	} {
		if _, err := svc.Scan(context.Background(), raw); err != nil {
			t.Fatalf("Scan(%q) error = %v", raw, err)
		}
	}

	t.Run("defaults are applied", func(t *testing.T) {
		got, err := svc.List(context.Background(), ListQuery{})
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if repo.gotFilter.Page != DefaultPage || repo.gotFilter.Limit != DefaultLimit {
			t.Errorf("filter paging = %d/%d, want %d/%d",
				repo.gotFilter.Page, repo.gotFilter.Limit, DefaultPage, DefaultLimit)
		}
		if got.Total != 3 || len(got.Scans) != 3 {
			t.Errorf("total/len = %d/%d, want 3/3", got.Total, len(got.Scans))
		}
	})

	t.Run("limit is clamped to the maximum", func(t *testing.T) {
		if _, err := svc.List(context.Background(), ListQuery{Limit: 9999}); err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if repo.gotFilter.Limit != MaxLimit {
			t.Errorf("filter limit = %d, want %d", repo.gotFilter.Limit, MaxLimit)
		}
	})

	t.Run("risk level filter reaches the repository", func(t *testing.T) {
		got, err := svc.List(context.Background(), ListQuery{RiskLevel: "HIGH"})
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if got.Total != 1 {
			t.Errorf("total = %d, want 1", got.Total)
		}
		if repo.gotFilter.RiskLevel != "HIGH" {
			t.Errorf("filter risk level = %q", repo.gotFilter.RiskLevel)
		}
	})

	t.Run("paging past the end returns an empty page with the real total", func(t *testing.T) {
		got, err := svc.List(context.Background(), ListQuery{Page: 5, Limit: 2})
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(got.Scans) != 0 || got.Total != 3 {
			t.Errorf("len/total = %d/%d, want 0/3", len(got.Scans), got.Total)
		}
	})
}

func TestList_RepositoryFailure(t *testing.T) {
	svc := NewScanService(&fakeRepo{listErr: errors.New("db down")}, nil)
	if _, err := svc.List(context.Background(), ListQuery{}); err == nil {
		t.Fatal("List() error = nil, want the repository error")
	}
}

// fakeCache records calls and can be made to fail like a down Redis. Like the
// real client it must tolerate concurrent use.
type fakeCache struct {
	mu      sync.Mutex
	entries map[string]*model.Scan
	gets    int
	sets    int
	down    bool
}

// writes returns how many times Set was called.
func (f *fakeCache) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string]*model.Scan{}}
}

func (f *fakeCache) Get(_ context.Context, key string) (*model.Scan, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.gets++
	if f.down {
		return nil, false // a real cache logs and reports a miss
	}
	s, ok := f.entries[key]
	return s, ok
}

func (f *fakeCache) Set(_ context.Context, key string, s *model.Scan) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sets++
	if f.down {
		return
	}
	f.entries[key] = s
}

func TestScan_CacheMissThenHit(t *testing.T) {
	repo := &fakeRepo{}
	cache := newFakeCache()
	svc := NewScanService(repo, cache)

	first, err := svc.Scan(context.Background(), "https://example.com/login")
	if err != nil {
		t.Fatalf("first Scan() error = %v", err)
	}
	if first.Cached {
		t.Error("first scan Cached = true, want false")
	}
	if cache.sets != 1 {
		t.Errorf("cache writes = %d, want 1", cache.sets)
	}

	// Same URL in a different spelling: normalization must land on the same key.
	second, err := svc.Scan(context.Background(), "HTTPS://Example.com:443/login")
	if err != nil {
		t.Fatalf("second Scan() error = %v", err)
	}
	if !second.Cached {
		t.Error("second scan Cached = false, want true")
	}
	if second.RiskScore != first.RiskScore || second.RiskLevel != first.RiskLevel {
		t.Errorf("cached verdict = %d/%s, want %d/%s",
			second.RiskScore, second.RiskLevel, first.RiskScore, first.RiskLevel)
	}
	if !reflect.DeepEqual(second.Reasons, first.Reasons) {
		t.Errorf("cached reasons = %v, want %v", second.Reasons, first.Reasons)
	}
	if second.ID == first.ID {
		t.Error("cached hit reused the original scan id, want a new one")
	}
	if cache.sets != 1 {
		t.Errorf("cache writes = %d, want the hit not to rewrite the entry", cache.sets)
	}
	if len(repo.stored) != 2 {
		t.Errorf("stored %d scans, want the cache hit recorded in history too", len(repo.stored))
	}
}

func TestScan_CacheDownStillServes(t *testing.T) {
	repo := &fakeRepo{}
	cache := newFakeCache()
	cache.down = true
	svc := NewScanService(repo, cache)

	for i := 0; i < 2; i++ {
		got, err := svc.Scan(context.Background(), "https://example.org")
		if err != nil {
			t.Fatalf("Scan() error = %v with the cache down", err)
		}
		if got.Cached {
			t.Error("Cached = true, want false when the cache is unavailable")
		}
	}
	if len(repo.stored) != 2 {
		t.Errorf("stored %d scans, want 2", len(repo.stored))
	}
}

func TestScan_DifferentURLsDoNotShareCacheEntries(t *testing.T) {
	cache := newFakeCache()
	svc := NewScanService(&fakeRepo{}, cache)

	if _, err := svc.Scan(context.Background(), "https://example.com/a"); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	got, err := svc.Scan(context.Background(), "https://example.com/b")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got.Cached {
		t.Error("Cached = true for a different path, want false")
	}
}
