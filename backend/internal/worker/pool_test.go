package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubmit_PreservesInputOrder(t *testing.T) {
	// Reverse the natural completion order: later inputs finish first.
	pool := NewPool(4, 8, func(_ context.Context, n int) string {
		time.Sleep(time.Duration(20-n) * time.Millisecond)
		return fmt.Sprintf("job-%d", n)
	})
	pool.Start(context.Background())
	defer pool.Stop()

	inputs := make([]int, 20)
	for i := range inputs {
		inputs[i] = i
	}

	got, err := pool.Submit(context.Background(), inputs)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if len(got) != len(inputs) {
		t.Fatalf("len(results) = %d, want %d", len(got), len(inputs))
	}
	for i, want := range inputs {
		if got[i] != fmt.Sprintf("job-%d", want) {
			t.Errorf("results[%d] = %q, want %q", i, got[i], fmt.Sprintf("job-%d", want))
		}
	}
}

func TestSubmit_EmptyBatch(t *testing.T) {
	pool := NewPool(2, 2, func(_ context.Context, n int) int { return n })
	pool.Start(context.Background())
	defer pool.Stop()

	got, err := pool.Submit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(results) = %d, want 0", len(got))
	}
}

func TestSubmit_ConcurrentBatches(t *testing.T) {
	var handled atomic.Int64
	pool := NewPool(5, 4, func(_ context.Context, n int) int {
		handled.Add(1)
		return n * 2
	})
	pool.Start(context.Background())
	defer pool.Stop()

	const batches, size = 8, 25

	var wg sync.WaitGroup
	wg.Add(batches)
	errs := make(chan error, batches)

	for b := 0; b < batches; b++ {
		go func(b int) {
			defer wg.Done()

			inputs := make([]int, size)
			for i := range inputs {
				inputs[i] = b*size + i
			}
			got, err := pool.Submit(context.Background(), inputs)
			if err != nil {
				errs <- err
				return
			}
			for i, in := range inputs {
				if got[i] != in*2 {
					errs <- fmt.Errorf("batch %d: results[%d] = %d, want %d", b, i, got[i], in*2)
					return
				}
			}
		}(b)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
	if got := handled.Load(); got != batches*size {
		t.Errorf("handled %d jobs, want %d", got, batches*size)
	}
}

func TestSubmit_NeverExceedsWorkerCount(t *testing.T) {
	const workers = 3

	var (
		inFlight atomic.Int64
		peak     atomic.Int64
	)
	pool := NewPool(workers, 4, func(_ context.Context, n int) int {
		current := inFlight.Add(1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		return n
	})
	pool.Start(context.Background())
	defer pool.Stop()

	inputs := make([]int, 60)
	if _, err := pool.Submit(context.Background(), inputs); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if got := peak.Load(); got > workers {
		t.Errorf("peak concurrency = %d, want at most %d", got, workers)
	}
}

func TestSubmit_CallerCancellation(t *testing.T) {
	release := make(chan struct{})
	pool := NewPool(1, 1, func(ctx context.Context, n int) int {
		<-release
		return n
	})
	pool.Start(context.Background())
	defer func() {
		close(release)
		pool.Stop()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	// More jobs than workers plus queue depth, so Submit is still blocked when
	// the context is cancelled.
	_, err := pool.Submit(ctx, make([]int, 50))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Submit() error = %v, want context.Canceled", err)
	}
}

func TestSubmit_PoolContextCancellationStopsWorkers(t *testing.T) {
	pool := NewPool(2, 2, func(ctx context.Context, n int) int {
		select {
		case <-ctx.Done():
			return -1
		case <-time.After(time.Second):
			return n
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)

	cancel()

	done := make(chan struct{})
	go func() {
		pool.Stop() // must return once the workers observe the cancellation
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return after the pool context was cancelled")
	}
}

func TestSubmit_AfterStop(t *testing.T) {
	pool := NewPool(2, 2, func(_ context.Context, n int) int { return n })
	pool.Start(context.Background())
	pool.Stop()

	if _, err := pool.Submit(context.Background(), make([]int, 10)); !errors.Is(err, ErrPoolStopped) {
		t.Fatalf("Submit() error = %v, want ErrPoolStopped", err)
	}
}

func TestStop_IsIdempotent(t *testing.T) {
	pool := NewPool(2, 2, func(_ context.Context, n int) int { return n })
	pool.Start(context.Background())

	pool.Stop()
	pool.Stop() // must not panic on a second close
}

func TestNewPool_ClampsConfiguration(t *testing.T) {
	pool := NewPool(0, 0, func(_ context.Context, n int) int { return n })
	if pool.Workers() != 1 {
		t.Errorf("Workers() = %d, want 1", pool.Workers())
	}
	if cap(pool.jobs) != 1 {
		t.Errorf("queue capacity = %d, want 1", cap(pool.jobs))
	}
}
