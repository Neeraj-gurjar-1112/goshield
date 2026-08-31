// Package worker provides a bounded worker pool. Bulk requests are fanned out
// across a fixed number of goroutines feeding off a buffered channel, so an
// expensive request cannot spawn an unbounded number of goroutines.
package worker

import (
	"context"
	"errors"
	"sync"
)

// ErrPoolStopped is returned when work is submitted to a stopped pool.
var ErrPoolStopped = errors.New("worker pool is stopped")

// Handler processes one input and returns its output. It must be safe for
// concurrent use.
type Handler[I, O any] func(ctx context.Context, input I) O

// Pool is a fixed-size worker pool over a buffered job queue.
type Pool[I, O any] struct {
	workers int
	jobs    chan job[I, O]
	handler Handler[I, O]

	wg       sync.WaitGroup
	quit     chan struct{}
	stopOnce sync.Once
	cancel   context.CancelFunc
}

// job is one unit of work plus where its result should be delivered.
type job[I, O any] struct {
	ctx   context.Context
	input I
	index int
	out   chan<- indexed[O]
}

// indexed carries a result together with its position in the submitted batch.
type indexed[O any] struct {
	index int
	value O
}

// NewPool builds a pool with the given number of workers and queue depth. Both
// are clamped to at least one.
func NewPool[I, O any](workers, queueSize int, handler Handler[I, O]) *Pool[I, O] {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	return &Pool[I, O]{
		workers: workers,
		jobs:    make(chan job[I, O], queueSize),
		handler: handler,
		quit:    make(chan struct{}),
	}
}

// Start launches the workers. They run until Stop is called or ctx is
// cancelled.
func (p *Pool[I, O]) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.wg.Add(p.workers)
	for i := 0; i < p.workers; i++ {
		go p.work(ctx)
	}
}

// Stop signals the workers to finish and waits for them. It is safe to call
// more than once.
func (p *Pool[I, O]) Stop() {
	p.stopOnce.Do(func() {
		close(p.quit)
		if p.cancel != nil {
			p.cancel()
		}
	})
	p.wg.Wait()
}

// Workers returns the configured worker count.
func (p *Pool[I, O]) Workers() int { return p.workers }

// Submit runs the handler over every input and returns the outputs in input
// order. It blocks until the batch finishes, ctx is cancelled, or the pool is
// stopped.
func (p *Pool[I, O]) Submit(ctx context.Context, inputs []I) ([]O, error) {
	if len(inputs) == 0 {
		return []O{}, nil
	}

	// Buffered for the whole batch so a worker never blocks on delivery, even
	// if this call returns early on cancellation.
	out := make(chan indexed[O], len(inputs))

	submitted := 0
	for i, input := range inputs {
		select {
		case p.jobs <- job[I, O]{ctx: ctx, input: input, index: i, out: out}:
			submitted++
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.quit:
			return nil, ErrPoolStopped
		}
	}

	results := make([]O, len(inputs))
	for n := 0; n < submitted; n++ {
		select {
		case r := <-out:
			results[r.index] = r.value
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.quit:
			return nil, ErrPoolStopped
		}
	}
	return results, nil
}

// work is the worker loop.
func (p *Pool[I, O]) work(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case j := <-p.jobs:
			p.runJob(ctx, j)
		}
	}
}

// runJob executes one job, skipping work whose caller has already given up.
func (p *Pool[I, O]) runJob(ctx context.Context, j job[I, O]) {
	var zero O
	if j.ctx.Err() != nil || ctx.Err() != nil {
		j.out <- indexed[O]{index: j.index, value: zero}
		return
	}
	j.out <- indexed[O]{index: j.index, value: p.handler(j.ctx, j.input)}
}
