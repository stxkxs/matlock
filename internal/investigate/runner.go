package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// RunOptions controls module execution.
type RunOptions struct {
	Modules     []string              // explicit module list; empty = auto-detect
	Exclude     []string              // modules to skip
	Concurrency int                   // max parallel modules (default 5)
	Timeout     time.Duration         // per-module timeout (default 10s)
	Score       bool                  // run scoring after modules
	Progress    func(done, total int) // optional progress callback
}

// Runner orchestrates module execution against a single target.
type Runner struct {
	registry map[string]Module
	order    []string // preserves registration order
}

// NewRunner creates a runner with the given modules.
func NewRunner(modules []Module) *Runner {
	r := &Runner{
		registry: make(map[string]Module, len(modules)),
	}
	for _, m := range modules {
		r.registry[m.Name()] = m
		r.order = append(r.order, m.Name())
	}
	return r
}

// ListModules returns all registered modules in order.
func (r *Runner) ListModules() []Module {
	out := make([]Module, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.registry[name])
	}
	return out
}

// Run executes applicable modules against the target and returns a Report.
func (r *Runner) Run(ctx context.Context, target string, tt TargetType, opts RunOptions) (*Report, error) {
	startedAt := time.Now()

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	// Determine which modules to run.
	selected := r.selectModules(tt, opts)
	if len(selected) == 0 {
		return nil, fmt.Errorf("no applicable modules for target type %s", tt)
	}

	results := make(map[string]ModuleResult, len(selected))
	var mu sync.Mutex
	var doneCount atomic.Int64

	sem := make(chan struct{}, concurrency)
	g, gctx := errgroup.WithContext(ctx)

	for _, mod := range selected {
		mod := mod
		sem <- struct{}{}

		g.Go(func() error {
			defer func() {
				<-sem
				n := int(doneCount.Add(1))
				if opts.Progress != nil {
					opts.Progress(n, len(selected))
				}
			}()

			modCtx, cancel := context.WithTimeout(gctx, timeout)
			defer cancel()

			modStart := time.Now()
			data, err := mod.Run(modCtx, target)
			dur := time.Since(modStart)

			mr := ModuleResult{
				Module:   mod.Name(),
				Duration: dur.Round(time.Millisecond).String(),
			}

			switch {
			case err != nil && data != nil:
				mr.Status = "partial"
				mr.Data = data
				mr.Error = err.Error()
			case err != nil:
				mr.Status = "failed"
				mr.Data = json.RawMessage(`null`)
				mr.Error = err.Error()
			default:
				mr.Status = "success"
				mr.Data = data
			}

			mu.Lock()
			results[mod.Name()] = mr
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait() // individual module errors are captured in results

	endedAt := time.Now()
	dur := endedAt.Sub(startedAt)

	var ok, failed int
	for _, mr := range results {
		if mr.Status == "success" || mr.Status == "partial" {
			ok++
		} else {
			failed++
		}
	}

	report := &Report{
		Meta: ReportMeta{
			StartedAt: startedAt,
			EndedAt:   endedAt,
			Duration:  dur.Round(time.Millisecond).String(),
		},
		Target:  target,
		Type:    tt,
		Results: results,
		Summary: ReportSummary{
			ModulesRun:    len(results),
			ModulesOK:     ok,
			ModulesFailed: failed,
		},
	}

	if opts.Score {
		score := CalculateScore(report)
		report.Score = score
	}

	return report, nil
}

// selectModules decides which modules to run based on target type and options.
func (r *Runner) selectModules(tt TargetType, opts RunOptions) []Module {
	excludeSet := make(map[string]bool, len(opts.Exclude))
	for _, e := range opts.Exclude {
		excludeSet[e] = true
	}

	// If explicit modules requested, use those.
	if len(opts.Modules) > 0 {
		var out []Module
		for _, name := range opts.Modules {
			if excludeSet[name] {
				continue
			}
			if mod, ok := r.registry[name]; ok {
				out = append(out, mod)
			}
		}
		return out
	}

	// Auto-select by target type.
	var defaults []string
	switch tt {
	case TargetDomain:
		defaults = DefaultDomainModules
	case TargetIPv4, TargetIPv6:
		defaults = DefaultIPModules
	}

	var out []Module
	for _, name := range defaults {
		if excludeSet[name] {
			continue
		}
		if mod, ok := r.registry[name]; ok {
			out = append(out, mod)
		}
	}
	return out
}
