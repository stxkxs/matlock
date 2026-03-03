package investigate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// BatchResult holds the outcome for one target in a batch run.
type BatchResult struct {
	Target string  `json:"target"`
	Report *Report `json:"report,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// BatchOptions controls batch execution.
type BatchOptions struct {
	RunOptions
	Parallel int                               // number of concurrent targets (default 4)
	Progress func(done, total int, target string) // per-target progress
}

// RunBatch reads targets from r (one per line, # comments allowed) and runs
// the full probe pipeline per target.
func (runner *Runner) RunBatch(ctx context.Context, r io.Reader, opts BatchOptions) ([]BatchResult, error) {
	targets, err := parseTargets(r)
	if err != nil {
		return nil, fmt.Errorf("parse targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found in input")
	}

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 4
	}

	results := make([]BatchResult, len(targets))
	var doneCount atomic.Int64

	sem := make(chan struct{}, parallel)
	g, gctx := errgroup.WithContext(ctx)

	for i, raw := range targets {
		i, raw := i, raw
		sem <- struct{}{}

		g.Go(func() error {
			defer func() {
				<-sem
				n := int(doneCount.Add(1))
				if opts.Progress != nil {
					opts.Progress(n, len(targets), raw)
				}
			}()

			target, tt, err := ValidateTarget(raw)
			if err != nil {
				results[i] = BatchResult{Target: raw, Error: err.Error()}
				return nil
			}

			// Silence per-module progress in batch mode.
			runOpts := opts.RunOptions
			runOpts.Progress = nil

			report, err := runner.Run(gctx, target, tt, runOpts)
			if err != nil {
				results[i] = BatchResult{Target: target, Error: err.Error()}
				return nil
			}
			results[i] = BatchResult{Target: target, Report: report}
			return nil
		})
	}

	_ = g.Wait()
	return results, nil
}

// BatchReport is the JSON envelope for batch output.
type BatchReport struct {
	Results []BatchResult `json:"results"`
	Total   int           `json:"total"`
	OK      int           `json:"ok"`
	Failed  int           `json:"failed"`
}

// NewBatchReport summarizes batch results.
func NewBatchReport(results []BatchResult) BatchReport {
	var ok, failed int
	for _, r := range results {
		if r.Error == "" {
			ok++
		} else {
			failed++
		}
	}
	return BatchReport{
		Results: results,
		Total:   len(results),
		OK:      ok,
		Failed:  failed,
	}
}

func parseTargets(r io.Reader) ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
