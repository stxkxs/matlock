package investigate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRunBatch(t *testing.T) {
	// Register a simple mock module for domain targets.
	mod := &mockModule{
		name:  "dns",
		types: []TargetType{TargetDomain},
		data:  json.RawMessage(`{"test": true}`),
	}

	runner := NewRunner([]Module{mod})

	input := "example.com\n# comment\nexample.org\n\n"
	opts := BatchOptions{
		RunOptions: RunOptions{
			Modules:     []string{"dns"},
			Concurrency: 2,
			Timeout:     5 * time.Second,
		},
		Parallel: 2,
	}

	results, err := runner.RunBatch(context.Background(), strings.NewReader(input), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Error != "" {
			t.Errorf("unexpected error for %s: %s", r.Target, r.Error)
		}
		if r.Report == nil {
			t.Errorf("expected report for %s", r.Target)
		}
	}
}

func TestRunBatchInvalidTarget(t *testing.T) {
	mod := &mockModule{
		name:  "dns",
		types: []TargetType{TargetDomain},
		data:  json.RawMessage(`{}`),
	}

	runner := NewRunner([]Module{mod})

	input := "example.com\nnot valid!\n"
	opts := BatchOptions{
		RunOptions: RunOptions{
			Modules:     []string{"dns"},
			Concurrency: 1,
			Timeout:     5 * time.Second,
		},
		Parallel: 1,
	}

	results, err := runner.RunBatch(context.Background(), strings.NewReader(input), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// First target should succeed.
	if results[0].Error != "" {
		t.Errorf("expected no error for example.com, got %s", results[0].Error)
	}
	// Second target should fail validation.
	if results[1].Error == "" {
		t.Error("expected error for invalid target")
	}
}

func TestRunBatchEmpty(t *testing.T) {
	runner := NewRunner(nil)
	_, err := runner.RunBatch(context.Background(), strings.NewReader("# only comments\n\n"), BatchOptions{})
	if err == nil {
		t.Error("expected error for empty targets")
	}
}

func TestRunBatchProgress(t *testing.T) {
	mod := &mockModule{
		name:  "dns",
		types: []TargetType{TargetDomain},
		data:  json.RawMessage(`{}`),
	}

	runner := NewRunner([]Module{mod})

	input := "a.com\nb.com\nc.com\n"
	var progressCalls int
	opts := BatchOptions{
		RunOptions: RunOptions{
			Modules:     []string{"dns"},
			Concurrency: 1,
			Timeout:     5 * time.Second,
		},
		Parallel: 1,
		Progress: func(done, total int, target string) {
			progressCalls++
		},
	}

	results, err := runner.RunBatch(context.Background(), strings.NewReader(input), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if progressCalls != 3 {
		t.Errorf("expected 3 progress calls, got %d", progressCalls)
	}
}

func TestNewBatchReport(t *testing.T) {
	results := []BatchResult{
		{Target: "a.com", Report: &Report{}},
		{Target: "b.com", Error: "failed"},
		{Target: "c.com", Report: &Report{}},
	}

	br := NewBatchReport(results)
	if br.Total != 3 {
		t.Errorf("expected total 3, got %d", br.Total)
	}
	if br.OK != 2 {
		t.Errorf("expected ok 2, got %d", br.OK)
	}
	if br.Failed != 1 {
		t.Errorf("expected failed 1, got %d", br.Failed)
	}
}
