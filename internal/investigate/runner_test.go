package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// mockModule is a test double for Module.
type mockModule struct {
	name    string
	types   []TargetType
	data    json.RawMessage
	err     error
	delay   time.Duration
}

func (m *mockModule) Name() string               { return m.name }
func (m *mockModule) Description() string         { return "mock " + m.name }
func (m *mockModule) TargetTypes() []TargetType   { return m.types }
func (m *mockModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.data, m.err
}

func TestRunnerSelectsModulesByTargetType(t *testing.T) {
	domainMod := &mockModule{name: "dns", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}
	ipMod := &mockModule{name: "ip", types: []TargetType{TargetIPv4, TargetIPv6}, data: json.RawMessage(`{}`)}
	bothMod := &mockModule{name: "ports", types: []TargetType{TargetDomain, TargetIPv4, TargetIPv6}, data: json.RawMessage(`{}`)}

	runner := NewRunner([]Module{domainMod, ipMod, bothMod})

	// Explicit module list — should use exactly what's requested.
	opts := RunOptions{Modules: []string{"dns", "ports"}, Concurrency: 2, Timeout: 5 * time.Second}
	report, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Results))
	}
	if _, ok := report.Results["dns"]; !ok {
		t.Error("expected dns result")
	}
	if _, ok := report.Results["ports"]; !ok {
		t.Error("expected ports result")
	}
}

func TestRunnerHandlesModuleErrors(t *testing.T) {
	okMod := &mockModule{name: "ok", types: []TargetType{TargetDomain}, data: json.RawMessage(`{"test":true}`)}
	errMod := &mockModule{name: "err", types: []TargetType{TargetDomain}, err: fmt.Errorf("boom")}
	partialMod := &mockModule{name: "partial", types: []TargetType{TargetDomain}, data: json.RawMessage(`{"partial":true}`), err: fmt.Errorf("partial failure")}

	runner := NewRunner([]Module{okMod, errMod, partialMod})
	opts := RunOptions{Modules: []string{"ok", "err", "partial"}, Concurrency: 3, Timeout: 5 * time.Second}

	report, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.ModulesRun != 3 {
		t.Errorf("expected 3 modules run, got %d", report.Summary.ModulesRun)
	}
	if report.Results["ok"].Status != "success" {
		t.Errorf("expected ok status 'success', got %q", report.Results["ok"].Status)
	}
	if report.Results["err"].Status != "failed" {
		t.Errorf("expected err status 'failed', got %q", report.Results["err"].Status)
	}
	if report.Results["partial"].Status != "partial" {
		t.Errorf("expected partial status 'partial', got %q", report.Results["partial"].Status)
	}
}

func TestRunnerExcludesModules(t *testing.T) {
	m1 := &mockModule{name: "dns", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}
	m2 := &mockModule{name: "ssl", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}

	runner := NewRunner([]Module{m1, m2})
	opts := RunOptions{
		Modules:     []string{"dns", "ssl"},
		Exclude:     []string{"ssl"},
		Concurrency: 2,
		Timeout:     5 * time.Second,
	}

	report, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(report.Results))
	}
	if _, ok := report.Results["dns"]; !ok {
		t.Error("expected dns result")
	}
}

func TestRunnerTimeout(t *testing.T) {
	slowMod := &mockModule{
		name:  "slow",
		types: []TargetType{TargetDomain},
		delay: 5 * time.Second,
	}

	runner := NewRunner([]Module{slowMod})
	opts := RunOptions{
		Modules:     []string{"slow"},
		Concurrency: 1,
		Timeout:     50 * time.Millisecond,
	}

	report, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Results["slow"].Status != "failed" {
		t.Errorf("expected failed status for timed out module, got %q", report.Results["slow"].Status)
	}
}

func TestRunnerProgress(t *testing.T) {
	m1 := &mockModule{name: "a", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}
	m2 := &mockModule{name: "b", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}

	runner := NewRunner([]Module{m1, m2})

	var progressCalls int
	opts := RunOptions{
		Modules:     []string{"a", "b"},
		Concurrency: 1,
		Timeout:     5 * time.Second,
		Progress: func(done, total int) {
			progressCalls++
		},
	}

	_, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if progressCalls != 2 {
		t.Errorf("expected 2 progress calls, got %d", progressCalls)
	}
}

func TestRunnerReportMeta(t *testing.T) {
	m := &mockModule{name: "test", types: []TargetType{TargetDomain}, data: json.RawMessage(`{}`)}
	runner := NewRunner([]Module{m})
	opts := RunOptions{Modules: []string{"test"}, Concurrency: 1, Timeout: 5 * time.Second}

	report, err := runner.Run(context.Background(), "example.com", TargetDomain, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", report.Target)
	}
	if report.Type != TargetDomain {
		t.Errorf("expected type domain, got %s", report.Type)
	}
	if report.Meta.StartedAt.IsZero() {
		t.Error("expected non-zero started_at")
	}
	if report.Meta.EndedAt.IsZero() {
		t.Error("expected non-zero ended_at")
	}
	if report.Meta.Duration == "" {
		t.Error("expected non-empty duration")
	}
}

func TestListModules(t *testing.T) {
	m1 := &mockModule{name: "dns", types: []TargetType{TargetDomain}}
	m2 := &mockModule{name: "ports", types: []TargetType{TargetDomain, TargetIPv4}}

	runner := NewRunner([]Module{m1, m2})
	mods := runner.ListModules()
	if len(mods) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(mods))
	}
	if mods[0].Name() != "dns" {
		t.Errorf("expected first module dns, got %s", mods[0].Name())
	}
	if mods[1].Name() != "ports" {
		t.Errorf("expected second module ports, got %s", mods[1].Name())
	}
}
