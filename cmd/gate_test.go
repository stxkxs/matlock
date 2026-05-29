package cmd

import (
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestGate(t *testing.T) {
	tests := []struct {
		name   string
		failOn string
		sevs   []cloud.Severity
		want   int
	}{
		{"disabled ignores findings", "", []cloud.Severity{cloud.SeverityCritical}, 0},
		{"below threshold", "CRITICAL", []cloud.Severity{cloud.SeverityHigh}, 0},
		{"at threshold", "HIGH", []cloud.Severity{cloud.SeverityLow, cloud.SeverityHigh}, 2},
		{"above threshold", "MEDIUM", []cloud.Severity{cloud.SeverityCritical}, 2},
		{"lowercase flag", "high", []cloud.Severity{cloud.SeverityHigh}, 2},
		{"no findings", "LOW", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = 0
			failOn = tt.failOn
			gate(tt.sevs, func(s cloud.Severity) cloud.Severity { return s })
			if exitCode != tt.want {
				t.Errorf("exitCode = %d, want %d", exitCode, tt.want)
			}
		})
	}
	exitCode = 0
	failOn = ""
}

func TestGateBool(t *testing.T) {
	t.Cleanup(func() { exitCode = 0; failOn = "" })

	exitCode, failOn = 0, ""
	gateBool(true)
	if exitCode != 0 {
		t.Errorf("gateBool with --fail-on unset must not gate, got %d", exitCode)
	}

	failOn = "LOW"
	gateBool(false)
	if exitCode != 0 {
		t.Errorf("gateBool(false) must not gate, got %d", exitCode)
	}
	gateBool(true)
	if exitCode != 2 {
		t.Errorf("gateBool(true) with --fail-on set must gate to 2, got %d", exitCode)
	}
}
