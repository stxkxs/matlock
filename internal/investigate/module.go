package investigate

import (
	"context"
	"encoding/json"
	"time"
)

// TargetType classifies the probe target.
type TargetType string

const (
	TargetDomain TargetType = "domain"
	TargetIPv4   TargetType = "ipv4"
	TargetIPv6   TargetType = "ipv6"
)

// Module is a single reconnaissance check (DNS, SSL, ports, etc.).
type Module interface {
	Name() string
	Description() string
	TargetTypes() []TargetType
	Run(ctx context.Context, target string) (json.RawMessage, error)
}

// ModuleResult holds the output of one module execution.
type ModuleResult struct {
	Module   string          `json:"module"`
	Status   string          `json:"status"` // success, partial, failed
	Data     json.RawMessage `json:"data"`
	Error    string          `json:"error,omitempty"`
	Duration string          `json:"duration"`
}

// ReportMeta holds scan metadata.
type ReportMeta struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Duration  string    `json:"duration"`
}

// ScoreCheck is a single scored check.
type ScoreCheck struct {
	Category       string `json:"category"`
	Check          string `json:"check"`
	Pass           bool   `json:"pass"`
	Points         int    `json:"points"`
	Max            int    `json:"max"`
	Recommendation string `json:"recommendation,omitempty"`
}

// ScoreResult holds the security scoring output.
type ScoreResult struct {
	Score           int          `json:"score"`
	MaxScore        int          `json:"max_score"`
	Percentage      int          `json:"percentage"`
	Grade           string       `json:"grade"`
	Checks          []ScoreCheck `json:"checks"`
	Passed          int          `json:"passed"`
	Failed          int          `json:"failed"`
	Recommendations []string     `json:"recommendations"`
}

// ReportSummary holds aggregate counts.
type ReportSummary struct {
	ModulesRun    int `json:"modules_run"`
	ModulesOK     int `json:"modules_ok"`
	ModulesFailed int `json:"modules_failed"`
}

// Report is the top-level output of a probe.
type Report struct {
	Meta    ReportMeta              `json:"meta"`
	Target  string                  `json:"target"`
	Type    TargetType              `json:"type"`
	Results map[string]ModuleResult `json:"results"`
	Score   *ScoreResult            `json:"score,omitempty"`
	Summary ReportSummary           `json:"summary"`
}

// DefaultDomainModules lists modules enabled by default for domain targets.
var DefaultDomainModules = []string{
	"dns", "ssl", "http", "ports", "whois", "subdomain", "crt",
	"cors", "waf", "tech", "dnssec", "files", "shodan", "virustotal",
	"sectrails", "wayback", "axfr", "methods", "dirs", "jsanalysis", "favicon",
}

// DefaultIPModules lists modules enabled by default for IP targets.
var DefaultIPModules = []string{
	"ip", "ports", "shodan", "virustotal", "reverseip", "asn",
}
