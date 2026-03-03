package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type corsResult struct {
	Vulnerable bool       `json:"vulnerable"`
	Risk       string     `json:"risk"`
	Tests      []corsTest `json:"tests"`
}

type corsTest struct {
	Origin        string `json:"origin"`
	AllowOrigin   string `json:"allow_origin"`
	AllowCreds    string `json:"allow_credentials"`
	AllowMethods  string `json:"allow_methods"`
	Misconfigured bool   `json:"misconfigured"`
	Detail        string `json:"detail,omitempty"`
}

// CORSModule detects CORS misconfigurations.
type CORSModule struct{}

func (m *CORSModule) Name() string        { return "cors" }
func (m *CORSModule) Description() string { return "CORS misconfiguration detection" }
func (m *CORSModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *CORSModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	targetURL := fmt.Sprintf("https://%s", target)

	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://attacker.example.com",
		fmt.Sprintf("https://evil.%s", target),
	}

	var tests []corsTest
	highestRisk := "none"
	vulnerable := false

	for _, origin := range testOrigins {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
		if err != nil {
			return nil, fmt.Errorf("cors build request: %w", err)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("User-Agent", "matlock/1.0")

		resp, err := client.Do(req)
		if err != nil {
			tests = append(tests, corsTest{
				Origin:        origin,
				Misconfigured: false,
				Detail:        fmt.Sprintf("request failed: %v", err),
			})
			continue
		}
		resp.Body.Close()

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
		allowMethods := resp.Header.Get("Access-Control-Allow-Methods")

		test := corsTest{
			Origin:       origin,
			AllowOrigin:  allowOrigin,
			AllowCreds:   allowCreds,
			AllowMethods: allowMethods,
		}

		test.Misconfigured, test.Detail = evaluateCORS(origin, allowOrigin, allowCreds)
		if test.Misconfigured {
			vulnerable = true
			risk := classifyCORSRisk(origin, allowOrigin, allowCreds)
			highestRisk = maxCORSRisk(highestRisk, risk)
		}

		tests = append(tests, test)
	}

	result := corsResult{
		Vulnerable: vulnerable,
		Risk:       highestRisk,
		Tests:      tests,
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("cors marshal result: %w", err)
	}
	return data, nil
}

func evaluateCORS(origin, allowOrigin, allowCreds string) (bool, string) {
	if allowOrigin == "" {
		return false, ""
	}

	if allowOrigin == "*" && strings.EqualFold(allowCreds, "true") {
		return true, "wildcard ACAO with credentials enabled"
	}

	if allowOrigin == "*" {
		return true, "wildcard Access-Control-Allow-Origin"
	}

	if strings.EqualFold(allowOrigin, "null") && strings.EqualFold(origin, "null") {
		return true, "null origin accepted"
	}

	if strings.EqualFold(allowOrigin, origin) {
		if strings.EqualFold(allowCreds, "true") {
			return true, fmt.Sprintf("origin %q reflected with credentials", origin)
		}
		return true, fmt.Sprintf("origin %q reflected", origin)
	}

	return false, ""
}

func classifyCORSRisk(origin, allowOrigin, allowCreds string) string {
	if allowOrigin == "*" && strings.EqualFold(allowCreds, "true") {
		return "critical"
	}
	if strings.EqualFold(allowOrigin, origin) && strings.EqualFold(allowCreds, "true") {
		return "critical"
	}
	if strings.EqualFold(allowOrigin, "null") && strings.EqualFold(origin, "null") {
		return "high"
	}
	if strings.EqualFold(allowOrigin, origin) {
		return "medium"
	}
	if allowOrigin == "*" {
		return "low"
	}
	return "none"
}

var corsRiskOrder = map[string]int{
	"none":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func maxCORSRisk(a, b string) string {
	if corsRiskOrder[b] > corsRiskOrder[a] {
		return b
	}
	return a
}
