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

type wafResult struct {
	Detected   bool          `json:"detected"`
	Providers  []wafProvider `json:"providers"`
	Confidence string        `json:"confidence"`
}

type wafProvider struct {
	Name       string   `json:"name"`
	Indicators []string `json:"indicators"`
}

type wafSignature struct {
	name    string
	checks  []wafCheck
}

type wafCheck struct {
	headerName    string // header to inspect (lowercased)
	headerPrefix  bool   // true = match header names starting with this prefix
	valueContains string // substring to look for in the header value (lowercased)
	description   string // human-readable indicator label
}

// WAFModule fingerprints WAF and CDN providers from HTTP response headers.
type WAFModule struct{}

func (m *WAFModule) Name() string        { return "waf" }
func (m *WAFModule) Description() string { return "WAF/CDN fingerprinting from HTTP response headers" }
func (m *WAFModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

var wafSignatures = []wafSignature{
	{
		name: "Cloudflare",
		checks: []wafCheck{
			{headerName: "cf-ray", description: "cf-ray header present"},
			{headerName: "server", valueContains: "cloudflare", description: "server: cloudflare"},
		},
	},
	{
		name: "CloudFront",
		checks: []wafCheck{
			{headerName: "x-amz-cf-id", description: "x-amz-cf-id header present"},
			{headerName: "x-amz-cf-pop", description: "x-amz-cf-pop header present"},
			{headerName: "via", valueContains: "cloudfront", description: "via: cloudfront"},
		},
	},
	{
		name: "Akamai",
		checks: []wafCheck{
			{headerName: "x-akamai-", headerPrefix: true, description: "x-akamai-* header present"},
			{headerName: "server", valueContains: "akamai", description: "server contains akamai"},
		},
	},
	{
		name: "Fastly",
		checks: []wafCheck{
			{headerName: "x-served-by", valueContains: "cache", description: "x-served-by contains cache"},
			{headerName: "x-fastly-request-id", description: "x-fastly-request-id header present"},
			{headerName: "fastly-io", description: "fastly-io header present"},
		},
	},
	{
		name: "Imperva",
		checks: []wafCheck{
			{headerName: "x-cdn", valueContains: "imperva", description: "x-cdn: imperva"},
			{headerName: "x-iinfo", description: "x-iinfo header present"},
		},
	},
	{
		name: "Sucuri",
		checks: []wafCheck{
			{headerName: "x-sucuri-id", description: "x-sucuri-id header present"},
			{headerName: "server", valueContains: "sucuri", description: "server: sucuri"},
		},
	},
	{
		name: "Azure",
		checks: []wafCheck{
			{headerName: "x-azure-ref", description: "x-azure-ref header present"},
			{headerName: "x-ms-", headerPrefix: true, description: "x-ms-* header present"},
		},
	},
	{
		name: "AWS WAF",
		checks: []wafCheck{
			{headerName: "x-amzn-waf", headerPrefix: true, description: "x-amzn-waf* header present"},
			{headerName: "x-amzn-requestid", description: "x-amzn-requestid header present"},
		},
	},
	{
		name: "F5 BigIP",
		checks: []wafCheck{
			{headerName: "x-cnection", description: "x-cnection header present"},
			{headerName: "bigipserver", headerPrefix: true, description: "bigipserver* header present"},
		},
	},
	{
		name: "Vercel",
		checks: []wafCheck{
			{headerName: "x-vercel-id", description: "x-vercel-id header present"},
			{headerName: "server", valueContains: "vercel", description: "server: vercel"},
		},
	},
	{
		name: "Netlify",
		checks: []wafCheck{
			{headerName: "x-nf-request-id", description: "x-nf-request-id header present"},
			{headerName: "server", valueContains: "netlify", description: "server: netlify"},
		},
	},
}

func (m *WAFModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	targetURL := fmt.Sprintf("https://%s", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("waf build request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("waf http request: %w", err)
	}
	defer resp.Body.Close()

	// Build a lowercased header map for matching.
	lowerHeaders := make(map[string]string)
	for name, values := range resp.Header {
		lowerName := strings.ToLower(name)
		lowerVal := strings.ToLower(strings.Join(values, " "))
		lowerHeaders[lowerName] = lowerVal
	}

	var providers []wafProvider
	totalIndicators := 0

	for _, sig := range wafSignatures {
		var indicators []string
		for _, check := range sig.checks {
			if check.headerPrefix {
				for hName, hVal := range lowerHeaders {
					if strings.HasPrefix(hName, check.headerName) {
						if check.valueContains == "" || strings.Contains(hVal, check.valueContains) {
							indicators = append(indicators, check.description)
							break
						}
					}
				}
			} else {
				hVal, exists := lowerHeaders[check.headerName]
				if !exists {
					continue
				}
				if check.valueContains == "" || strings.Contains(hVal, check.valueContains) {
					indicators = append(indicators, check.description)
				}
			}
		}
		if len(indicators) > 0 {
			providers = append(providers, wafProvider{
				Name:       sig.name,
				Indicators: indicators,
			})
			totalIndicators += len(indicators)
		}
	}

	confidence := "none"
	if len(providers) > 0 {
		if totalIndicators >= 2 {
			confidence = "high"
		} else {
			// Single indicator: check if it's just a server header match.
			serverOnly := true
			for _, p := range providers {
				for _, ind := range p.Indicators {
					if !strings.HasPrefix(ind, "server") {
						serverOnly = false
						break
					}
				}
				if !serverOnly {
					break
				}
			}
			if serverOnly {
				confidence = "low"
			} else {
				confidence = "medium"
			}
		}
	}

	result := wafResult{
		Detected:   len(providers) > 0,
		Providers:  providers,
		Confidence: confidence,
	}
	if result.Providers == nil {
		result.Providers = []wafProvider{}
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("waf marshal result: %w", err)
	}
	return data, nil
}
