package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type techResult struct {
	Frontend       []string `json:"frontend"`
	Analytics      []string `json:"analytics"`
	Infrastructure []string `json:"infrastructure"`
	Total          int      `json:"total"`
}

type techPattern struct {
	name     string
	patterns []string // substrings to look for in HTML (lowercased)
}

var frontendPatterns = []techPattern{
	{name: "React", patterns: []string{"__next_data__", "react", "reactjs"}},
	{name: "Angular", patterns: []string{"ng-version", "angular"}},
	{name: "Vue", patterns: []string{"vue.js", "__vue__"}},
	{name: "Svelte", patterns: []string{"svelte"}},
	{name: "jQuery", patterns: []string{"jquery"}},
	{name: "Next.js", patterns: []string{"__next_data__"}},
	{name: "Nuxt", patterns: []string{"_nuxt"}},
	{name: "Gatsby", patterns: []string{"gatsby"}},
}

var analyticsPatterns = []techPattern{
	{name: "Google Analytics", patterns: []string{"google-analytics", "gtag"}},
	{name: "Sentry", patterns: []string{"sentry"}},
	{name: "Segment", patterns: []string{"segment.com/analytics"}},
	{name: "Mixpanel", patterns: []string{"mixpanel"}},
	{name: "Hotjar", patterns: []string{"hotjar"}},
	{name: "Intercom", patterns: []string{"intercom"}},
}

var infraPatterns = []techPattern{
	{name: "nginx", patterns: []string{"nginx"}},
	{name: "Apache", patterns: []string{"apache"}},
	{name: "Express", patterns: []string{"express"}},
	{name: "PHP", patterns: []string{"php"}},
	{name: "ASP.NET", patterns: []string{"asp.net"}},
	{name: "Django", patterns: []string{"django"}},
	{name: "Rails", patterns: []string{"rails"}},
}

// TechModule detects frontend frameworks, analytics, and infrastructure from HTML and headers.
type TechModule struct{}

func (m *TechModule) Name() string        { return "tech" }
func (m *TechModule) Description() string { return "Technology detection from HTML and headers" }
func (m *TechModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *TechModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
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
		return nil, fmt.Errorf("tech build request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tech http request: %w", err)
	}
	defer resp.Body.Close()

	// Read up to 1MB of HTML to avoid memory issues on large pages.
	limited := io.LimitReader(resp.Body, 1<<20)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("tech read response: %w", err)
	}
	htmlLower := strings.ToLower(string(body))

	// Detect frontend frameworks from HTML content.
	frontend := detectFromHTML(htmlLower, frontendPatterns)

	// Detect analytics from HTML content.
	analytics := detectFromHTML(htmlLower, analyticsPatterns)

	// Detect infrastructure from server and x-powered-by headers.
	infrastructure := detectFromHeaders(resp.Header, infraPatterns)

	if frontend == nil {
		frontend = []string{}
	}
	if analytics == nil {
		analytics = []string{}
	}
	if infrastructure == nil {
		infrastructure = []string{}
	}

	result := techResult{
		Frontend:       frontend,
		Analytics:      analytics,
		Infrastructure: infrastructure,
		Total:          len(frontend) + len(analytics) + len(infrastructure),
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("tech marshal result: %w", err)
	}
	return data, nil
}

func detectFromHTML(htmlLower string, patterns []techPattern) []string {
	seen := make(map[string]bool)
	var detected []string

	for _, tp := range patterns {
		if seen[tp.name] {
			continue
		}
		for _, pat := range tp.patterns {
			if strings.Contains(htmlLower, pat) {
				seen[tp.name] = true
				detected = append(detected, tp.name)
				break
			}
		}
	}
	return detected
}

func detectFromHeaders(headers http.Header, patterns []techPattern) []string {
	serverVal := strings.ToLower(headers.Get("Server"))
	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	combined := serverVal + " " + poweredBy

	seen := make(map[string]bool)
	var detected []string

	for _, tp := range patterns {
		if seen[tp.name] {
			continue
		}
		for _, pat := range tp.patterns {
			if strings.Contains(combined, pat) {
				seen[tp.name] = true
				detected = append(detected, tp.name)
				break
			}
		}
	}
	return detected
}
