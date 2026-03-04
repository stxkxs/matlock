package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/stxkxs/matlock/internal/investigate"
)

type jsResult struct {
	Scripts      []jsScript `json:"scripts"`
	Secrets      []jsSecret `json:"secrets"`
	Endpoints    []string   `json:"endpoints"`
	SecretsCount int        `json:"secrets_count"`
}

type jsScript struct {
	URL  string `json:"url"`
	Size int    `json:"size"`
}

type jsSecret struct {
	Type  string `json:"type"`
	File  string `json:"file"`
	Match string `json:"match"`
}

// JSAnalysis finds JavaScript files in HTML, downloads them, and searches for secrets and endpoints.
type JSAnalysis struct{}

func (j *JSAnalysis) Name() string        { return "jsanalysis" }
func (j *JSAnalysis) Description() string { return "Analyze JavaScript files for secrets and API endpoints" }
func (j *JSAnalysis) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

	cdnDomains = []string{
		"cdnjs.cloudflare.com",
		"unpkg.com",
		"cdn.jsdelivr.net",
		"ajax.googleapis.com",
		"code.jquery.com",
	}

	secretPatterns = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"google_api", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
		{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36}`)},
		{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]+`)},
		{"stripe_key", regexp.MustCompile(`[sr]k_(live|test)_[0-9a-zA-Z]{24,}`)},
		{"api_key", regexp.MustCompile(`api[_\-]?key`)},
		{"api_secret", regexp.MustCompile(`api[_\-]?secret`)},
		{"access_token", regexp.MustCompile(`access[_\-]?token`)},
		{"private_key", regexp.MustCompile(`private[_\-]?key`)},
	}

	endpointPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/api/v[0-9]+/[a-zA-Z0-9/_-]+`),
		regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`XMLHttpRequest`),
	}
)

const (
	maxJSFiles = 20
	maxJSSize  = 2 * 1024 * 1024 // 2MB
)

func (j *JSAnalysis) Run(ctx context.Context, target string) (json.RawMessage, error) {
	baseURL := fmt.Sprintf("https://%s", target)

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Fetch HTML page.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create html request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch html: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read html body: %w", err)
	}

	// Extract script src URLs.
	matches := scriptSrcRe.FindAllSubmatch(body, -1)
	var scriptURLs []string
	for _, m := range matches {
		src := string(m[1])
		resolved := resolveURL(baseURL, src)
		if resolved != "" && !isCDN(resolved) {
			scriptURLs = append(scriptURLs, resolved)
		}
	}

	// Cap at maxJSFiles.
	if len(scriptURLs) > maxJSFiles {
		scriptURLs = scriptURLs[:maxJSFiles]
	}

	var scripts []jsScript
	var secrets []jsSecret
	endpointSet := make(map[string]bool)

	for _, jsURL := range scriptURLs {
		jsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
		if err != nil {
			continue
		}
		jsReq.Header.Set("User-Agent", "matlock/1.0")

		jsResp, err := client.Do(jsReq)
		if err != nil {
			continue
		}

		jsBody, err := io.ReadAll(io.LimitReader(jsResp.Body, maxJSSize))
		jsResp.Body.Close()
		if err != nil {
			continue
		}

		scripts = append(scripts, jsScript{
			URL:  jsURL,
			Size: len(jsBody),
		})

		content := string(jsBody)

		// Search for secrets.
		for _, sp := range secretPatterns {
			found := sp.pattern.FindAllString(content, 5)
			for _, match := range found {
				// Truncate long matches for safety.
				displayed := match
				if len(displayed) > 80 {
					displayed = displayed[:80] + "..."
				}
				secrets = append(secrets, jsSecret{
					Type:  sp.name,
					File:  jsURL,
					Match: displayed,
				})
			}
		}

		// Search for endpoints.
		for _, ep := range endpointPatterns {
			found := ep.FindAllString(content, 20)
			for _, match := range found {
				if !endpointSet[match] {
					endpointSet[match] = true
				}
			}
		}
	}

	var endpoints []string
	for ep := range endpointSet {
		endpoints = append(endpoints, ep)
	}

	result := jsResult{
		Scripts:      scripts,
		Secrets:      secrets,
		Endpoints:    endpoints,
		SecretsCount: len(secrets),
	}

	return json.Marshal(result)
}

func resolveURL(base, src string) string {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	if strings.HasPrefix(src, "//") {
		return "https:" + src
	}
	baseU, err := url.Parse(base)
	if err != nil {
		return ""
	}
	srcU, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return baseU.ResolveReference(srcU).String()
}

func isCDN(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, cdn := range cdnDomains {
		if host == cdn || strings.HasSuffix(host, "."+cdn) {
			return true
		}
	}
	return false
}
