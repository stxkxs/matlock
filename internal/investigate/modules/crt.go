package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type crtResult struct {
	Subdomains []string `json:"subdomains"`
	Total      int      `json:"total"`
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// CrtModule queries Certificate Transparency logs via crt.sh.
type CrtModule struct{}

func (m *CrtModule) Name() string        { return "crt" }
func (m *CrtModule) Description() string { return "Certificate Transparency log search via crt.sh" }
func (m *CrtModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *CrtModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	query := url.QueryEscape(fmt.Sprintf("%%.%s", target))
	reqURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", query)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("crt build request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crt read response: %w", err)
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt parse response: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.ToLower(name)
			name = strings.TrimPrefix(name, "*.")
			if name == "" {
				continue
			}
			if !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	if subdomains == nil {
		subdomains = []string{}
	}

	result := crtResult{
		Subdomains: subdomains,
		Total:      len(subdomains),
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("crt marshal result: %w", err)
	}
	return data, nil
}
