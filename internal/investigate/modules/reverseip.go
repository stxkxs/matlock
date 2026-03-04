package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/stxkxs/matlock/internal/investigate"
)

type reverseIPResult struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
	Total   int      `json:"total"`
}

// ReverseIPModule performs reverse IP lookup via the HackerTarget API.
type ReverseIPModule struct{}

func (m *ReverseIPModule) Name() string        { return "reverseip" }
func (m *ReverseIPModule) Description() string { return "Reverse IP lookup to find co-hosted domains" }
func (m *ReverseIPModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain, investigate.TargetIPv4, investigate.TargetIPv6}
}

func (m *ReverseIPModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	ip := target
	if net.ParseIP(target) == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("resolve domain %s: %w", target, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no addresses found for domain %s", target)
		}
		ip = addrs[0]
	}

	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create reverse IP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reverse IP API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read reverse IP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reverse IP API returned status %d: %s", resp.StatusCode, string(body))
	}

	result := reverseIPResult{
		IP: ip,
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// HackerTarget returns "error" messages as plain text
		if strings.HasPrefix(line, "error") || strings.HasPrefix(line, "API count exceeded") {
			return nil, fmt.Errorf("reverse IP API error: %s", line)
		}
		result.Domains = append(result.Domains, line)
	}

	if result.Domains == nil {
		result.Domains = []string{}
	}
	result.Total = len(result.Domains)

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal reverse IP result: %w", err)
	}
	return json.RawMessage(out), nil
}
