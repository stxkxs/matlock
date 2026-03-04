package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/stxkxs/matlock/internal/investigate"
)

type shodanResult struct {
	IP        string          `json:"ip"`
	Org       string          `json:"org"`
	ISP       string          `json:"isp"`
	Country   string          `json:"country"`
	Hostnames []string        `json:"hostnames"`
	Ports     []int           `json:"ports"`
	Vulns     []string        `json:"vulns"`
	Services  []shodanService `json:"services"`
}

type shodanService struct {
	Port    int    `json:"port"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// ShodanModule queries the Shodan API for host intelligence.
type ShodanModule struct{}

func (m *ShodanModule) Name() string        { return "shodan" }
func (m *ShodanModule) Description() string { return "Shodan host intelligence lookup" }
func (m *ShodanModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain, investigate.TargetIPv4, investigate.TargetIPv6}
}

func (m *ShodanModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SHODAN_API_KEY environment variable not set")
	}

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

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create shodan request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read shodan response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API returned status %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse shodan response: %w", err)
	}

	result := shodanResult{
		IP: ip,
	}

	if v, ok := raw["org"].(string); ok {
		result.Org = v
	}
	if v, ok := raw["isp"].(string); ok {
		result.ISP = v
	}
	if v, ok := raw["country_code"].(string); ok {
		result.Country = v
	}

	if hostnames, ok := raw["hostnames"].([]interface{}); ok {
		for _, h := range hostnames {
			if s, ok := h.(string); ok {
				result.Hostnames = append(result.Hostnames, s)
			}
		}
	}

	if ports, ok := raw["ports"].([]interface{}); ok {
		for _, p := range ports {
			if n, ok := p.(float64); ok {
				result.Ports = append(result.Ports, int(n))
			}
		}
	}

	if vulns, ok := raw["vulns"].([]interface{}); ok {
		for _, v := range vulns {
			if s, ok := v.(string); ok {
				result.Vulns = append(result.Vulns, s)
			}
		}
	}

	if data, ok := raw["data"].([]interface{}); ok {
		for _, entry := range data {
			if m, ok := entry.(map[string]interface{}); ok {
				svc := shodanService{}
				if p, ok := m["port"].(float64); ok {
					svc.Port = int(p)
				}
				if prod, ok := m["product"].(string); ok {
					svc.Product = prod
				}
				if ver, ok := m["version"].(string); ok {
					svc.Version = ver
				}
				result.Services = append(result.Services, svc)
			}
		}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal shodan result: %w", err)
	}
	return json.RawMessage(out), nil
}
