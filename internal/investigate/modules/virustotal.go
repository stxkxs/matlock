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

type vtResult struct {
	Reputation int               `json:"reputation"`
	Malicious  int               `json:"malicious"`
	Suspicious int               `json:"suspicious"`
	Harmless   int               `json:"harmless"`
	Undetected int               `json:"undetected"`
	Categories map[string]string `json:"categories"`
}

// VirusTotalModule queries the VirusTotal API v3 for threat intelligence.
type VirusTotalModule struct{}

func (m *VirusTotalModule) Name() string        { return "virustotal" }
func (m *VirusTotalModule) Description() string { return "VirusTotal threat intelligence lookup" }
func (m *VirusTotalModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain, investigate.TargetIPv4, investigate.TargetIPv6}
}

func (m *VirusTotalModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("VIRUSTOTAL_API_KEY environment variable not set")
	}

	var url string
	if net.ParseIP(target) != nil {
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", target)
	} else {
		url = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", target)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create virustotal request: %w", err)
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read virustotal response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal API returned status %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse virustotal response: %w", err)
	}

	result := vtResult{
		Categories: make(map[string]string),
	}

	data, _ := raw["data"].(map[string]interface{})
	if data == nil {
		out, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshal virustotal result: %w", err)
		}
		return json.RawMessage(out), nil
	}

	attrs, _ := data["attributes"].(map[string]interface{})
	if attrs == nil {
		out, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshal virustotal result: %w", err)
		}
		return json.RawMessage(out), nil
	}

	if rep, ok := attrs["reputation"].(float64); ok {
		result.Reputation = int(rep)
	}

	if stats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
		if v, ok := stats["malicious"].(float64); ok {
			result.Malicious = int(v)
		}
		if v, ok := stats["suspicious"].(float64); ok {
			result.Suspicious = int(v)
		}
		if v, ok := stats["harmless"].(float64); ok {
			result.Harmless = int(v)
		}
		if v, ok := stats["undetected"].(float64); ok {
			result.Undetected = int(v)
		}
	}

	if cats, ok := attrs["categories"].(map[string]interface{}); ok {
		for k, v := range cats {
			if s, ok := v.(string); ok {
				result.Categories[k] = s
			}
		}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal virustotal result: %w", err)
	}
	return json.RawMessage(out), nil
}
