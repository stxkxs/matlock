package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/stxkxs/matlock/internal/investigate"
)

type sectrailsResult struct {
	Hostname   string   `json:"hostname"`
	AlexaRank  int      `json:"alexa_rank"`
	Subdomains []string `json:"subdomains"`
	CurrentDNS any      `json:"current_dns,omitempty"`
}

// SecTrailsModule queries the SecurityTrails API for domain intelligence.
type SecTrailsModule struct{}

func (m *SecTrailsModule) Name() string        { return "sectrails" }
func (m *SecTrailsModule) Description() string { return "SecurityTrails domain intelligence lookup" }
func (m *SecTrailsModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *SecTrailsModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SECURITYTRAILS_API_KEY environment variable not set")
	}

	result := sectrailsResult{
		Hostname: target,
	}

	// Fetch domain info
	domainURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s", target)
	domainReq, err := http.NewRequestWithContext(ctx, http.MethodGet, domainURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create securitytrails domain request: %w", err)
	}
	domainReq.Header.Set("APIKEY", apiKey)

	domainResp, err := http.DefaultClient.Do(domainReq)
	if err != nil {
		return nil, fmt.Errorf("securitytrails domain API request: %w", err)
	}
	defer domainResp.Body.Close()

	domainBody, err := io.ReadAll(domainResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read securitytrails domain response: %w", err)
	}

	if domainResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails domain API returned status %d: %s", domainResp.StatusCode, string(domainBody))
	}

	var domainData map[string]interface{}
	if err := json.Unmarshal(domainBody, &domainData); err != nil {
		return nil, fmt.Errorf("parse securitytrails domain response: %w", err)
	}

	if hostname, ok := domainData["hostname"].(string); ok {
		result.Hostname = hostname
	}
	if rank, ok := domainData["alexa_rank"].(float64); ok {
		result.AlexaRank = int(rank)
	}
	if dns, ok := domainData["current_dns"]; ok {
		result.CurrentDNS = dns
	}

	// Fetch subdomains
	subURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", target)
	subReq, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create securitytrails subdomains request: %w", err)
	}
	subReq.Header.Set("APIKEY", apiKey)

	subResp, err := http.DefaultClient.Do(subReq)
	if err != nil {
		return nil, fmt.Errorf("securitytrails subdomains API request: %w", err)
	}
	defer subResp.Body.Close()

	subBody, err := io.ReadAll(subResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read securitytrails subdomains response: %w", err)
	}

	if subResp.StatusCode == http.StatusOK {
		var subData map[string]interface{}
		if err := json.Unmarshal(subBody, &subData); err != nil {
			return nil, fmt.Errorf("parse securitytrails subdomains response: %w", err)
		}

		if subs, ok := subData["subdomains"].([]interface{}); ok {
			for _, s := range subs {
				if prefix, ok := s.(string); ok {
					result.Subdomains = append(result.Subdomains, prefix+"."+target)
				}
			}
		}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal securitytrails result: %w", err)
	}
	return json.RawMessage(out), nil
}
