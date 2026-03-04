package modules

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/stxkxs/matlock/internal/investigate"
)

type whoisResult struct {
	Raw    string       `json:"raw"`
	Parsed *whoisParsed `json:"parsed,omitempty"`
	Error  string       `json:"error,omitempty"`
}

type whoisParsed struct {
	Registrar      string   `json:"registrar"`
	CreationDate   string   `json:"creation_date"`
	ExpirationDate string   `json:"expiration_date"`
	UpdatedDate    string   `json:"updated_date"`
	NameServers    []string `json:"name_servers"`
	Status         []string `json:"status"`
	Registrant     string   `json:"registrant"`
	Country        string   `json:"country"`
}

// WhoisModule performs WHOIS lookups on domains and IP addresses.
type WhoisModule struct{}

func (m *WhoisModule) Name() string        { return "whois" }
func (m *WhoisModule) Description() string { return "WHOIS registration lookup" }
func (m *WhoisModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{
		investigate.TargetDomain,
		investigate.TargetIPv4,
		investigate.TargetIPv6,
	}
}

func (m *WhoisModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	raw, err := whoisLookup(ctx, target)
	if err != nil {
		result := whoisResult{
			Error: err.Error(),
		}
		data, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return nil, fmt.Errorf("whois marshal error: %w", marshalErr)
		}
		return data, fmt.Errorf("whois lookup: %w", err)
	}

	result := whoisResult{
		Raw: raw,
	}

	parsed, parseErr := whoisparser.Parse(raw)
	if parseErr == nil {
		result.Parsed = &whoisParsed{
			Registrar:      parsed.Registrar.Name,
			CreationDate:   parsed.Domain.CreatedDate,
			ExpirationDate: parsed.Domain.ExpirationDate,
			UpdatedDate:    parsed.Domain.UpdatedDate,
			NameServers:    parsed.Domain.NameServers,
			Status:         parsed.Domain.Status,
			Registrant:     parsed.Registrant.Name,
			Country:        parsed.Registrant.Country,
		}
		if result.Parsed.Registrant == "" && parsed.Registrant.Organization != "" {
			result.Parsed.Registrant = parsed.Registrant.Organization
		}
	} else {
		result.Error = fmt.Sprintf("parse warning: %v", parseErr)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("whois marshal result: %w", err)
	}
	return data, nil
}

func whoisLookup(ctx context.Context, target string) (string, error) {
	type lookupResult struct {
		raw string
		err error
	}
	ch := make(chan lookupResult, 1)

	go func() {
		raw, err := whois.Whois(target)
		ch <- lookupResult{raw: raw, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("whois lookup cancelled: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return "", fmt.Errorf("whois query %q: %w", target, res.err)
		}
		return res.raw, nil
	}
}
