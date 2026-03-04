package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/stxkxs/matlock/internal/investigate"
)

type dnssecResult struct {
	Enabled   bool   `json:"enabled"`
	Valid     bool   `json:"valid"`
	HasDNSKEY bool   `json:"has_dnskey"`
	HasDS     bool   `json:"has_ds"`
	HasRRSIG  bool   `json:"has_rrsig"`
	Algorithm string `json:"algorithm"`
	KeyCount  int    `json:"key_count"`
	ADFlag    bool   `json:"ad_flag"`
}

// algorithmNames maps DNSSEC algorithm numbers to human-readable names.
var algorithmNames = map[uint8]string{
	1:  "RSA/MD5",
	3:  "DSA/SHA-1",
	5:  "RSA/SHA-1",
	6:  "DSA-NSEC3-SHA1",
	7:  "RSA/SHA-1-NSEC3",
	8:  "RSA/SHA-256",
	10: "RSA/SHA-512",
	12: "ECC-GOST",
	13: "ECDSA/P-256",
	14: "ECDSA/P-384",
	15: "Ed25519",
	16: "Ed448",
}

// DNSSECModule checks DNSSEC configuration for a domain.
type DNSSECModule struct{}

func (m *DNSSECModule) Name() string        { return "dnssec" }
func (m *DNSSECModule) Description() string { return "DNSSEC validation and configuration check" }
func (m *DNSSECModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *DNSSECModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	fqdn := dns.Fqdn(target)
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}
	server := "8.8.8.8:53"

	result := dnssecResult{}

	// Query DNSKEY records
	dnskeyMsg := new(dns.Msg)
	dnskeyMsg.SetQuestion(fqdn, dns.TypeDNSKEY)
	dnskeyMsg.SetEdns0(4096, true) // enable DNSSEC OK flag

	dnskeyResp, _, err := client.ExchangeContext(ctx, dnskeyMsg, server)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY query for %s: %w", target, err)
	}

	for _, rr := range dnskeyResp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			result.HasDNSKEY = true
			result.KeyCount++
			if result.Algorithm == "" {
				if name, exists := algorithmNames[key.Algorithm]; exists {
					result.Algorithm = name
				} else {
					result.Algorithm = fmt.Sprintf("Unknown (%d)", key.Algorithm)
				}
			}
		}
	}

	// Query DS records
	dsMsg := new(dns.Msg)
	dsMsg.SetQuestion(fqdn, dns.TypeDS)
	dsMsg.SetEdns0(4096, true)

	dsResp, _, err := client.ExchangeContext(ctx, dsMsg, server)
	if err != nil {
		return nil, fmt.Errorf("DS query for %s: %w", target, err)
	}

	for _, rr := range dsResp.Answer {
		if _, ok := rr.(*dns.DS); ok {
			result.HasDS = true
			break
		}
	}

	// Query RRSIG records (query for A record with DNSSEC)
	rrsigMsg := new(dns.Msg)
	rrsigMsg.SetQuestion(fqdn, dns.TypeA)
	rrsigMsg.SetEdns0(4096, true)

	rrsigResp, _, err := client.ExchangeContext(ctx, rrsigMsg, server)
	if err != nil {
		return nil, fmt.Errorf("RRSIG query for %s: %w", target, err)
	}

	for _, rr := range rrsigResp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			result.HasRRSIG = true
			break
		}
	}

	// Check AD (Authenticated Data) flag
	// Send a query with the AD flag set and check if the response has AD
	adMsg := new(dns.Msg)
	adMsg.SetQuestion(fqdn, dns.TypeA)
	adMsg.SetEdns0(4096, true)
	adMsg.AuthenticatedData = true

	adResp, _, err := client.ExchangeContext(ctx, adMsg, server)
	if err != nil {
		return nil, fmt.Errorf("AD flag query for %s: %w", target, err)
	}

	result.ADFlag = adResp.AuthenticatedData

	// Determine overall status
	result.Enabled = result.HasDNSKEY || result.HasDS
	result.Valid = result.Enabled && result.HasRRSIG && result.ADFlag

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal DNSSEC result: %w", err)
	}
	return json.RawMessage(out), nil
}
