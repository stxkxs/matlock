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

type asnResult struct {
	IP       string      `json:"ip"`
	ASN      string      `json:"asn"`
	ASNName  string      `json:"asn_name"`
	Prefix   string      `json:"prefix"`
	Country  string      `json:"country"`
	Registry string      `json:"registry"`
	Prefixes []asnPrefix `json:"prefixes"`
}

type asnPrefix struct {
	Prefix string `json:"prefix"`
	Name   string `json:"name,omitempty"`
}

// ASNModule performs ASN lookup via Team Cymru DNS and HackerTarget API.
type ASNModule struct{}

func (m *ASNModule) Name() string        { return "asn" }
func (m *ASNModule) Description() string { return "ASN lookup via Team Cymru DNS and HackerTarget" }
func (m *ASNModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain, investigate.TargetIPv4, investigate.TargetIPv6}
}

func (m *ASNModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
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

	result := asnResult{
		IP: ip,
	}

	// Team Cymru DNS lookup: reverse octets and query origin.asn.cymru.com
	reversed := reverseIPOctets(ip)
	if reversed == "" {
		return nil, fmt.Errorf("unable to reverse IP octets for %s", ip)
	}

	originQuery := reversed + ".origin.asn.cymru.com"
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, originQuery)
	if err != nil {
		return nil, fmt.Errorf("team cymru origin lookup for %s: %w", ip, err)
	}

	// Response format: "ASN | Prefix | Country | Registry | Allocated"
	if len(txtRecords) > 0 {
		parts := strings.Split(txtRecords[0], "|")
		if len(parts) >= 5 {
			result.ASN = strings.TrimSpace(parts[0])
			result.Prefix = strings.TrimSpace(parts[1])
			result.Country = strings.TrimSpace(parts[2])
			result.Registry = strings.TrimSpace(parts[3])
		}
	}

	// Look up ASN name
	if result.ASN != "" {
		asnNum := result.ASN
		asnNameQuery := "AS" + asnNum + ".asn.cymru.com"
		asnTXT, err := net.DefaultResolver.LookupTXT(ctx, asnNameQuery)
		if err == nil && len(asnTXT) > 0 {
			// Response format: "ASN | Country | Registry | Allocated | ASN Name"
			parts := strings.Split(asnTXT[0], "|")
			if len(parts) >= 5 {
				result.ASNName = strings.TrimSpace(parts[4])
			}
		}
	}

	// Fetch prefix list from HackerTarget
	if result.ASN != "" {
		prefixes, err := fetchASNPrefixes(ctx, result.ASN)
		if err == nil {
			result.Prefixes = prefixes
		}
	}

	if result.Prefixes == nil {
		result.Prefixes = []asnPrefix{}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal ASN result: %w", err)
	}
	return json.RawMessage(out), nil
}

// reverseIPOctets reverses the octets of an IPv4 address for DNS queries.
// For IPv6, it returns the nibble-reversed form.
func reverseIPOctets(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
	}

	// IPv6: expand to full 32 hex nibbles and reverse
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	var nibbles []string
	for i := len(ip6) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", ip6[i]&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", (ip6[i]>>4)&0x0f))
	}
	return strings.Join(nibbles, ".")
}

// fetchASNPrefixes queries HackerTarget for prefixes announced by the ASN.
func fetchASNPrefixes(ctx context.Context, asn string) ([]asnPrefix, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/aslookup/?q=AS%s", asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create ASN prefix request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ASN prefix API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ASN prefix response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ASN prefix API returned status %d: %s", resp.StatusCode, string(body))
	}

	var prefixes []asnPrefix
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Lines may be "prefix, name" or just "prefix"
		parts := strings.SplitN(line, ",", 2)
		p := asnPrefix{
			Prefix: strings.TrimSpace(parts[0]),
		}
		if len(parts) > 1 {
			p.Name = strings.TrimSpace(parts[1])
		}
		prefixes = append(prefixes, p)
	}

	return prefixes, nil
}
