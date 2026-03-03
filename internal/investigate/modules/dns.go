package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/stxkxs/matlock/internal/investigate"
)

type dnsResult struct {
	A         []string          `json:"a"`
	AAAA      []string          `json:"aaaa"`
	MX        []mxRecord        `json:"mx"`
	NS        []string          `json:"ns"`
	TXT       []string          `json:"txt"`
	CAA       []caaRecord       `json:"caa"`
	DMARC     string            `json:"dmarc"`
	DKIM      map[string]string `json:"dkim"`
	NSCount   int               `json:"ns_count"`
	CAACount  int               `json:"caa_count"`
	DKIMCount int               `json:"dkim_count"`
}

type mxRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

type caaRecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// dnsModule performs DNS enumeration for a domain target.
type dnsModule struct {
	timeout  time.Duration
	resolver string
}

// NewDNSModule creates a DNS enumeration module.
func NewDNSModule() investigate.Module {
	resolver := systemResolver()
	return &dnsModule{
		timeout:  5 * time.Second,
		resolver: resolver,
	}
}

func (m *dnsModule) Name() string        { return "dns" }
func (m *dnsModule) Description() string  { return "DNS record enumeration (A, AAAA, MX, NS, TXT, CAA, DMARC, DKIM)" }
func (m *dnsModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *dnsModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	fqdn := dns.Fqdn(target)

	client := &dns.Client{
		Timeout: m.timeout,
	}

	result := dnsResult{
		A:    make([]string, 0),
		AAAA: make([]string, 0),
		MX:   make([]mxRecord, 0),
		NS:   make([]string, 0),
		TXT:  make([]string, 0),
		CAA:  make([]caaRecord, 0),
		DKIM: make(map[string]string),
	}

	var errs []string

	// A records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeA); err != nil {
		errs = append(errs, fmt.Sprintf("A: %v", err))
	} else {
		for _, rr := range records {
			if a, ok := rr.(*dns.A); ok {
				result.A = append(result.A, a.A.String())
			}
		}
	}

	// AAAA records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeAAAA); err != nil {
		errs = append(errs, fmt.Sprintf("AAAA: %v", err))
	} else {
		for _, rr := range records {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				result.AAAA = append(result.AAAA, aaaa.AAAA.String())
			}
		}
	}

	// MX records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeMX); err != nil {
		errs = append(errs, fmt.Sprintf("MX: %v", err))
	} else {
		for _, rr := range records {
			if mx, ok := rr.(*dns.MX); ok {
				result.MX = append(result.MX, mxRecord{
					Host:     strings.TrimSuffix(mx.Mx, "."),
					Priority: mx.Preference,
				})
			}
		}
	}

	// NS records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeNS); err != nil {
		errs = append(errs, fmt.Sprintf("NS: %v", err))
	} else {
		for _, rr := range records {
			if ns, ok := rr.(*dns.NS); ok {
				result.NS = append(result.NS, strings.TrimSuffix(ns.Ns, "."))
			}
		}
	}

	// TXT records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeTXT); err != nil {
		errs = append(errs, fmt.Sprintf("TXT: %v", err))
	} else {
		for _, rr := range records {
			if txt, ok := rr.(*dns.TXT); ok {
				result.TXT = append(result.TXT, strings.Join(txt.Txt, ""))
			}
		}
	}

	// CAA records
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	if records, err := m.query(client, fqdn, dns.TypeCAA); err != nil {
		errs = append(errs, fmt.Sprintf("CAA: %v", err))
	} else {
		for _, rr := range records {
			if caa, ok := rr.(*dns.CAA); ok {
				result.CAA = append(result.CAA, caaRecord{
					Flag:  caa.Flag,
					Tag:   caa.Tag,
					Value: caa.Value,
				})
			}
		}
	}

	// DMARC record
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns: context cancelled: %w", err)
	}
	dmarcDomain := dns.Fqdn("_dmarc." + target)
	if records, err := m.query(client, dmarcDomain, dns.TypeTXT); err != nil {
		errs = append(errs, fmt.Sprintf("DMARC: %v", err))
	} else {
		for _, rr := range records {
			if txt, ok := rr.(*dns.TXT); ok {
				joined := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.ToLower(joined), "v=dmarc1") {
					result.DMARC = joined
					break
				}
			}
		}
	}

	// DKIM selectors
	dkimSelectors := []string{
		"google", "default", "mail", "dkim", "s1", "s2",
		"k1", "selector1", "selector2", "mandrill",
	}
	for _, selector := range dkimSelectors {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("dns: context cancelled: %w", err)
		}
		dkimDomain := dns.Fqdn(selector + "._domainkey." + target)
		records, err := m.query(client, dkimDomain, dns.TypeTXT)
		if err != nil {
			continue
		}
		for _, rr := range records {
			if txt, ok := rr.(*dns.TXT); ok {
				joined := strings.Join(txt.Txt, "")
				if joined != "" {
					result.DKIM[selector] = joined
					break
				}
			}
		}
	}

	result.NSCount = len(result.NS)
	result.CAACount = len(result.CAA)
	result.DKIMCount = len(result.DKIM)

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("dns: marshal result: %w", err)
	}

	if len(errs) > 0 {
		return data, fmt.Errorf("dns: partial errors: %s", strings.Join(errs, "; "))
	}

	return data, nil
}

// query sends a single DNS query and returns the answer section.
func (m *dnsModule) query(client *dns.Client, name string, qtype uint16) ([]dns.RR, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, m.resolver)
	if err != nil {
		return nil, fmt.Errorf("exchange %s %s: %w", name, dns.TypeToString[qtype], err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil // no records is not an error
	}
	return resp.Answer, nil
}

// systemResolver returns the first nameserver from /etc/resolv.conf, falling back to 8.8.8.8:53.
func systemResolver() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return "8.8.8.8:53"
	}
	server := config.Servers[0]
	if net.ParseIP(server) != nil && !strings.Contains(server, ":") {
		server = server + ":53"
	} else if _, _, err := net.SplitHostPort(server); err != nil {
		server = server + ":53"
	}
	return server
}
