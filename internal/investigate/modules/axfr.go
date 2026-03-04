package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/stxkxs/matlock/internal/investigate"
)

type axfrResult struct {
	Vulnerable bool         `json:"vulnerable"`
	Tested     []axfrServer `json:"tested"`
	Records    []axfrRecord `json:"records,omitempty"`
}

type axfrServer struct {
	NS          string `json:"ns"`
	Success     bool   `json:"success"`
	RecordCount int    `json:"record_count"`
	Error       string `json:"error,omitempty"`
}

type axfrRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AXFRModule tests DNS zone transfer vulnerability.
type AXFRModule struct{}

func (m *AXFRModule) Name() string        { return "axfr" }
func (m *AXFRModule) Description() string { return "DNS zone transfer (AXFR) vulnerability test" }
func (m *AXFRModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *AXFRModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	fqdn := dns.Fqdn(target)
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}
	server := "8.8.8.8:53"

	// Get authoritative NS records
	nsMsg := new(dns.Msg)
	nsMsg.SetQuestion(fqdn, dns.TypeNS)

	nsResp, _, err := client.ExchangeContext(ctx, nsMsg, server)
	if err != nil {
		return nil, fmt.Errorf("NS query for %s: %w", target, err)
	}

	var nameservers []string
	for _, rr := range nsResp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", target)
	}

	result := axfrResult{}
	const maxRecords = 500

	for _, ns := range nameservers {
		serverEntry := axfrServer{
			NS: strings.TrimSuffix(ns, "."),
		}

		records, err := attemptAXFR(ctx, fqdn, ns)
		if err != nil {
			serverEntry.Error = err.Error()
			result.Tested = append(result.Tested, serverEntry)
			continue
		}

		serverEntry.Success = true
		serverEntry.RecordCount = len(records)
		result.Tested = append(result.Tested, serverEntry)
		result.Vulnerable = true

		// Collect records up to the cap
		for _, r := range records {
			if len(result.Records) >= maxRecords {
				break
			}
			result.Records = append(result.Records, r)
		}
	}

	if result.Tested == nil {
		result.Tested = []axfrServer{}
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal AXFR result: %w", err)
	}
	return json.RawMessage(out), nil
}

// attemptAXFR tries a zone transfer against the given nameserver.
func attemptAXFR(ctx context.Context, fqdn string, ns string) ([]axfrRecord, error) {
	transfer := &dns.Transfer{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	axfrMsg := new(dns.Msg)
	axfrMsg.SetAxfr(fqdn)

	nsAddr := ns
	if !strings.Contains(nsAddr, ":") {
		nsAddr = nsAddr + ":53"
	}

	env, err := transfer.In(axfrMsg, nsAddr)
	if err != nil {
		return nil, fmt.Errorf("AXFR to %s: %w", ns, err)
	}

	var records []axfrRecord
	for envelope := range env {
		if envelope.Error != nil {
			// If we already got some records, return what we have
			if len(records) > 0 {
				break
			}
			return nil, fmt.Errorf("AXFR envelope from %s: %w", ns, envelope.Error)
		}
		for _, rr := range envelope.RR {
			if ctx.Err() != nil {
				return records, fmt.Errorf("context cancelled during AXFR: %w", ctx.Err())
			}

			record := axfrRecord{
				Name:  rr.Header().Name,
				Type:  dns.TypeToString[rr.Header().Rrtype],
				Value: extractRRValue(rr),
			}
			records = append(records, record)

			if len(records) >= 500 {
				return records, nil
			}
		}
	}

	return records, nil
}

// extractRRValue returns the value portion of a DNS resource record.
func extractRRValue(rr dns.RR) string {
	// The full string representation includes the header; strip it.
	full := rr.String()
	header := rr.Header().String()
	value := strings.TrimPrefix(full, header)
	return strings.TrimSpace(value)
}
