package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type ipResult struct {
	IP         string   `json:"ip"`
	ReverseDNS []string `json:"reverse_dns"`
	ASN        string   `json:"asn"`
	ASNName    string   `json:"asn_name"`
	Org        string   `json:"org"`
	Country    string   `json:"country"`
	Prefix     string   `json:"prefix"`
}

// IP performs reverse DNS, ASN lookup, and WHOIS summary for IP targets.
type IP struct{}

func (i *IP) Name() string        { return "ip" }
func (i *IP) Description() string { return "IP reconnaissance: reverse DNS, ASN, and WHOIS summary" }
func (i *IP) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetIPv4, investigate.TargetIPv6}
}

func (i *IP) Run(ctx context.Context, target string) (json.RawMessage, error) {
	result := ipResult{
		IP: target,
	}

	// Reverse DNS lookup.
	names, err := net.DefaultResolver.LookupAddr(ctx, target)
	if err == nil {
		for _, name := range names {
			result.ReverseDNS = append(result.ReverseDNS, strings.TrimSuffix(name, "."))
		}
	}

	// ASN lookup via Team Cymru DNS.
	asnInfo, err := lookupASNViaDNS(ctx, target)
	if err == nil {
		result.ASN = asnInfo.asn
		result.ASNName = asnInfo.name
		result.Country = asnInfo.country
		result.Prefix = asnInfo.prefix
	}

	// WHOIS summary.
	org, err := lookupWHOIS(ctx, target)
	if err == nil {
		result.Org = org
	}

	return json.Marshal(result)
}

type asnInfo struct {
	asn     string
	name    string
	country string
	prefix  string
}

func lookupASNViaDNS(ctx context.Context, ip string) (*asnInfo, error) {
	// Reverse the IP octets for DNS query.
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid ip: %s", ip)
	}

	var reversed string
	if v4 := parsed.To4(); v4 != nil {
		reversed = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com",
			v4[3], v4[2], v4[1], v4[0])
	} else {
		// IPv6: expand to full hex and reverse nibbles.
		expanded := parsed.To16()
		var nibbles []string
		for i := len(expanded) - 1; i >= 0; i-- {
			nibbles = append(nibbles, fmt.Sprintf("%x", expanded[i]&0x0f))
			nibbles = append(nibbles, fmt.Sprintf("%x", (expanded[i]>>4)&0x0f))
		}
		reversed = strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
	}

	// Query Team Cymru origin service.
	txts, err := net.DefaultResolver.LookupTXT(ctx, reversed)
	if err != nil {
		return nil, fmt.Errorf("asn dns lookup: %w", err)
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no asn dns result for %s", ip)
	}

	// Format: "ASN | Prefix | CC | Registry | Date"
	parts := strings.Split(txts[0], "|")
	info := &asnInfo{}
	if len(parts) >= 1 {
		info.asn = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		info.prefix = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		info.country = strings.TrimSpace(parts[2])
	}

	// Look up ASN name.
	if info.asn != "" {
		asnQuery := fmt.Sprintf("AS%s.asn.cymru.com", info.asn)
		nameTxts, err := net.DefaultResolver.LookupTXT(ctx, asnQuery)
		if err == nil && len(nameTxts) > 0 {
			// Format: "ASN | CC | Registry | Date | Name"
			nameParts := strings.Split(nameTxts[0], "|")
			if len(nameParts) >= 5 {
				info.name = strings.TrimSpace(nameParts[4])
			}
		}
	}

	return info, nil
}

func lookupWHOIS(ctx context.Context, ip string) (string, error) {
	var d net.Dialer
	d.Timeout = 5 * time.Second

	conn, err := d.DialContext(ctx, "tcp", "whois.arin.net:43")
	if err != nil {
		return "", fmt.Errorf("connect to whois: %w", err)
	}
	defer conn.Close()

	// Set deadline from context or fallback.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	_, err = fmt.Fprintf(conn, "n %s\r\n", ip)
	if err != nil {
		return "", fmt.Errorf("write whois query: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	var org string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "OrgName:") {
			org = strings.TrimSpace(strings.TrimPrefix(line, "OrgName:"))
			break
		}
		if strings.HasPrefix(line, "org-name:") {
			org = strings.TrimSpace(strings.TrimPrefix(line, "org-name:"))
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read whois response: %w", err)
	}

	return org, nil
}
