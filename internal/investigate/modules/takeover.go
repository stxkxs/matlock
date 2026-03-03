package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/stxkxs/matlock/internal/investigate"
)

type takeoverResult struct {
	Vulnerable []takeoverEntry `json:"vulnerable"`
	Checked    int             `json:"checked"`
}

type takeoverEntry struct {
	Subdomain string `json:"subdomain"`
	CNAME     string `json:"cname"`
	Service   string `json:"service"`
	Dangling  bool   `json:"dangling"`
	Risk      string `json:"risk"`
}

type servicePattern struct {
	suffix  string
	service string
}

// Takeover checks subdomains for potential subdomain takeover vulnerabilities.
type Takeover struct{}

func (t *Takeover) Name() string        { return "takeover" }
func (t *Takeover) Description() string { return "Detect potential subdomain takeover vulnerabilities" }
func (t *Takeover) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

var (
	takeoverSubdomains = []string{
		"www", "app", "api", "blog", "docs", "dev",
		"staging", "test", "beta", "cdn", "assets",
		"mail", "admin",
	}

	vulnerableServices = []servicePattern{
		{suffix: ".github.io", service: "GitHub Pages"},
		{suffix: ".herokuapp.com", service: "Heroku"},
		{suffix: ".s3.amazonaws.com", service: "AWS S3"},
		{suffix: ".s3-website", service: "AWS S3"},
		{suffix: ".azurewebsites.net", service: "Azure"},
		{suffix: ".cloudapp.azure.com", service: "Azure"},
		{suffix: ".blob.core.windows.net", service: "Azure"},
		{suffix: ".trafficmanager.net", service: "Azure"},
		{suffix: ".myshopify.com", service: "Shopify"},
		{suffix: ".netlify.app", service: "Netlify"},
		{suffix: ".netlify.com", service: "Netlify"},
		{suffix: ".vercel.app", service: "Vercel"},
		{suffix: ".surge.sh", service: "Surge"},
		{suffix: ".pantheonsite.io", service: "Pantheon"},
		{suffix: ".wordpress.com", service: "WordPress"},
		{suffix: ".ghost.io", service: "Ghost"},
		{suffix: ".fly.dev", service: "Fly.io"},
		{suffix: ".unbouncepages.com", service: "Unbounce"},
	}
)

func (t *Takeover) Run(ctx context.Context, target string) (json.RawMessage, error) {
	var vulnerable []takeoverEntry
	checked := 0

	for _, sub := range takeoverSubdomains {
		fqdn := fmt.Sprintf("%s.%s", sub, target)
		checked++

		// Look up CNAME.
		cname, err := net.DefaultResolver.LookupCNAME(ctx, fqdn)
		if err != nil {
			continue
		}
		cname = strings.TrimSuffix(cname, ".")

		// If CNAME is the same as the queried name, skip (no CNAME record).
		if strings.EqualFold(cname, fqdn) {
			continue
		}

		// Check CNAME against vulnerable service patterns.
		service := matchService(cname)
		if service == "" {
			continue
		}

		// Check if the CNAME is dangling (NXDOMAIN).
		dangling := isDangling(ctx, cname)

		risk := "low"
		if dangling {
			risk = "critical"
		} else {
			risk = "info"
		}

		vulnerable = append(vulnerable, takeoverEntry{
			Subdomain: fqdn,
			CNAME:     cname,
			Service:   service,
			Dangling:  dangling,
			Risk:      risk,
		})
	}

	result := takeoverResult{
		Vulnerable: vulnerable,
		Checked:    checked,
	}

	return json.Marshal(result)
}

func matchService(cname string) string {
	lower := strings.ToLower(cname)
	for _, sp := range vulnerableServices {
		if strings.HasSuffix(lower, sp.suffix) {
			return sp.service
		}
	}
	return ""
}

func isDangling(ctx context.Context, hostname string) bool {
	_, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		// If LookupHost fails, it is likely NXDOMAIN or similar: treat as dangling.
		if dnsErr, ok := err.(*net.DNSError); ok {
			return dnsErr.IsNotFound
		}
		return false
	}
	return false
}
