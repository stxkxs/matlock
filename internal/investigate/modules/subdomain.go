package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/stxkxs/matlock/internal/investigate"
)

var defaultWordlist = []string{
	"www", "app", "api", "blog", "docs", "developer", "dev", "help",
	"support", "status", "mail", "admin", "staging", "test", "beta",
	"cdn", "assets", "static", "ws", "graphql", "oauth", "auth",
	"sso", "login", "portal", "dashboard", "console", "manage",
	"git", "gitlab", "ci", "metrics", "grafana", "kibana", "elastic",
	"internal", "corp", "vpn", "intranet", "billing", "payments",
	"mobile", "m", "sandbox", "demo", "preview", "smtp", "email",
	"imap", "calendar", "search", "analytics", "db", "redis", "cache",
	"queue", "jobs", "workers", "reporting", "reports", "web", "ns1",
	"ns2", "ftp", "proxy", "gateway", "store", "shop", "media",
	"images", "img", "video", "download", "upload", "files", "backup",
	"monitor", "logs", "vault", "secrets", "config", "registry",
	"docker", "k8s", "kubernetes", "jenkins", "drone", "argo",
	"prometheus", "alertmanager", "jaeger", "tracing", "ntp", "ldap",
	"ad", "exchange", "webmail", "autodiscover", "relay", "mx",
	"pop", "pop3",
}

type subdomainResult struct {
	Found []subdomainEntry `json:"found"`
	Total int              `json:"total_checked"`
}

type subdomainEntry struct {
	FQDN  string   `json:"fqdn"`
	IPs   []string `json:"ips"`
	CNAME string   `json:"cname,omitempty"`
}

// SubdomainModule brute-forces subdomains via DNS resolution.
type SubdomainModule struct{}

func (m *SubdomainModule) Name() string        { return "subdomain" }
func (m *SubdomainModule) Description() string { return "Subdomain brute-force via DNS resolution" }
func (m *SubdomainModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *SubdomainModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	const maxConcurrency = 20

	var (
		mu      sync.Mutex
		found   []subdomainEntry
		sem     = make(chan struct{}, maxConcurrency)
		wg      sync.WaitGroup
		resolver = net.DefaultResolver
	)

	for _, sub := range defaultWordlist {
		select {
		case <-ctx.Done():
			break
		default:
		}

		fqdn := fmt.Sprintf("%s.%s", sub, target)
		sem <- struct{}{}
		wg.Add(1)

		go func(fqdn string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil {
				return
			}
			if len(ips) == 0 {
				return
			}

			entry := subdomainEntry{
				FQDN: fqdn,
				IPs:  ips,
			}

			cname, err := resolver.LookupCNAME(ctx, fqdn)
			if err == nil {
				cname = strings.TrimSuffix(cname, ".")
				if cname != "" && !strings.EqualFold(cname, fqdn) {
					entry.CNAME = cname
				}
			}

			mu.Lock()
			found = append(found, entry)
			mu.Unlock()
		}(fqdn)
	}

	wg.Wait()

	result := subdomainResult{
		Found: found,
		Total: len(defaultWordlist),
	}
	if result.Found == nil {
		result.Found = []subdomainEntry{}
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("subdomain marshal result: %w", err)
	}
	return data, nil
}
