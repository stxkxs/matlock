package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/stxkxs/matlock/internal/investigate"
)

type dirsResult struct {
	Found         []dirEntry `json:"found"`
	TotalChecked  int        `json:"total_checked"`
	CriticalCount int        `json:"critical_count"`
}

type dirEntry struct {
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

type dirProbe struct {
	path     string
	category string
	severity string
}

// Dirs discovers exposed directories, sensitive files, and debug endpoints.
type Dirs struct{}

func (d *Dirs) Name() string        { return "dirs" }
func (d *Dirs) Description() string { return "Discover exposed directories, sensitive files, and debug endpoints" }
func (d *Dirs) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (d *Dirs) Run(ctx context.Context, target string) (json.RawMessage, error) {
	probes := []dirProbe{
		// Version control
		{path: "/.git/config", category: "version_control", severity: "critical"},
		{path: "/.svn/entries", category: "version_control", severity: "critical"},
		{path: "/.hg", category: "version_control", severity: "critical"},
		{path: "/.bzr", category: "version_control", severity: "critical"},

		// Config files
		{path: "/.env", category: "config", severity: "critical"},
		{path: "/.env.local", category: "config", severity: "critical"},
		{path: "/.env.production", category: "config", severity: "critical"},
		{path: "/wp-config.php", category: "config", severity: "critical"},
		{path: "/database.yml", category: "config", severity: "critical"},
		{path: "/appsettings.json", category: "config", severity: "critical"},
		{path: "/config.yml", category: "config", severity: "critical"},
		{path: "/.dockerenv", category: "config", severity: "critical"},

		// Admin panels
		{path: "/admin/", category: "admin", severity: "high"},
		{path: "/wp-admin/", category: "admin", severity: "high"},
		{path: "/phpmyadmin/", category: "admin", severity: "high"},
		{path: "/adminer/", category: "admin", severity: "high"},

		// API docs
		{path: "/swagger.json", category: "api_docs", severity: "medium"},
		{path: "/swagger-ui/", category: "api_docs", severity: "medium"},
		{path: "/graphql", category: "api_docs", severity: "medium"},
		{path: "/openapi.json", category: "api_docs", severity: "medium"},
		{path: "/api-docs", category: "api_docs", severity: "medium"},

		// Debug
		{path: "/phpinfo.php", category: "debug", severity: "high"},
		{path: "/debug/", category: "debug", severity: "high"},
		{path: "/elmah.axd", category: "debug", severity: "high"},
		{path: "/.DS_Store", category: "debug", severity: "high"},
		{path: "/trace", category: "debug", severity: "high"},
		{path: "/server-status", category: "debug", severity: "high"},

		// Backup
		{path: "/backup/", category: "backup", severity: "critical"},
		{path: "/backup.sql", category: "backup", severity: "critical"},
		{path: "/db.sql", category: "backup", severity: "critical"},
		{path: "/dump.sql", category: "backup", severity: "critical"},

		// Actuator
		{path: "/actuator", category: "actuator", severity: "medium"},
		{path: "/actuator/health", category: "actuator", severity: "medium"},
		{path: "/actuator/env", category: "actuator", severity: "medium"},
		{path: "/metrics", category: "actuator", severity: "medium"},
		{path: "/jolokia", category: "actuator", severity: "medium"},
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type indexedEntry struct {
		index int
		entry dirEntry
	}

	var mu sync.Mutex
	var found []indexedEntry
	criticalCount := 0

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for i, probe := range probes {
		wg.Add(1)
		go func(idx int, p dirProbe) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("https://%s%s", target, p.path)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "matlock/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			// Record interesting status codes.
			switch resp.StatusCode {
			case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden,
				http.StatusMovedPermanently, http.StatusFound:
			default:
				return
			}

			severity := p.severity
			// Downgrade severity for 403/redirect responses.
			if resp.StatusCode == http.StatusForbidden ||
				resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusFound {
				severity = "low"
			}

			entry := dirEntry{
				Path:     p.path,
				Status:   resp.StatusCode,
				Severity: severity,
				Category: p.category,
			}

			mu.Lock()
			found = append(found, indexedEntry{index: idx, entry: entry})
			if severity == "critical" {
				criticalCount++
			}
			mu.Unlock()
		}(i, probe)
	}

	wg.Wait()

	// Sort by original probe order.
	sortedFound := make([]dirEntry, 0, len(found))
	if len(found) > 0 {
		// Simple insertion sort by index to preserve probe order.
		ordered := make([]indexedEntry, len(found))
		copy(ordered, found)
		for i := 1; i < len(ordered); i++ {
			key := ordered[i]
			j := i - 1
			for j >= 0 && ordered[j].index > key.index {
				ordered[j+1] = ordered[j]
				j--
			}
			ordered[j+1] = key
		}
		for _, ie := range ordered {
			sortedFound = append(sortedFound, ie.entry)
		}
	}

	result := dirsResult{
		Found:         sortedFound,
		TotalChecked:  len(probes),
		CriticalCount: criticalCount,
	}

	return json.Marshal(result)
}
