package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/stxkxs/matlock/internal/investigate"
)

type filesResult struct {
	Files          []fileEntry `json:"files"`
	HasSecurityTxt bool        `json:"has_security_txt"`
}

type fileEntry struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Exists      bool   `json:"exists"`
}

// Files probes for security.txt, robots.txt, sitemap.xml, and well-known files.
type Files struct{}

func (f *Files) Name() string        { return "files" }
func (f *Files) Description() string { return "Check for security.txt, robots.txt, and well-known files" }
func (f *Files) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (f *Files) Run(ctx context.Context, target string) (json.RawMessage, error) {
	paths := []string{
		"/.well-known/security.txt",
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/openid-configuration",
		"/.well-known/assetlinks.json",
		"/.well-known/apple-app-site-association",
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var entries []fileEntry
	hasSecurityTxt := false

	for _, p := range paths {
		url := fmt.Sprintf("https://%s%s", target, p)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			entries = append(entries, fileEntry{
				Path:   p,
				Status: 0,
				Exists: false,
			})
			continue
		}
		req.Header.Set("User-Agent", "matlock/1.0")

		resp, err := client.Do(req)
		if err != nil {
			entries = append(entries, fileEntry{
				Path:   p,
				Status: 0,
				Exists: false,
			})
			continue
		}
		resp.Body.Close()

		entry := fileEntry{
			Path:        p,
			Status:      resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Exists:      resp.StatusCode == http.StatusOK,
		}
		entries = append(entries, entry)

		if p == "/.well-known/security.txt" && entry.Exists {
			hasSecurityTxt = true
		}
	}

	result := filesResult{
		Files:          entries,
		HasSecurityTxt: hasSecurityTxt,
	}

	return json.Marshal(result)
}
