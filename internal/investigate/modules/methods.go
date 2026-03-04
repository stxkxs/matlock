package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/stxkxs/matlock/internal/investigate"
)

type methodsResult struct {
	Endpoints []methodEndpoint `json:"endpoints"`
	Risky     []riskyMethod    `json:"risky"`
}

type methodEndpoint struct {
	Path    string   `json:"path"`
	Allowed []string `json:"allowed"`
}

type riskyMethod struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Risk   string `json:"risk"`
	Detail string `json:"detail,omitempty"`
}

// Methods enumerates allowed HTTP methods and detects risky configurations.
type Methods struct{}

func (m *Methods) Name() string        { return "methods" }
func (m *Methods) Description() string { return "Enumerate allowed HTTP methods and detect risky configurations" }
func (m *Methods) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *Methods) Run(ctx context.Context, target string) (json.RawMessage, error) {
	paths := []string{"/", "/api/", "/api/v1/", "/admin/"}
	dangerousMethods := []string{"TRACE", "PUT", "DELETE", "PATCH"}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var endpoints []methodEndpoint
	var risky []riskyMethod

	for _, p := range paths {
		baseURL := fmt.Sprintf("https://%s%s", target, p)

		// Send OPTIONS request to discover allowed methods.
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, baseURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "matlock/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		allow := resp.Header.Get("Allow")
		var allowed []string
		if allow != "" {
			for _, method := range strings.Split(allow, ",") {
				method = strings.TrimSpace(method)
				if method != "" {
					allowed = append(allowed, method)
				}
			}
		}

		endpoints = append(endpoints, methodEndpoint{
			Path:    p,
			Allowed: allowed,
		})

		// Test dangerous methods.
		for _, method := range dangerousMethods {
			req, err := http.NewRequestWithContext(ctx, method, baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "matlock/1.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			var detail string
			// Check for XST vulnerability: TRACE returns request body.
			if method == "TRACE" && resp.StatusCode == http.StatusOK {
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
				if readErr == nil && len(body) > 0 {
					detail = "TRACE reflects request body (XST vulnerability)"
				}
			}
			resp.Body.Close()

			// Methods that return non-405 are potentially risky.
			if resp.StatusCode != http.StatusMethodNotAllowed {
				risk := classifyMethodRisk(method, resp.StatusCode)
				if risk != "" {
					entry := riskyMethod{
						Path:   p,
						Method: method,
						Status: resp.StatusCode,
						Risk:   risk,
						Detail: detail,
					}
					risky = append(risky, entry)
				}
			}
		}
	}

	result := methodsResult{
		Endpoints: endpoints,
		Risky:     risky,
	}

	return json.Marshal(result)
}

func classifyMethodRisk(method string, status int) string {
	switch method {
	case "TRACE":
		if status == http.StatusOK {
			return "high"
		}
		return "medium"
	case "PUT", "DELETE":
		if status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent {
			return "high"
		}
		if status != http.StatusMethodNotAllowed && status != http.StatusForbidden {
			return "medium"
		}
	case "PATCH":
		if status == http.StatusOK || status == http.StatusNoContent {
			return "medium"
		}
	}
	return ""
}
