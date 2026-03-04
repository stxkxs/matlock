package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stxkxs/matlock/internal/investigate"
)

type httpResult struct {
	HTTPSReachable bool              `json:"https_reachable"`
	RedirectsHTTPS bool              `json:"redirects_https"`
	StatusCode     int               `json:"status_code"`
	Server         string            `json:"server"`
	SecurityHeaders map[string]string `json:"security_headers"`
	Infrastructure  map[string]string `json:"infrastructure"`
	RedirectChain   []string          `json:"redirect_chain,omitempty"`
}

// httpModule performs HTTP header and security header analysis.
type httpModule struct {
	timeout time.Duration
}

// NewHTTPModule creates an HTTP header analysis module.
func NewHTTPModule() investigate.Module {
	return &httpModule{
		timeout: 10 * time.Second,
	}
}

func (m *httpModule) Name() string        { return "http" }
func (m *httpModule) Description() string  { return "HTTP header and security header analysis" }
func (m *httpModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

// securityHeaders lists HTTP security headers to check.
var securityHeaders = []string{
	"strict-transport-security",
	"x-frame-options",
	"content-security-policy",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"x-xss-protection",
	"cross-origin-opener-policy",
	"cross-origin-resource-policy",
}

// infraHeaders lists headers that hint at infrastructure / CDN providers.
var infraHeaders = []string{
	"x-cdn",
	"x-akamai-transformed",
	"x-amz-cf-id",
	"x-amz-cf-pop",
	"x-azure-ref",
	"via",
	"cf-ray",
	"x-served-by",
}

func (m *httpModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	result := httpResult{
		SecurityHeaders: make(map[string]string),
		Infrastructure:  make(map[string]string),
	}

	// Check HTTPS
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("http: context cancelled: %w", err)
	}

	var redirectChain []string
	httpsClient := m.newClient(&redirectChain)

	httpsURL := "https://" + target
	httpsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http: create https request: %w", err)
	}
	httpsReq.Header.Set("User-Agent", "matlock/1.0 security-scanner")

	httpsResp, httpsErr := httpsClient.Do(httpsReq)
	if httpsErr == nil {
		defer httpsResp.Body.Close()
		result.HTTPSReachable = true
		result.StatusCode = httpsResp.StatusCode
		result.Server = httpsResp.Header.Get("Server")

		// Extract security headers
		for _, name := range securityHeaders {
			if val := httpsResp.Header.Get(name); val != "" {
				result.SecurityHeaders[name] = val
			}
		}

		// Extract infrastructure headers
		for _, name := range infraHeaders {
			if val := httpsResp.Header.Get(name); val != "" {
				result.Infrastructure[name] = val
			}
		}

		if len(redirectChain) > 0 {
			result.RedirectChain = redirectChain
		}
	}

	// Check HTTP and whether it redirects to HTTPS
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("http: context cancelled: %w", err)
	}

	var httpRedirects []string
	httpClient := m.newClient(&httpRedirects)

	httpURL := "http://" + target
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http: create http request: %w", err)
	}
	httpReq.Header.Set("User-Agent", "matlock/1.0 security-scanner")

	httpResp, httpErr := httpClient.Do(httpReq)
	if httpErr == nil {
		defer httpResp.Body.Close()

		// Check if any redirect in the chain went to HTTPS
		for _, loc := range httpRedirects {
			if strings.HasPrefix(strings.ToLower(loc), "https://") {
				result.RedirectsHTTPS = true
				break
			}
		}

		// If we didn't get HTTPS info, use HTTP info
		if !result.HTTPSReachable {
			result.StatusCode = httpResp.StatusCode
			result.Server = httpResp.Header.Get("Server")

			for _, name := range securityHeaders {
				if val := httpResp.Header.Get(name); val != "" {
					result.SecurityHeaders[name] = val
				}
			}
			for _, name := range infraHeaders {
				if val := httpResp.Header.Get(name); val != "" {
					result.Infrastructure[name] = val
				}
			}
		}
	}

	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, fmt.Errorf("http: marshal result: %w", marshalErr)
	}

	// If both HTTPS and HTTP failed, return partial data with an error
	if httpsErr != nil && httpErr != nil {
		return data, fmt.Errorf("http: https: %v; http: %v", httpsErr, httpErr)
	}

	return data, nil
}

// newClient creates an HTTP client that captures redirect URLs instead of following them automatically.
func (m *httpModule) newClient(chain *[]string) *http.Client {
	return &http.Client{
		Timeout: m.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			*chain = append(*chain, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}
