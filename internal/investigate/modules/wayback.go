package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/stxkxs/matlock/internal/investigate"
)

type waybackResult struct {
	Snapshots []waybackEntry `json:"snapshots"`
	Total     int            `json:"total"`
}

type waybackEntry struct {
	Timestamp  string `json:"timestamp"`
	URL        string `json:"url"`
	StatusCode string `json:"status_code"`
	MimeType   string `json:"mime_type"`
}

// WaybackModule queries the Wayback Machine CDX API for archived snapshots.
type WaybackModule struct{}

func (m *WaybackModule) Name() string        { return "wayback" }
func (m *WaybackModule) Description() string { return "Wayback Machine archived snapshot lookup" }
func (m *WaybackModule) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

func (m *WaybackModule) Run(ctx context.Context, target string) (json.RawMessage, error) {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&output=json&limit=100&fl=timestamp,original,statuscode,mimetype", target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create wayback request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read wayback response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback API returned status %d: %s", resp.StatusCode, string(body))
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		// CDX may return empty body for no results
		result := waybackResult{
			Snapshots: []waybackEntry{},
			Total:     0,
		}
		out, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal empty wayback result: %w", marshalErr)
		}
		return json.RawMessage(out), nil
	}

	result := waybackResult{}

	// First row is the header: [timestamp, original, statuscode, mimetype]
	// Skip it and parse remaining rows.
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 4 {
			continue
		}
		entry := waybackEntry{
			Timestamp:  row[0],
			URL:        row[1],
			StatusCode: row[2],
			MimeType:   row[3],
		}
		result.Snapshots = append(result.Snapshots, entry)
	}

	if result.Snapshots == nil {
		result.Snapshots = []waybackEntry{}
	}
	result.Total = len(result.Snapshots)

	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal wayback result: %w", err)
	}
	return json.RawMessage(out), nil
}
