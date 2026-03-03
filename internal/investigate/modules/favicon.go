package modules

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/stxkxs/matlock/internal/investigate"
)

type faviconResult struct {
	URL         string `json:"url"`
	MD5         string `json:"md5"`
	MMH3        int32  `json:"mmh3"`
	ShodanQuery string `json:"shodan_query"`
	Size        int    `json:"size"`
}

// Favicon fetches favicon.ico, computes MD5 and MurmurHash3, and generates a Shodan query.
type Favicon struct{}

func (f *Favicon) Name() string        { return "favicon" }
func (f *Favicon) Description() string { return "Favicon hash fingerprinting for Shodan lookups" }
func (f *Favicon) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

var faviconLinkRe = regexp.MustCompile(`<link[^>]+rel=["'](?:icon|shortcut icon)["'][^>]+href=["']([^"']+)["']`)

func (f *Favicon) Run(ctx context.Context, target string) (json.RawMessage, error) {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try /favicon.ico first.
	faviconURL := fmt.Sprintf("https://%s/favicon.ico", target)
	data, err := fetchFavicon(ctx, client, faviconURL)
	if err != nil || len(data) == 0 {
		// Fall back: fetch HTML and look for <link rel="icon"> or <link rel="shortcut icon">.
		altURL, findErr := findFaviconInHTML(ctx, client, target)
		if findErr != nil {
			if err != nil {
				return nil, fmt.Errorf("fetch favicon: %w", err)
			}
			return nil, fmt.Errorf("find favicon in html: %w", findErr)
		}
		faviconURL = altURL
		data, err = fetchFavicon(ctx, client, faviconURL)
		if err != nil {
			return nil, fmt.Errorf("fetch favicon from html link: %w", err)
		}
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no favicon data found for %s", target)
	}

	// Compute MD5 hash.
	md5Sum := fmt.Sprintf("%x", md5.Sum(data))

	// Compute MurmurHash3 (Shodan style): base64 encode then hash.
	b64 := base64.StdEncoding.EncodeToString(data)
	mmh3 := murmur3Hash32([]byte(b64))

	result := faviconResult{
		URL:         faviconURL,
		MD5:         md5Sum,
		MMH3:        mmh3,
		ShodanQuery: fmt.Sprintf("http.favicon.hash:%d", mmh3),
		Size:        len(data),
	}

	return json.Marshal(result)
}

func fetchFavicon(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create favicon request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch favicon url: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read favicon body: %w", err)
	}
	return data, nil
}

func findFaviconInHTML(ctx context.Context, client *http.Client, target string) (string, error) {
	htmlURL := fmt.Sprintf("https://%s", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, htmlURL, nil)
	if err != nil {
		return "", fmt.Errorf("create html request: %w", err)
	}
	req.Header.Set("User-Agent", "matlock/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch html: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read html body: %w", err)
	}

	matches := faviconLinkRe.FindSubmatch(body)
	if matches == nil {
		return "", fmt.Errorf("no favicon link found in html")
	}

	href := string(matches[1])
	return resolveURL(htmlURL, href), nil
}

// murmur3Hash32 implements the MurmurHash3 32-bit hash function.
func murmur3Hash32(data []byte) int32 {
	const (
		c1   uint32 = 0xcc9e2d51
		c2   uint32 = 0x1b873593
		seed uint32 = 0
	)

	h := seed
	length := len(data)
	nblocks := length / 4

	// Body: process 4-byte blocks.
	for i := 0; i < nblocks; i++ {
		offset := i * 4
		k := uint32(data[offset]) |
			uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 |
			uint32(data[offset+3])<<24

		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2

		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}

	// Tail: process remaining bytes.
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h ^= k1
	}

	// Finalization mix.
	h ^= uint32(length)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return int32(h)
}
