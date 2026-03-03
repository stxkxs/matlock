package investigate

import (
	"encoding/json"
	"testing"
)

func TestCalculateScoreAllPass(t *testing.T) {
	report := &Report{
		Results: map[string]ModuleResult{
			"http": {
				Status: "success",
				Data: mustJSON(map[string]interface{}{
					"https_reachable": true,
					"redirects_https": true,
					"security_headers": map[string]string{
						"strict-transport-security": "max-age=31536000",
						"content-security-policy":   "default-src 'self'",
						"x-frame-options":           "DENY",
						"x-content-type-options":    "nosniff",
						"referrer-policy":           "strict-origin",
						"permissions-policy":        "camera=()",
					},
				}),
			},
			"dns": {
				Status: "success",
				Data: mustJSON(map[string]interface{}{
					"txt":        []string{"v=spf1 include:_spf.google.com -all"},
					"dmarc":      "v=DMARC1; p=reject",
					"dkim_count": 2,
					"ns_count":   3,
					"caa_count":  1,
				}),
			},
			"ssl": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"valid": true}),
			},
			"files": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"has_security_txt": true}),
			},
			"dirs": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"critical_count": 0}),
			},
			"jsanalysis": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"secrets_count": 0}),
			},
		},
	}

	score := CalculateScore(report)
	if score.Grade != "A" {
		t.Errorf("expected grade A, got %s (score: %d/%d = %d%%)", score.Grade, score.Score, score.MaxScore, score.Percentage)
	}
	if score.Failed != 0 {
		t.Errorf("expected 0 failed checks, got %d", score.Failed)
	}
	if len(score.Recommendations) != 0 {
		t.Errorf("expected 0 recommendations, got %d", len(score.Recommendations))
	}
}

func TestCalculateScoreAllFail(t *testing.T) {
	report := &Report{
		Results: map[string]ModuleResult{},
	}

	score := CalculateScore(report)
	if score.Grade != "F" {
		t.Errorf("expected grade F, got %s", score.Grade)
	}
	// With no module data, most checks fail. However, "no sensitive dirs"
	// and "no JS secrets" pass because missing data defaults to 0 count.
	if score.Passed < 2 {
		t.Errorf("expected at least 2 passed (exposure checks default-pass), got %d", score.Passed)
	}
	if score.Failed == 0 {
		t.Error("expected some failed checks")
	}
	if len(score.Recommendations) == 0 {
		t.Error("expected recommendations for failing checks")
	}
}

func TestCalculateScorePartial(t *testing.T) {
	report := &Report{
		Results: map[string]ModuleResult{
			"http": {
				Status: "success",
				Data: mustJSON(map[string]interface{}{
					"https_reachable": true,
					"redirects_https": true,
					"security_headers": map[string]string{
						"strict-transport-security": "max-age=31536000",
						"content-security-policy":   "default-src 'self'",
						"x-frame-options":           "DENY",
						"x-content-type-options":    "nosniff",
						"referrer-policy":           "strict-origin",
					},
				}),
			},
			"dns": {
				Status: "success",
				Data: mustJSON(map[string]interface{}{
					"txt":        []string{"v=spf1 -all"},
					"dmarc":      "v=DMARC1; p=reject",
					"dkim_count": 1,
					"ns_count":   2,
					"caa_count":  1,
				}),
			},
			"ssl": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"valid": true}),
			},
			"files": {
				Status: "success",
				Data:   mustJSON(map[string]interface{}{"has_security_txt": true}),
			},
		},
	}

	score := CalculateScore(report)
	// Should get a good-but-not-perfect grade (missing permissions-policy).
	if score.Grade == "F" {
		t.Errorf("expected non-F grade, got %s (score: %d/%d = %d%%)", score.Grade, score.Score, score.MaxScore, score.Percentage)
	}
	if score.Passed == 0 {
		t.Error("expected some passing checks")
	}
	if score.Failed == 0 {
		t.Error("expected some failing checks")
	}
}

func TestJsonPath(t *testing.T) {
	data := mustJSON(map[string]interface{}{
		"a": "hello",
		"b": true,
		"c": 42,
		"nested": map[string]interface{}{
			"deep": "value",
		},
	})
	if got := jsonPath(data, "a"); got != "hello" {
		t.Errorf("jsonPath(a) = %q, want %q", got, "hello")
	}
	if got := jsonPath(data, "b"); got != "true" {
		t.Errorf("jsonPath(b) = %q, want %q", got, "true")
	}
	if got := jsonPath(data, "c"); got != "42" {
		t.Errorf("jsonPath(c) = %q, want %q", got, "42")
	}
	if got := jsonPath(data, "nested.deep"); got != "value" {
		t.Errorf("jsonPath(nested.deep) = %q, want %q", got, "value")
	}
	if got := jsonPath(data, "nonexistent"); got != "" {
		t.Errorf("jsonPath(nonexistent) = %q, want empty", got)
	}
}

func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(b)
}
