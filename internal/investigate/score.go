package investigate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CalculateScore runs a weighted security assessment across module results.
// Categories (100 pts total):
//   - Transport Security: 25 pts
//   - Email Security: 15 pts
//   - Certificate Health: 15 pts
//   - Security Headers: 25 pts
//   - Infrastructure: 10 pts
//   - Information Exposure: 10 pts
func CalculateScore(report *Report) *ScoreResult {
	var checks []ScoreCheck

	// helpers
	getString := func(module, path string) string {
		mr, ok := report.Results[module]
		if !ok || mr.Data == nil {
			return ""
		}
		return jsonPath(mr.Data, path)
	}
	getBool := func(module, path string) bool {
		return getString(module, path) == "true"
	}
	getInt := func(module, path string) int {
		s := getString(module, path)
		var n int
		for _, c := range s {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				break
			}
		}
		return n
	}

	// ── Transport Security (25 pts) ──

	// HTTPS reachable (10)
	httpsOK := getBool("http", "https_reachable")
	checks = append(checks, scoreCheck("transport", "HTTPS available", httpsOK, 10,
		"Enable HTTPS on your web server"))

	// HSTS (10)
	hsts := getString("http", "security_headers.strict-transport-security")
	checks = append(checks, scoreCheck("transport", "HSTS enabled", hsts != "", 10,
		"Add Strict-Transport-Security header"))

	// HTTP redirect (5)
	redirectOK := getBool("http", "redirects_https")
	checks = append(checks, scoreCheck("transport", "HTTP redirects to HTTPS", redirectOK, 5,
		"Redirect HTTP to HTTPS"))

	// ── Email Security (15 pts) ──

	// SPF (5)
	hasSPF := false
	txtRaw := getString("dns", "txt")
	if strings.Contains(txtRaw, "v=spf1") {
		hasSPF = true
	}
	checks = append(checks, scoreCheck("email", "SPF record", hasSPF, 5,
		"Add SPF TXT record to prevent email spoofing"))

	// DMARC (5)
	dmarc := getString("dns", "dmarc")
	checks = append(checks, scoreCheck("email", "DMARC record", dmarc != "" && dmarc != "null", 5,
		"Add DMARC record for email authentication"))

	// DKIM (5)
	dkimCount := getInt("dns", "dkim_count")
	checks = append(checks, scoreCheck("email", "DKIM record", dkimCount > 0, 5,
		"Configure DKIM for email signing"))

	// ── Certificate Health (15 pts) ──

	// Valid SSL (10)
	sslValid := getBool("ssl", "valid")
	checks = append(checks, scoreCheck("certificate", "Valid SSL certificate", sslValid, 10,
		"Install a valid SSL certificate"))

	// CAA record (5)
	caaCount := getInt("dns", "caa_count")
	checks = append(checks, scoreCheck("certificate", "CAA record", caaCount > 0, 5,
		"Add CAA DNS record to restrict certificate issuance"))

	// ── Security Headers (25 pts) ──

	csp := getString("http", "security_headers.content-security-policy")
	checks = append(checks, scoreCheck("headers", "Content-Security-Policy", csp != "", 8,
		"Add Content-Security-Policy header to prevent XSS"))

	xfo := getString("http", "security_headers.x-frame-options")
	checks = append(checks, scoreCheck("headers", "X-Frame-Options", xfo != "", 5,
		"Add X-Frame-Options header to prevent clickjacking"))

	xcto := getString("http", "security_headers.x-content-type-options")
	checks = append(checks, scoreCheck("headers", "X-Content-Type-Options", xcto != "", 4,
		"Add X-Content-Type-Options: nosniff header"))

	rp := getString("http", "security_headers.referrer-policy")
	checks = append(checks, scoreCheck("headers", "Referrer-Policy", rp != "", 4,
		"Add Referrer-Policy header"))

	pp := getString("http", "security_headers.permissions-policy")
	checks = append(checks, scoreCheck("headers", "Permissions-Policy", pp != "", 4,
		"Add Permissions-Policy header to control browser features"))

	// ── Infrastructure (10 pts) ──

	nsCount := getInt("dns", "ns_count")
	checks = append(checks, scoreCheck("infrastructure", "Multiple nameservers", nsCount >= 2, 5,
		"Configure at least 2 nameservers for redundancy"))

	secTxt := getBool("files", "has_security_txt")
	checks = append(checks, scoreCheck("infrastructure", "security.txt present", secTxt, 5,
		"Add /.well-known/security.txt for vulnerability disclosure"))

	// ── Information Exposure (10 pts) ──

	// No sensitive dirs exposed (5)
	sensitiveDirs := getInt("dirs", "critical_count")
	checks = append(checks, scoreCheck("exposure", "No sensitive files exposed", sensitiveDirs == 0, 5,
		"Remove or restrict access to exposed sensitive files (.env, .git, etc.)"))

	// No JS secrets (5)
	jsSecrets := getInt("jsanalysis", "secrets_count")
	checks = append(checks, scoreCheck("exposure", "No secrets in JavaScript", jsSecrets == 0, 5,
		"Remove API keys and secrets from client-side JavaScript"))

	// ── Aggregate ──

	var total, maxScore, passed, failed int
	var recommendations []string
	for i := range checks {
		maxScore += checks[i].Max
		if checks[i].Pass {
			checks[i].Points = checks[i].Max
			total += checks[i].Max
			passed++
		} else {
			failed++
			if checks[i].Recommendation != "" {
				recommendations = append(recommendations, checks[i].Recommendation)
			}
		}
	}

	pct := 0
	if maxScore > 0 {
		pct = total * 100 / maxScore
	}

	grade := "F"
	switch {
	case pct >= 90:
		grade = "A"
	case pct >= 80:
		grade = "B"
	case pct >= 70:
		grade = "C"
	case pct >= 60:
		grade = "D"
	}

	return &ScoreResult{
		Score:           total,
		MaxScore:        maxScore,
		Percentage:      pct,
		Grade:           grade,
		Checks:          checks,
		Passed:          passed,
		Failed:          failed,
		Recommendations: recommendations,
	}
}

func scoreCheck(category, check string, pass bool, max int, rec string) ScoreCheck {
	sc := ScoreCheck{
		Category: category,
		Check:    check,
		Pass:     pass,
		Max:      max,
	}
	if !pass {
		sc.Recommendation = rec
	}
	return sc
}

// jsonPath does a simple dot-separated path lookup in a JSON object.
// Returns the string representation of the value, or "" if not found.
func jsonPath(raw json.RawMessage, path string) string {
	parts := strings.Split(path, ".")
	var current interface{}
	if err := json.Unmarshal(raw, &current); err != nil {
		return ""
	}
	for _, p := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = m[p]
		if !ok {
			return ""
		}
	}
	switch v := current.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		if v == float64(int(v)) {
			return fmt.Sprintf("%d", int(v))
		}
		return fmt.Sprintf("%g", v)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

