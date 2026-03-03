package modules

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/stxkxs/matlock/internal/investigate"
)

type emailSecResult struct {
	SPF   *spfResult   `json:"spf"`
	DMARC *dmarcResult `json:"dmarc"`
	DKIM  []dkimResult `json:"dkim"`
	BIMI  *bimiResult  `json:"bimi"`
	Grade string       `json:"grade"`
}

type spfResult struct {
	Record       string   `json:"record"`
	Mechanisms   []string `json:"mechanisms"`
	AllQualifier string   `json:"all_qualifier"`
	Strict       bool     `json:"strict"`
}

type dmarcResult struct {
	Record string            `json:"record"`
	Tags   map[string]string `json:"tags"`
	Policy string            `json:"policy"`
}

type dkimResult struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
	Record   string `json:"record,omitempty"`
	KeyType  string `json:"key_type,omitempty"`
}

type bimiResult struct {
	Found  bool   `json:"found"`
	Record string `json:"record,omitempty"`
	Logo   string `json:"logo,omitempty"`
	VMC    string `json:"vmc,omitempty"`
}

// EmailSec analyzes email security configuration (SPF, DMARC, DKIM, BIMI).
type EmailSec struct{}

func (e *EmailSec) Name() string        { return "emailsec" }
func (e *EmailSec) Description() string { return "Analyze email security: SPF, DMARC, DKIM, BIMI" }
func (e *EmailSec) TargetTypes() []investigate.TargetType {
	return []investigate.TargetType{investigate.TargetDomain}
}

var dkimSelectors = []string{
	"google", "default", "mail", "dkim", "s1", "s2",
	"k1", "k2", "selector1", "selector2", "mandrill",
	"amazonses", "postmark",
}

func (e *EmailSec) Run(ctx context.Context, target string) (json.RawMessage, error) {
	result := emailSecResult{}

	// SPF lookup.
	result.SPF = lookupSPF(ctx, target)

	// DMARC lookup.
	result.DMARC = lookupDMARC(ctx, target)

	// DKIM lookup across selectors.
	result.DKIM = lookupDKIM(ctx, target)

	// BIMI lookup.
	result.BIMI = lookupBIMI(ctx, target)

	// Calculate grade.
	result.Grade = calculateEmailGrade(result)

	return json.Marshal(result)
}

func lookupSPF(ctx context.Context, domain string) *spfResult {
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=spf1") {
			continue
		}

		spf := &spfResult{
			Record: txt,
		}

		parts := strings.Fields(txt)
		for _, part := range parts[1:] {
			spf.Mechanisms = append(spf.Mechanisms, part)

			// Extract all qualifier.
			if strings.HasSuffix(part, "all") {
				switch {
				case strings.HasPrefix(part, "-"):
					spf.AllQualifier = "-all"
					spf.Strict = true
				case strings.HasPrefix(part, "~"):
					spf.AllQualifier = "~all"
				case strings.HasPrefix(part, "?"):
					spf.AllQualifier = "?all"
				case part == "+all" || part == "all":
					spf.AllQualifier = "+all"
				}
			}
		}

		return spf
	}
	return nil
}

func lookupDMARC(ctx context.Context, domain string) *dmarcResult {
	dmarcDomain := "_dmarc." + domain
	txts, err := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return nil
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=DMARC1") {
			continue
		}

		dmarc := &dmarcResult{
			Record: txt,
			Tags:   make(map[string]string),
		}

		parts := strings.Split(txt, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				dmarc.Tags[key] = value
				if key == "p" {
					dmarc.Policy = value
				}
			}
		}

		return dmarc
	}
	return nil
}

func lookupDKIM(ctx context.Context, domain string) []dkimResult {
	var results []dkimResult

	for _, selector := range dkimSelectors {
		dkimDomain := selector + "._domainkey." + domain
		txts, err := net.DefaultResolver.LookupTXT(ctx, dkimDomain)

		entry := dkimResult{
			Selector: selector,
			Found:    false,
		}

		if err == nil && len(txts) > 0 {
			record := strings.Join(txts, "")
			if strings.Contains(record, "v=DKIM1") || strings.Contains(record, "p=") {
				entry.Found = true
				entry.Record = record

				// Extract key type.
				for _, part := range strings.Split(record, ";") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "k=") {
						entry.KeyType = strings.TrimPrefix(part, "k=")
					}
				}
				if entry.KeyType == "" {
					entry.KeyType = "rsa" // default per RFC 6376
				}
			}
		}

		results = append(results, entry)
	}

	return results
}

func lookupBIMI(ctx context.Context, domain string) *bimiResult {
	bimiDomain := "default._bimi." + domain
	txts, err := net.DefaultResolver.LookupTXT(ctx, bimiDomain)
	if err != nil {
		return &bimiResult{Found: false}
	}

	for _, txt := range txts {
		if !strings.Contains(txt, "v=BIMI1") {
			continue
		}

		bimi := &bimiResult{
			Found:  true,
			Record: txt,
		}

		parts := strings.Split(txt, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "l=") {
				bimi.Logo = strings.TrimPrefix(part, "l=")
			}
			if strings.HasPrefix(part, "a=") {
				bimi.VMC = strings.TrimPrefix(part, "a=")
			}
		}

		return bimi
	}

	return &bimiResult{Found: false}
}

func calculateEmailGrade(result emailSecResult) string {
	hasSPF := result.SPF != nil
	spfStrict := hasSPF && result.SPF.Strict
	hasDMARC := result.DMARC != nil
	dmarcPolicy := ""
	if hasDMARC {
		dmarcPolicy = result.DMARC.Policy
	}

	dkimCount := 0
	for _, d := range result.DKIM {
		if d.Found {
			dkimCount++
		}
	}
	hasDKIM := dkimCount > 0
	strongDKIM := dkimCount >= 2

	switch {
	case spfStrict && dmarcPolicy == "reject" && strongDKIM:
		return "A"
	case hasSPF && (dmarcPolicy == "quarantine" || dmarcPolicy == "reject") && hasDKIM:
		return "B"
	case hasSPF && hasDMARC:
		return "C"
	case hasSPF || hasDMARC:
		return "D"
	default:
		return "F"
	}
}
