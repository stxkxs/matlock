package output

import (
	"encoding/json"
	"io"

	"github.com/stxkxs/matlock/internal/cloud"
)

// SARIF 2.1.0 structures (minimal subset for GitHub Advanced Security).
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
	Kind    string       `json:"kind"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// WriteSARIF writes IAM findings in SARIF 2.1.0 format.
func WriteSARIF(w io.Writer, findings []cloud.Finding, version string) error {
	rules := buildRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "matlock",
				Version:        version,
				InformationURI: "https://github.com/stxkxs/matlock",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteStorageSARIF writes storage audit findings in SARIF 2.1.0 format.
func WriteStorageSARIF(w io.Writer, findings []cloud.BucketFinding, version string) error {
	rules := buildStorageRules()
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Type),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Detail},
			Kind:    "open",
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "matlock",
				Version:        version,
				InformationURI: "https://github.com/stxkxs/matlock",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s cloud.Severity) string {
	switch s {
	case cloud.SeverityCritical, cloud.SeverityHigh:
		return "error"
	case cloud.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildStorageRules() []sarifRule {
	types := []struct {
		id    cloud.BucketFindingType
		name  string
		level string
	}{
		{cloud.BucketPublicAccess, "PublicAccess", "error"},
		{cloud.BucketUnencrypted, "Unencrypted", "error"},
		{cloud.BucketNoVersioning, "NoVersioning", "warning"},
		{cloud.BucketNoLogging, "NoLogging", "note"},
		{cloud.BucketPublicACL, "PublicACL", "error"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}

func buildRules() []sarifRule {
	types := []struct {
		id    cloud.FindingType
		name  string
		level string
	}{
		{cloud.FindingAdminAccess, "AdminAccess", "error"},
		{cloud.FindingWildcardResource, "WildcardResource", "error"},
		{cloud.FindingUnusedPermission, "UnusedPermission", "error"},
		{cloud.FindingCrossAccountAccess, "CrossAccountAccess", "error"},
		{cloud.FindingStalePrincipal, "StalePrincipal", "warning"},
		{cloud.FindingBroadScope, "BroadScope", "warning"},
		{cloud.FindingPublicAccess, "PublicAccess", "error"},
		{cloud.FindingUnencrypted, "Unencrypted", "error"},
		{cloud.FindingNoVersioning, "NoVersioning", "warning"},
		{cloud.FindingOrphanResource, "OrphanResource", "note"},
	}
	var rules []sarifRule
	for _, t := range types {
		rules = append(rules, sarifRule{
			ID:               string(t.id),
			Name:             t.name,
			ShortDescription: sarifMessage{Text: t.name},
			DefaultConfig:    sarifRuleConfig{Level: t.level},
		})
	}
	return rules
}
