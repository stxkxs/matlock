package output

import (
	"encoding/json"
	"io"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/compliance"
	"github.com/stxkxs/matlock/internal/investigate"
)

type iamReport struct {
	Findings        []cloud.Finding                `json:"findings"`
	Total           int                            `json:"total"`
	Principals      int                            `json:"principals_scanned"`
	UsedPermissions map[string][]cloud.Permission  `json:"used_permissions,omitempty"`
}

type storageReport struct {
	Findings []cloud.BucketFinding `json:"findings"`
	Total    int                   `json:"total"`
}

type orphansReport struct {
	Resources          []cloud.OrphanResource `json:"resources"`
	Total              int                    `json:"total"`
	EstimatedMonthlyUSD float64               `json:"estimated_monthly_usd"`
}

type costReport struct {
	Diffs []cloud.CostDiff `json:"diffs"`
}

// WriteIAM marshals IAM findings as JSON to w.
func WriteIAM(w io.Writer, findings []cloud.Finding, principalsScanned int, usedPerms map[string][]cloud.Permission) error {
	return writeJSON(w, iamReport{
		Findings:        findings,
		Total:           len(findings),
		Principals:      principalsScanned,
		UsedPermissions: usedPerms,
	})
}

// WriteStorage marshals storage findings as JSON to w.
func WriteStorage(w io.Writer, findings []cloud.BucketFinding) error {
	return writeJSON(w, storageReport{
		Findings: findings,
		Total:    len(findings),
	})
}

// WriteOrphans marshals orphan resources as JSON to w.
func WriteOrphans(w io.Writer, orphans []cloud.OrphanResource) error {
	var total float64
	for _, o := range orphans {
		total += o.MonthlyCost
	}
	return writeJSON(w, orphansReport{
		Resources:          orphans,
		Total:              len(orphans),
		EstimatedMonthlyUSD: total,
	})
}

// WriteCost marshals cost diffs as JSON to w.
func WriteCost(w io.Writer, diffs []cloud.CostDiff) error {
	return writeJSON(w, costReport{Diffs: diffs})
}

type networkReport struct {
	Findings []cloud.NetworkFinding `json:"findings"`
	Total    int                   `json:"total"`
}

type certsReport struct {
	Findings []cloud.CertFinding `json:"findings"`
	Total    int                 `json:"total"`
}

type tagsReport struct {
	Findings []cloud.TagFinding `json:"findings"`
	Total    int                `json:"total"`
}

// WriteNetwork marshals network findings as JSON to w.
func WriteNetwork(w io.Writer, findings []cloud.NetworkFinding) error {
	return writeJSON(w, networkReport{Findings: findings, Total: len(findings)})
}

// WriteCerts marshals certificate findings as JSON to w.
func WriteCerts(w io.Writer, findings []cloud.CertFinding) error {
	return writeJSON(w, certsReport{Findings: findings, Total: len(findings)})
}

// WriteTags marshals tag findings as JSON to w.
func WriteTags(w io.Writer, findings []cloud.TagFinding) error {
	return writeJSON(w, tagsReport{Findings: findings, Total: len(findings)})
}

type secretsReport struct {
	Findings []cloud.SecretFinding `json:"findings"`
	Total    int                   `json:"total"`
}

// WriteSecrets marshals secret findings as JSON to w.
func WriteSecrets(w io.Writer, findings []cloud.SecretFinding) error {
	return writeJSON(w, secretsReport{Findings: findings, Total: len(findings)})
}

type driftReport struct {
	Results []cloud.DriftResult `json:"results"`
	Total   int                 `json:"total"`
}

// WriteDrift marshals drift results as JSON to w.
func WriteDrift(w io.Writer, results []cloud.DriftResult) error {
	return writeJSON(w, driftReport{Results: results, Total: len(results)})
}

// WriteCompliance marshals a compliance report as JSON to w.
func WriteCompliance(w io.Writer, report compliance.ComplianceReport) error {
	return writeJSON(w, report)
}

// WriteProbe marshals a probe report as JSON to w.
func WriteProbe(w io.Writer, report *investigate.Report) error {
	return writeJSON(w, report)
}

// WriteProbeBatch marshals batch probe results as JSON to w.
func WriteProbeBatch(w io.Writer, results []investigate.BatchResult) error {
	return writeJSON(w, investigate.NewBatchReport(results))
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
