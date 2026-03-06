package compliance

import "github.com/stxkxs/matlock/internal/cloud"

// Evaluate runs all controls in a benchmark against the provided findings.
func Evaluate(benchmark *Benchmark, input InputFindings) ComplianceReport {
	results := make([]ControlResult, 0, len(benchmark.Controls))
	for _, ctrl := range benchmark.Controls {
		results = append(results, evaluateControl(ctrl, input))
	}

	var summary ComplianceSummary
	summary.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusNotEvaluated:
			summary.NotEvaluated++
		}
	}

	return ComplianceReport{
		Benchmark: benchmark.Name,
		Summary:   summary,
		Results:   results,
	}
}

func evaluateControl(ctrl Control, input InputFindings) ControlResult {
	switch ctrl.ID {
	// IAM controls
	case "1.16":
		return evalAdminAccess(ctrl, input.IAM)
	case "1.10", "1.12":
		return evalStalePrincipal(ctrl, input.IAM)
	case "1.15":
		return evalBroadScope(ctrl, input.IAM)
	case "1.4", "1.5", "1.17", "1.19", "1.22":
		return evalIAMGeneric(ctrl, input.IAM)

	// Storage controls
	case "2.1.4":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketUnencrypted)
	case "2.1.5":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketPublicAccess)
	case "2.1.1", "2.1.2", "2.2.1":
		return evalStorageGeneric(ctrl, input.Storage)

	// Logging controls
	case "3.7":
		return evalStorageFinding(ctrl, input.Storage, cloud.BucketNoLogging)
	case "3.1", "3.4":
		return evalNotEvaluated(ctrl, "CloudTrail configuration not included in scan data")

	// Monitoring
	case "4.1":
		return evalTags(ctrl, input.Tags)

	// Networking
	case "5.1":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkAdminPortOpen)
	case "5.2", "5.3":
		return evalNetworkAdminPorts(ctrl, input.Network)
	case "5.4":
		return evalNetworkFinding(ctrl, input.Network, cloud.NetworkOpenIngress)

	default:
		return evalNotEvaluated(ctrl, "no evaluator for this control")
	}
}

func evalAdminAccess(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingAdminAccess {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "admin access policies found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no admin access policies detected"}
}

func evalStalePrincipal(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingStalePrincipal || f.Type == cloud.FindingUnusedPermission {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "stale or unused credentials found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no stale credentials detected"}
}

func evalBroadScope(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.FindingBroadScope || f.Type == cloud.FindingWildcardResource {
			ref := f.Detail
			if f.Principal != nil {
				ref = f.Principal.Name + ": " + f.Detail
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "broad scope or wildcard resource policies found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no broad scope policies detected"}
}

func evalIAMGeneric(ctrl Control, findings []cloud.Finding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no IAM findings provided"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no relevant IAM findings detected"}
}

func evalStorageFinding(ctrl Control, findings []cloud.BucketFinding, findingType cloud.BucketFindingType) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no storage findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == findingType {
			refs = append(refs, f.Bucket+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: string(findingType) + " issues found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no " + string(findingType) + " issues detected"}
}

func evalStorageGeneric(ctrl Control, findings []cloud.BucketFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no storage findings provided"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no relevant storage findings detected"}
}

func evalNetworkFinding(ctrl Control, findings []cloud.NetworkFinding, findingType cloud.NetworkFindingType) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no network findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == findingType {
			refs = append(refs, f.Resource+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: string(findingType) + " issues found"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no " + string(findingType) + " issues detected"}
}

func evalNetworkAdminPorts(ctrl Control, findings []cloud.NetworkFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no network findings provided"}
	}
	var refs []string
	for _, f := range findings {
		if f.Type == cloud.NetworkAdminPortOpen {
			refs = append(refs, f.Resource+": "+f.Detail)
		}
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "admin ports open to internet"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "no admin ports open to internet"}
}

func evalTags(ctrl Control, findings []cloud.TagFinding) ControlResult {
	if len(findings) == 0 {
		return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: "no tags findings provided"}
	}
	var refs []string
	for _, f := range findings {
		refs = append(refs, f.ResourceID+": missing "+joinTags(f.MissingTags))
	}
	if len(refs) > 0 {
		return ControlResult{Control: ctrl, Status: StatusFail, Findings: refs, Detail: "resources missing required tags"}
	}
	return ControlResult{Control: ctrl, Status: StatusPass, Detail: "all resources have required tags"}
}

func evalNotEvaluated(ctrl Control, reason string) ControlResult {
	return ControlResult{Control: ctrl, Status: StatusNotEvaluated, Detail: reason}
}

func joinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	s := tags[0]
	for _, t := range tags[1:] {
		s += ", " + t
	}
	return s
}
