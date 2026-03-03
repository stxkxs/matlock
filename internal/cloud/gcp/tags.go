package gcp

import (
	"context"
	"fmt"

	gcpstorage "cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"

	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditTags checks GCP compute instances and GCS buckets for missing required labels.
func (p *Provider) AuditTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}
	if len(required) == 0 {
		return nil, nil
	}

	var findings []cloud.TagFinding

	instanceFindings, err := p.auditInstanceLabels(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("instance labels: %w", err)
	}
	findings = append(findings, instanceFindings...)

	bucketFindings, err := p.auditBucketLabels(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("bucket labels: %w", err)
	}
	findings = append(findings, bucketFindings...)

	return findings, nil
}

func (p *Provider) auditInstanceLabels(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}

	var findings []cloud.TagFinding
	if err := svc.Instances.AggregatedList(p.projectID).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, inst := range scopedList.Instances {
				labelMap := make(map[string]struct{})
				for k := range inst.Labels {
					labelMap[k] = struct{}{}
				}
				missing := gcpMissingLabels(required, labelMap)
				if len(missing) == 0 {
					continue
				}
				zone := inst.Zone
				// Extract short zone name from full URL
				if idx := lastSlash(zone); idx >= 0 {
					zone = zone[idx+1:]
				}
				findings = append(findings, cloud.TagFinding{
					Severity:     cloud.SeverityMedium,
					Provider:     "gcp",
					ResourceID:   inst.Name,
					ResourceType: "compute:instance",
					Region:       zone,
					MissingTags:  missing,
					Detail:       fmt.Sprintf("instance %s missing labels: %v", inst.Name, missing),
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	return findings, nil
}

func (p *Provider) auditBucketLabels(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	client, err := gcpstorage.NewClient(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	var findings []cloud.TagFinding
	iter := client.Buckets(ctx, p.projectID)
	for {
		attrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}
		labelMap := make(map[string]struct{})
		for k := range attrs.Labels {
			labelMap[k] = struct{}{}
		}
		missing := gcpMissingLabels(required, labelMap)
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, cloud.TagFinding{
			Severity:     cloud.SeverityMedium,
			Provider:     "gcp",
			ResourceID:   attrs.Name,
			ResourceType: "gcs:bucket",
			Region:       attrs.Location,
			MissingTags:  missing,
			Detail:       fmt.Sprintf("bucket %s missing labels: %v", attrs.Name, missing),
		})
	}
	return findings, nil
}

func gcpMissingLabels(required []string, have map[string]struct{}) []string {
	var missing []string
	for _, label := range required {
		if _, ok := have[label]; !ok {
			missing = append(missing, label)
		}
	}
	return missing
}
