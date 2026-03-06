package gcp

import (
	"context"
	"fmt"
	"strings"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	cstorage "google.golang.org/api/storage/v1"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/drift"
)

// SupportedResourceTypes returns the Terraform resource types this provider can check for drift.
func (p *Provider) SupportedResourceTypes() []string {
	return []string{
		"google_compute_firewall",
		"google_storage_bucket",
	}
}

// CheckDrift compares live GCP state against the provided Terraform attributes.
func (p *Provider) CheckDrift(ctx context.Context, resourceType, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	switch resourceType {
	case "google_compute_firewall":
		return p.checkFirewallDrift(ctx, resourceID, attrs)
	case "google_storage_bucket":
		return p.checkStorageBucketDrift(ctx, resourceID, attrs)
	default:
		return cloud.DriftResult{
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Status:       cloud.DriftError,
			Detail:       "unsupported resource type",
		}, nil
	}
}

func (p *Provider) checkFirewallDrift(ctx context.Context, resourceID string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create compute client: %w", err)
	}

	// Extract firewall name from ID (projects/proj/global/firewalls/name or just name)
	name := resourceID
	if parts := strings.Split(resourceID, "/"); len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	fw, err := svc.Firewalls.Get(p.projectID, name).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_compute_firewall",
				ResourceID:   resourceID,
				Status:       cloud.DriftDeleted,
				Detail:       "firewall rule not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get firewall %s: %w", name, err)
	}

	actual := map[string]interface{}{
		"name":        fw.Name,
		"description": fw.Description,
		"direction":   fw.Direction,
		"disabled":    fmt.Sprintf("%v", fw.Disabled),
		"priority":    fmt.Sprintf("%d", fw.Priority),
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "description", "direction", "disabled", "priority"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_compute_firewall",
			ResourceID:   resourceID,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_compute_firewall",
		ResourceID:   resourceID,
		Status:       cloud.DriftInSync,
	}, nil
}

func (p *Provider) checkStorageBucketDrift(ctx context.Context, bucketName string, attrs map[string]interface{}) (cloud.DriftResult, error) {
	svc, err := cstorage.NewService(ctx, p.opts...)
	if err != nil {
		return cloud.DriftResult{}, fmt.Errorf("create storage client: %w", err)
	}

	bucket, err := svc.Buckets.Get(bucketName).Context(ctx).Do()
	if err != nil {
		if isGoogleNotFound(err) {
			return cloud.DriftResult{
				ResourceType: "google_storage_bucket",
				ResourceID:   bucketName,
				Status:       cloud.DriftDeleted,
				Detail:       "storage bucket not found in GCP",
			}, nil
		}
		return cloud.DriftResult{}, fmt.Errorf("get bucket %s: %w", bucketName, err)
	}

	actual := map[string]interface{}{
		"name":          bucket.Name,
		"location":      strings.ToLower(bucket.Location),
		"storage_class": bucket.StorageClass,
	}

	diffs := drift.CompareAttributes(attrs, actual, []string{"name", "location", "storage_class"})
	if len(diffs) > 0 {
		return cloud.DriftResult{
			ResourceType: "google_storage_bucket",
			ResourceID:   bucketName,
			Status:       cloud.DriftModified,
			Fields:       diffs,
		}, nil
	}
	return cloud.DriftResult{
		ResourceType: "google_storage_bucket",
		ResourceID:   bucketName,
		Status:       cloud.DriftInSync,
	}, nil
}

func isGoogleNotFound(err error) bool {
	if gErr, ok := err.(*googleapi.Error); ok {
		return gErr.Code == 404
	}
	return false
}
