package gcp

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/stxkxs/matlock/internal/cloud"
)

// ListResources lists GCP resources for inventory.
func (p *Provider) ListResources(ctx context.Context, typeFilter []string) ([]cloud.InventoryResource, error) {
	filter := make(map[string]bool)
	for _, t := range typeFilter {
		filter[strings.ToLower(t)] = true
	}
	all := len(filter) == 0

	var resources []cloud.InventoryResource

	if all || filter["compute"] || filter["compute:instance"] {
		r, err := p.listComputeInstances(ctx)
		if err != nil {
			return nil, fmt.Errorf("list compute instances: %w", err)
		}
		resources = append(resources, r...)
	}

	if all || filter["gcs"] || filter["gcs:bucket"] {
		r, err := p.listGCSBuckets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list gcs buckets: %w", err)
		}
		resources = append(resources, r...)
	}

	return resources, nil
}

func (p *Provider) listComputeInstances(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	svc, err := compute.NewService(ctx, p.opts...)
	if err != nil {
		return nil, fmt.Errorf("create compute service: %w", err)
	}

	var resources []cloud.InventoryResource
	req := svc.Instances.AggregatedList(p.projectID)
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for zone, list := range page.Items {
			for _, inst := range list.Instances {
				region := zoneToRegion(zone)
				labels := inst.Labels
				resources = append(resources, cloud.InventoryResource{
					Kind:     cloud.ResourceCompute,
					Type:     "compute:instance",
					ID:       fmt.Sprintf("%d", inst.Id),
					Name:     inst.Name,
					Provider: "gcp",
					Region:   region,
					Tags:     labels,
					Status:   inst.Status,
				})
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list compute instances: %w", err)
	}

	return resources, nil
}

func (p *Provider) listGCSBuckets(ctx context.Context) ([]cloud.InventoryResource, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT not set")
	}

	var opts []option.ClientOption
	opts = append(opts, p.opts...)
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer client.Close()

	var resources []cloud.InventoryResource
	it := client.Buckets(ctx, p.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return resources, fmt.Errorf("list buckets: %w", err)
		}
		created := attrs.Created
		r := cloud.InventoryResource{
			Kind:      cloud.ResourceStorage,
			Type:      "gcs:bucket",
			ID:        attrs.Name,
			Name:      attrs.Name,
			Provider:  "gcp",
			Region:    attrs.Location,
			Tags:      attrs.Labels,
			CreatedAt: &created,
		}
		resources = append(resources, r)
	}
	return resources, nil
}

func zoneToRegion(zone string) string {
	// "zones/us-central1-a" -> "us-central1"
	zone = strings.TrimPrefix(zone, "zones/")
	parts := strings.Split(zone, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}
