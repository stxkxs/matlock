package azure

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListQuotas returns compute, network, and storage quota utilization.
func (p *Provider) ListQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	location := os.Getenv("AZURE_DEFAULTS_LOCATION")
	if location == "" {
		location = "eastus"
	}

	var quotas []cloud.QuotaUsage

	computeQuotas, err := p.computeQuotas(ctx, location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure compute quotas: %v\n", err)
	} else {
		quotas = append(quotas, computeQuotas...)
	}

	networkQuotas, err := p.networkQuotas(ctx, location)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure network quotas: %v\n", err)
	} else {
		quotas = append(quotas, networkQuotas...)
	}

	storageQuotas, err := p.storageQuotas(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: azure storage quotas: %v\n", err)
	} else {
		quotas = append(quotas, storageQuotas...)
	}

	return quotas, nil
}

func (p *Provider) computeQuotas(ctx context.Context, location string) ([]cloud.QuotaUsage, error) {
	client, err := armcompute.NewUsageClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create compute usage client: %w", err)
	}

	var quotas []cloud.QuotaUsage
	pager := client.NewListPager(location, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return quotas, fmt.Errorf("list compute usage: %w", err)
		}
		for _, u := range page.Value {
			if u.Limit == nil || *u.Limit == 0 {
				continue
			}
			used := float64(int32PtrVal(u.CurrentValue))
			limit := float64(*u.Limit)
			name := ""
			if u.Name != nil && u.Name.LocalizedValue != nil {
				name = *u.Name.LocalizedValue
			}
			quotas = append(quotas, cloud.QuotaUsage{
				Provider:    "azure",
				Service:     "Compute",
				QuotaName:   name,
				Used:        used,
				Limit:       limit,
				Utilization: pctAzure(used, limit),
				Region:      location,
			})
		}
	}
	return quotas, nil
}

func (p *Provider) networkQuotas(ctx context.Context, location string) ([]cloud.QuotaUsage, error) {
	client, err := armnetwork.NewUsagesClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create network usage client: %w", err)
	}

	var quotas []cloud.QuotaUsage
	pager := client.NewListPager(location, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return quotas, fmt.Errorf("list network usage: %w", err)
		}
		for _, u := range page.Value {
			if u.Limit == nil || *u.Limit == 0 {
				continue
			}
			used := float64(int64PtrVal(u.CurrentValue))
			limit := float64(*u.Limit)
			name := ""
			if u.Name != nil && u.Name.LocalizedValue != nil {
				name = *u.Name.LocalizedValue
			}
			quotas = append(quotas, cloud.QuotaUsage{
				Provider:    "azure",
				Service:     "Network",
				QuotaName:   name,
				Used:        used,
				Limit:       limit,
				Utilization: pctAzure(used, limit),
				Region:      location,
			})
		}
	}
	return quotas, nil
}

func (p *Provider) storageQuotas(ctx context.Context) ([]cloud.QuotaUsage, error) {
	client, err := armstorage.NewAccountsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create storage accounts client: %w", err)
	}

	var count int
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list storage accounts: %w", err)
		}
		count += len(page.Value)
	}

	used := float64(count)
	limit := float64(250) // Default Azure storage account limit per subscription

	return []cloud.QuotaUsage{{
		Provider:    "azure",
		Service:     "Storage",
		QuotaName:   "Storage Accounts",
		Used:        used,
		Limit:       limit,
		Utilization: pctAzure(used, limit),
		Region:      "subscription",
	}}, nil
}

func pctAzure(used, limit float64) float64 {
	if limit == 0 {
		return 0
	}
	return used / limit * 100
}

func int32PtrVal(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func int64PtrVal(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// compile-time check
var _ cloud.QuotaProvider = (*Provider)(nil)
