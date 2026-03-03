package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditTags checks all Azure resources for missing required tags.
func (p *Provider) AuditTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if len(required) == 0 {
		return nil, nil
	}

	client, err := armresources.NewClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("resources client: %w", err)
	}

	var findings []cloud.TagFinding
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list resources: %w", err)
		}
		for _, res := range page.Value {
			tagMap := make(map[string]struct{})
			for k := range res.Tags {
				tagMap[k] = struct{}{}
			}
			missing := azureMissingTags(required, tagMap)
			if len(missing) == 0 {
				continue
			}

			id := ptrStr(res.ID)
			resType := ptrStr(res.Type)
			region := ptrStr(res.Location)
			name := ptrStr(res.Name)

			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "azure",
				ResourceID:   name,
				ResourceType: resType,
				Region:       region,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("resource %s (%s) missing tags: %v", name, id, missing),
			})
		}
	}
	return findings, nil
}

func azureMissingTags(required []string, have map[string]struct{}) []string {
	var missing []string
	for _, tag := range required {
		if _, ok := have[tag]; !ok {
			missing = append(missing, tag)
		}
	}
	return missing
}
