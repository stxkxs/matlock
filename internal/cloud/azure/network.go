package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditNetwork checks Azure Network Security Groups for overly permissive rules.
func (p *Provider) AuditNetwork(ctx context.Context) ([]cloud.NetworkFinding, error) {
	client, err := armnetwork.NewSecurityGroupsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("nsg client: %w", err)
	}

	var findings []cloud.NetworkFinding
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list nsgs: %w", err)
		}
		for _, nsg := range page.Value {
			if nsg.Properties == nil {
				continue
			}
			name := ptrStr(nsg.Name)
			region := ptrStr(nsg.Location)
			for _, rule := range nsg.Properties.SecurityRules {
				findings = append(findings, classifyNSGRule(name, region, rule)...)
			}
		}
	}
	return findings, nil
}

// azureSensitivePorts are port numbers that should never be exposed to the internet.
var azureSensitivePorts = []int{22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}

func classifyNSGRule(nsgName, region string, rule *armnetwork.SecurityRule) []cloud.NetworkFinding {
	if rule == nil || rule.Properties == nil {
		return nil
	}
	props := rule.Properties

	// Only check Allow rules
	if props.Access == nil || *props.Access != armnetwork.SecurityRuleAccessAllow {
		return nil
	}

	// Inbound rules only for admin port and open ingress checks
	isInbound := props.Direction != nil && *props.Direction == armnetwork.SecurityRuleDirectionInbound
	isOutbound := props.Direction != nil && *props.Direction == armnetwork.SecurityRuleDirectionOutbound

	src := ptrStr(props.SourceAddressPrefix)
	openSource := src == "*" || strings.EqualFold(src, "Internet") || strings.EqualFold(src, "Any")

	dst := ptrStr(props.DestinationAddressPrefix)
	openDest := dst == "*" || strings.EqualFold(dst, "Internet") || strings.EqualFold(dst, "Any")

	proto := "*"
	if props.Protocol != nil {
		proto = string(*props.Protocol)
	}

	if isInbound && openSource {
		return classifyNSGInbound(nsgName, region, proto, props)
	}

	if isOutbound && openDest {
		portRange := ptrStr(props.DestinationPortRange)
		if portRange == "*" || portRange == "0-65535" {
			return []cloud.NetworkFinding{{
				Severity:    cloud.SeverityMedium,
				Type:        cloud.NetworkOpenEgress,
				Provider:    "azure",
				Resource:    nsgName,
				Region:      region,
				Protocol:    proto,
				Port:        "all",
				CIDR:        "Internet",
				Detail:      fmt.Sprintf("NSG %s allows all outbound traffic to internet", nsgName),
				Remediation: fmt.Sprintf("az network nsg rule delete --nsg-name %s --name %s", nsgName, ptrStr(rule.Name)),
			}}
		}
	}

	return nil
}

func classifyNSGInbound(nsgName, region, proto string, props *armnetwork.SecurityRulePropertiesFormat) []cloud.NetworkFinding {
	var findings []cloud.NetworkFinding

	portRange := ptrStr(props.DestinationPortRange)
	portRanges := []string{portRange}
	if portRange == "" {
		for _, pr := range props.DestinationPortRanges {
			if pr != nil {
				portRanges = append(portRanges, *pr)
			}
		}
	}

	for _, pr := range portRanges {
		if pr == "" {
			continue
		}
		if pr == "*" || pr == "0-65535" {
			return []cloud.NetworkFinding{{
				Severity:    cloud.SeverityCritical,
				Type:        cloud.NetworkAdminPortOpen,
				Provider:    "azure",
				Resource:    nsgName,
				Region:      region,
				Protocol:    proto,
				Port:        "all",
				CIDR:        "Internet",
				Detail:      fmt.Sprintf("NSG %s allows all inbound traffic from internet", nsgName),
				Remediation: fmt.Sprintf("az network nsg rule update --nsg-name %s --name <rule>", nsgName),
			}}
		}
		for _, sp := range azureSensitivePorts {
			if portInNSGRange(sp, pr) {
				return []cloud.NetworkFinding{{
					Severity:    cloud.SeverityCritical,
					Type:        cloud.NetworkAdminPortOpen,
					Provider:    "azure",
					Resource:    nsgName,
					Region:      region,
					Protocol:    proto,
					Port:        fmt.Sprintf("%d", sp),
					CIDR:        "Internet",
					Detail:      fmt.Sprintf("NSG %s exposes sensitive port %d to internet", nsgName, sp),
					Remediation: fmt.Sprintf("az network nsg rule update --nsg-name %s --name <rule>", nsgName),
				}}
			}
		}
		// Skip HTTP/HTTPS
		if pr == "80" || pr == "443" {
			continue
		}
		findings = append(findings, cloud.NetworkFinding{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.NetworkOpenIngress,
			Provider:    "azure",
			Resource:    nsgName,
			Region:      region,
			Protocol:    proto,
			Port:        pr,
			CIDR:        "Internet",
			Detail:      fmt.Sprintf("NSG %s allows inbound port %s from internet", nsgName, pr),
			Remediation: fmt.Sprintf("az network nsg rule update --nsg-name %s --name <rule>", nsgName),
		})
	}
	return findings
}

func portInNSGRange(port int, portRange string) bool {
	if portRange == "*" {
		return true
	}
	parts := strings.SplitN(portRange, "-", 2)
	var from, to int
	fmt.Sscanf(parts[0], "%d", &from)
	if len(parts) == 2 {
		fmt.Sscanf(parts[1], "%d", &to)
	} else {
		to = from
	}
	return port >= from && port <= to
}
