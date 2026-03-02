package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListPrincipals returns all IAM roles and users in the account.
func (p *Provider) ListPrincipals(ctx context.Context) ([]cloud.Principal, error) {
	client := iam.NewFromConfig(p.cfg)
	var principals []cloud.Principal

	// Roles
	rolePager := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for rolePager.HasMorePages() {
		page, err := rolePager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: list roles page: %v\n", err)
			break
		}
		for _, r := range page.Roles {
			meta := map[string]string{}
			if r.Description != nil {
				meta["description"] = *r.Description
			}
			principals = append(principals, cloud.Principal{
				ID:       awssdk.ToString(r.RoleId),
				Name:     awssdk.ToString(r.RoleName),
				Type:     cloud.PrincipalRole,
				Provider: "aws",
				Metadata: meta,
			})
		}
	}

	// Users
	userPager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPager.HasMorePages() {
		page, err := userPager.NextPage(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: list users page: %v\n", err)
			break
		}
		for _, u := range page.Users {
			principals = append(principals, cloud.Principal{
				ID:       awssdk.ToString(u.UserId),
				Name:     awssdk.ToString(u.UserName),
				Type:     cloud.PrincipalUser,
				Provider: "aws",
				Metadata: map[string]string{},
			})
		}
	}

	return principals, nil
}

// policyDocument is an IAM policy document.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string          `json:"Effect"`
	Action   json.RawMessage `json:"Action"`
	Resource json.RawMessage `json:"Resource"`
}

// toStringSlice converts a JSON string or []string to []string.
func toStringSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var ss []string
	_ = json.Unmarshal(raw, &ss)
	return ss
}

// parseDocument decodes a URL-encoded IAM policy document JSON.
func parseDocument(encoded string) (*policyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		decoded = encoded
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// documentToPermissions converts a policy document to a slice of Permissions.
func documentToPermissions(doc *policyDocument) []cloud.Permission {
	var perms []cloud.Permission
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := toStringSlice(stmt.Action)
		resources := toStringSlice(stmt.Resource)
		for _, action := range actions {
			for _, resource := range resources {
				perms = append(perms, cloud.Permission{
					Action:   action,
					Resource: resource,
				})
			}
		}
	}
	return perms
}

// GrantedPermissions returns all effective permissions for an IAM principal.
func (p *Provider) GrantedPermissions(ctx context.Context, principal cloud.Principal) ([]cloud.Permission, error) {
	client := iam.NewFromConfig(p.cfg)
	var perms []cloud.Permission

	switch principal.Type {
	case cloud.PrincipalRole:
		// Managed policies
		attachedPager := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{
			RoleName: awssdk.String(principal.Name),
		})
		for attachedPager.HasMorePages() {
			page, err := attachedPager.NextPage(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: list attached role policies page: %v\n", err)
				break
			}
			for _, ap := range page.AttachedPolicies {
				ps, err := p.getManagedPolicyPermissions(ctx, client, awssdk.ToString(ap.PolicyArn))
				if err != nil {
					continue // best-effort
				}
				perms = append(perms, ps...)
			}
		}
		// Inline policies
		inlinePager := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{
			RoleName: awssdk.String(principal.Name),
		})
		for inlinePager.HasMorePages() {
			page, err := inlinePager.NextPage(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: list role policies page: %v\n", err)
				break
			}
			for _, policyName := range page.PolicyNames {
				out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
					RoleName:   awssdk.String(principal.Name),
					PolicyName: awssdk.String(policyName),
				})
				if err != nil {
					continue
				}
				doc, err := parseDocument(awssdk.ToString(out.PolicyDocument))
				if err != nil {
					continue
				}
				perms = append(perms, documentToPermissions(doc)...)
			}
		}

	case cloud.PrincipalUser:
		// Managed policies
		attachedPager := iam.NewListAttachedUserPoliciesPaginator(client, &iam.ListAttachedUserPoliciesInput{
			UserName: awssdk.String(principal.Name),
		})
		for attachedPager.HasMorePages() {
			page, err := attachedPager.NextPage(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: list attached user policies page: %v\n", err)
				break
			}
			for _, ap := range page.AttachedPolicies {
				ps, err := p.getManagedPolicyPermissions(ctx, client, awssdk.ToString(ap.PolicyArn))
				if err != nil {
					continue
				}
				perms = append(perms, ps...)
			}
		}
		// Inline policies
		inlinePager := iam.NewListUserPoliciesPaginator(client, &iam.ListUserPoliciesInput{
			UserName: awssdk.String(principal.Name),
		})
		for inlinePager.HasMorePages() {
			page, err := inlinePager.NextPage(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: list user policies page: %v\n", err)
				break
			}
			for _, policyName := range page.PolicyNames {
				out, err := client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   awssdk.String(principal.Name),
					PolicyName: awssdk.String(policyName),
				})
				if err != nil {
					continue
				}
				doc, err := parseDocument(awssdk.ToString(out.PolicyDocument))
				if err != nil {
					continue
				}
				perms = append(perms, documentToPermissions(doc)...)
			}
		}
	}

	return dedupPermissions(perms), nil
}

func (p *Provider) getManagedPolicyPermissions(ctx context.Context, client *iam.Client, policyArn string) ([]cloud.Permission, error) {
	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: awssdk.String(policyArn),
	})
	if err != nil {
		var noSuchEntity *iamtypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			fmt.Fprintf(os.Stderr, "warn: policy %s no longer exists, skipping\n", policyArn)
			return nil, nil
		}
		return nil, err
	}
	if policyOut.Policy == nil {
		return nil, nil
	}
	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: awssdk.String(policyArn),
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		var noSuchEntity *iamtypes.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			fmt.Fprintf(os.Stderr, "warn: policy version for %s no longer exists, skipping\n", policyArn)
			return nil, nil
		}
		return nil, err
	}
	doc, err := parseDocument(awssdk.ToString(versionOut.PolicyVersion.Document))
	if err != nil {
		return nil, err
	}
	return documentToPermissions(doc), nil
}

// UsedPermissions returns permissions that appeared in CloudTrail during [since, now].
// Delegated to cloudtrail.go.
func (p *Provider) UsedPermissions(ctx context.Context, principal cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	return p.cloudtrailUsedPermissions(ctx, principal, since)
}

// MinimalPolicy builds an AWS IAM policy document from the used permission set.
func (p *Provider) MinimalPolicy(_ context.Context, principal cloud.Principal, used []cloud.Permission) (cloud.Policy, error) {
	grouped := make(map[string][]string)
	for _, perm := range used {
		r := perm.Resource
		if r == "" {
			r = "*"
		}
		grouped[r] = append(grouped[r], perm.Action)
	}

	type statement struct {
		Effect   string   `json:"Effect"`
		Action   []string `json:"Action"`
		Resource string   `json:"Resource"`
	}
	type doc struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}
	d := doc{Version: "2012-10-17"}
	for resource, actions := range grouped {
		d.Statement = append(d.Statement, statement{
			Effect:   "Allow",
			Action:   dedup(actions),
			Resource: resource,
		})
	}

	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return cloud.Policy{}, err
	}
	return cloud.Policy{
		Provider: "aws",
		Format:   "aws-iam-json",
		Raw:      raw,
	}, nil
}

func dedupPermissions(perms []cloud.Permission) []cloud.Permission {
	seen := make(map[string]bool)
	var out []cloud.Permission
	for _, p := range perms {
		key := p.Action + "|" + p.Resource
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

func dedup(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// accountID attempts to extract the AWS account ID from a role ARN.
func accountIDFromPrincipal(p cloud.Principal) string {
	if arn, ok := p.Metadata["arn"]; ok {
		parts := strings.Split(arn, ":")
		if len(parts) >= 5 {
			return parts[4]
		}
	}
	return ""
}

