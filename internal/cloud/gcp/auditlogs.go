package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/logging/logadmin"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/stxkxs/matlock/internal/cloud"
)

// auditLogPermissions queries Cloud Audit Logs for method calls by the principal.
func (p *Provider) auditLogPermissions(ctx context.Context, principal cloud.Principal, since time.Time) ([]cloud.Permission, error) {
	client, err := logadmin.NewClient(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("logadmin client: %w", err)
	}
	defer client.Close()

	email := principal.Name
	if principal.Type == cloud.PrincipalServiceAccount {
		email = principal.Name
	}

	filter := fmt.Sprintf(
		`logName:"cloudaudit.googleapis.com" AND protoPayload.authenticationInfo.principalEmail="%s" AND timestamp>="%s"`,
		email,
		since.UTC().Format(time.RFC3339),
	)

	iter := client.Entries(ctx, logadmin.Filter(filter))
	seen := make(map[string]time.Time)

	for {
		entry, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterate audit logs: %w", err)
		}

		// Extract method name from the proto payload
		method := extractMethod(entry.Payload)
		if method == "" {
			continue
		}
		// GCP method names are like "storage.objects.get" — already in the right format
		key := method + "|projects/" + p.projectID
		if prev, ok := seen[key]; !ok || entry.Timestamp.After(prev) {
			seen[key] = entry.Timestamp
		}
	}

	perms := make([]cloud.Permission, 0, len(seen))
	for key, ts := range seen {
		parts := strings.SplitN(key, "|", 2)
		action, resource := parts[0], ""
		if len(parts) == 2 {
			resource = parts[1]
		}
		t := ts
		ts8601 := t.UTC().Format(time.RFC3339)
		perms = append(perms, cloud.Permission{
			Action:   action,
			Resource: resource,
			LastUsed: &ts8601,
		})
	}
	return perms, nil
}

// extractMethod pulls the method name out of a log entry payload.
func extractMethod(payload interface{}) string {
	if payload == nil {
		return ""
	}
	switch v := payload.(type) {
	case map[string]interface{}:
		if m, ok := v["methodName"].(string); ok {
			return m
		}
	case *structpb.Struct:
		if f, ok := v.GetFields()["methodName"]; ok {
			return f.GetStringValue()
		}
	}
	return ""
}
