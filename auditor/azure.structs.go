package auditor

import (
	"strings"
	"time"
)

type (
	AzureBaseObject struct {
		ResourceID string
	}

	AzureObject map[string]interface{}

	AzureKeyvaultAccessPolicy struct {
		*AzureBaseObject
		Keyvault string

		PrincipalObjectID      string
		PrincipalApplicationID string
		PrincipalType          string
		PrincipalDisplayName   string

		Permissions AzureKeyvaultAccessPolicyPermissions
	}

	AzureKeyvaultAccessPolicyPermissions struct {
		Certificates []string
		Secrets      []string
		Keys         []string
		Storage      []string
	}

	AzureResourceGroup struct {
		*AzureBaseObject
		Name     string
		Location string
		Tags     map[string]string
	}

	AzureResourceProviderFeature struct {
		*AzureBaseObject
		Namespace string
		Feature   string
	}

	AzureResourceProvider struct {
		*AzureBaseObject
		Namespace string
	}

	AzureRoleAssignment struct {
		*AzureBaseObject

		Type  string
		Scope string

		PrincipalObjectID      string
		PrincipalApplicationID string
		PrincipalType          string
		PrincipalDisplayName   string

		RoleDefinitionID   string
		RoleDefinitionName string

		Description string

		CreationTime time.Time
		Age          time.Duration
	}
)

func (o *AzureObject) ResourceID() string {
	if val, ok := (*o)["resourceID"].(string); ok {
		return val
	}
	return ""
}

func (o *AzureObject) ToPrometheusLabel(name string) string {
	if val, ok := (*o)[name]; ok {
		switch v := val.(type) {
		case string:
			return v
		case []string:
			return strings.Join(v, ",")
		}
	}

	return ""
}
