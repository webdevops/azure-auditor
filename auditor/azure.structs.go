package auditor

type (
	AzureBaseObject struct {
		ResourceID string
	}

	AzureKeyvaultAccessPolicy struct {
		*AzureBaseObject
		Keyvault      string
		ApplicationID string
		ObjectID      string
		Permissions   AzureKeyvaultAccessPolicyPermissions
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
		PrincipalName          string

		RoleDefinitionID   string
		RoleDefinitionName string

		Description string
	}
)
