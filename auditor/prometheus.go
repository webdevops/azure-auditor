package auditor

import (
	"github.com/prometheus/client_golang/prometheus"
)

type (
	auditorPrometheus struct {
		roleAssignment          *prometheus.GaugeVec
		resourceGroup           *prometheus.GaugeVec
		resourceProvider        *prometheus.GaugeVec
		resourceProviderFeature *prometheus.GaugeVec
		keyvaultAccessPolicies  *prometheus.GaugeVec
	}
)

func (auditor *AzureAuditor) initPrometheus() {
	auditor.prometheus.roleAssignment = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_roleassignment",
			Help: "Azure ResourceManager audit RoleAssignment violation",
		},
		[]string{
			"subscriptionID",
			"roleAssignmentID",
			"scope",
			"resourceGroup",
			"principalType",
			"principalID",
			"principalName",
			"roleDefinitionID",
			"roleDefinitionName",
		},
	)
	prometheus.MustRegister(auditor.prometheus.roleAssignment)

	auditor.prometheus.resourceGroup = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_resourcegroup",
			Help: "Azure ResourceManager audit ResourceGroup violation",
		},
		[]string{
			"subscriptionID",
			"name",
			"location",
		},
	)
	prometheus.MustRegister(auditor.prometheus.resourceGroup)

	auditor.prometheus.resourceProvider = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_resourceprovider",
			Help: "Azure ResourceManager audit ResourceProvider violation",
		},
		[]string{
			"subscriptionID",
			"providerNamespace",
		},
	)
	prometheus.MustRegister(auditor.prometheus.resourceProvider)

	auditor.prometheus.resourceProviderFeature = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_resourceproviderfeature",
			Help: "Azure ResourceManager audit ResourceProviderFeature violation",
		},
		[]string{
			"subscriptionID",
			"providerNamespace",
			"feature",
		},
	)
	prometheus.MustRegister(auditor.prometheus.resourceProviderFeature)

	auditor.prometheus.keyvaultAccessPolicies = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_keyvault_accesspolicy",
			Help: "Azure ResourceManager audit Keyvault AccessPolicy violation",
		},
		[]string{
			"subscriptionID",
			"keyvault",
			"resourceGroup",
			"objectID",
			"applicationID",
			"permissionsCertificates",
			"permissionsSecrets",
			"permissionsKeys",
			"permissionsStorage",
		},
	)
	prometheus.MustRegister(auditor.prometheus.keyvaultAccessPolicies)
}
