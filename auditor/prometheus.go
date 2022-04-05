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
		resourceGraph           *prometheus.GaugeVec
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
			"scopeType",
			"resourceGroup",
			"principalType",
			"principalObjectID",
			"principalApplicationID",
			"principalDisplayName",
			"roleDefinitionID",
			"roleDefinitionName",
			"rule",
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
			"resourceGroup",
			"location",
			"rule",
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
			"rule",
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
			"providerFeature",
			"rule",
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
			"principalType",
			"principalObjectID",
			"principalApplicationID",
			"principalDisplayName",
			"permissionsCertificates",
			"permissionsSecrets",
			"permissionsKeys",
			"permissionsStorage",
			"rule",
		},
	)
	prometheus.MustRegister(auditor.prometheus.keyvaultAccessPolicies)

	auditor.prometheus.resourceGraph = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "azurerm_audit_violation_resourcegraph",
			Help: "Azure ResourceManager audit ResourceGraph violation",
		},
		[]string{
			"subscriptionID",
			"queryName",
			"resourceID",
			"rule",
		},
	)
	prometheus.MustRegister(auditor.prometheus.resourceGraph)
}
