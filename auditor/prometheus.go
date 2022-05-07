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
		resourceGraph           map[string]*prometheus.GaugeVec
	}
)

func (auditor *AzureAuditor) initPrometheus() {
	if auditor.config.RoleAssignments.IsEnabled() {
		auditor.prometheus.roleAssignment = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_roleassignment",
				Help: "Azure ResourceManager audit RoleAssignment violation",
			},
			append(
				auditor.config.RoleAssignments.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.roleAssignment)
	}

	if auditor.config.ResourceGroups.IsEnabled() {
		auditor.prometheus.resourceGroup = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_resourcegroup",
				Help: "Azure ResourceManager audit ResourceGroup violation",
			},
			append(
				auditor.config.ResourceGroups.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.resourceGroup)
	}

	if auditor.config.ResourceProviders.IsEnabled() {
		auditor.prometheus.resourceProvider = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_resourceprovider",
				Help: "Azure ResourceManager audit ResourceProvider violation",
			},
			append(
				auditor.config.ResourceProviders.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.resourceProvider)
	}

	if auditor.config.ResourceProviderFeatures.IsEnabled() {
		auditor.prometheus.resourceProviderFeature = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_resourceproviderfeature",
				Help: "Azure ResourceManager audit ResourceProviderFeature violation",
			},
			append(
				auditor.config.ResourceProviderFeatures.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.resourceProviderFeature)
	}

	if auditor.config.KeyvaultAccessPolicies.IsEnabled() {
		auditor.prometheus.keyvaultAccessPolicies = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_keyvaultaccesspolicy",
				Help: "Azure ResourceManager audit Keyvault AccessPolicy violation",
			},
			append(
				auditor.config.KeyvaultAccessPolicies.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.keyvaultAccessPolicies)
	}

	auditor.prometheus.resourceGraph = map[string]*prometheus.GaugeVec{}
	for queryName, query := range auditor.config.ResourceGraph.Queries {
		auditor.prometheus.resourceGraph[queryName] = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "azurerm_audit_violation_resourcegraph_" + queryName,
				Help: "Azure ResourceManager audit ResourceGraph violation",
			},
			append(
				query.PrometheusLabels(),
				"rule",
			),
		)
		prometheus.MustRegister(auditor.prometheus.resourceGraph[queryName])
	}

}
