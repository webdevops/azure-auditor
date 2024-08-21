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
		logAnalytics            map[string]*prometheus.GaugeVec
	}
)

func (auditor *AzureAuditor) initPrometheus() {
	if auditor.prometheus.roleAssignment != nil {
		prometheus.Unregister(auditor.prometheus.roleAssignment)
	}

	if auditor.prometheus.resourceGroup != nil {
		prometheus.Unregister(auditor.prometheus.resourceGroup)
	}

	if auditor.prometheus.resourceProvider != nil {
		prometheus.Unregister(auditor.prometheus.resourceProvider)
	}

	if auditor.prometheus.resourceProviderFeature != nil {
		prometheus.Unregister(auditor.prometheus.resourceProviderFeature)
	}

	if auditor.prometheus.keyvaultAccessPolicies != nil {
		prometheus.Unregister(auditor.prometheus.keyvaultAccessPolicies)
	}

	if auditor.prometheus.resourceGraph != nil {
		for _, metric := range auditor.prometheus.resourceGraph {
			prometheus.Unregister(metric)
		}
	}

	if auditor.prometheus.logAnalytics != nil {
		for _, metric := range auditor.prometheus.logAnalytics {
			prometheus.Unregister(metric)
		}
	}

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
	if auditor.config.ResourceGraph.IsEnabled() {
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

	auditor.prometheus.logAnalytics = map[string]*prometheus.GaugeVec{}
	if auditor.config.LogAnalytics.IsEnabled() {
		for queryName, query := range auditor.config.LogAnalytics.Queries {
			auditor.prometheus.logAnalytics[queryName] = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: "azurerm_audit_violation_loganalytics_" + queryName,
					Help: "Azure ResourceManager audit LogAnalytics violation",
				},
				append(
					query.PrometheusLabels(),
					"rule",
				),
			)
			prometheus.MustRegister(auditor.prometheus.logAnalytics[queryName])
		}
	}
}
