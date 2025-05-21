package auditor

import (
	"os"

	yaml "github.com/goccy/go-yaml"
	"go.uber.org/zap"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

type (
	AuditConfig struct {
		RoleAssignments          *validator.AuditConfigValidation `json:"roleAssignments"`
		ResourceGroups           *validator.AuditConfigValidation `json:"resourceGroups"`
		ResourceProviders        *validator.AuditConfigValidation `json:"resourceProviders"`
		ResourceProviderFeatures *validator.AuditConfigValidation `json:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   *validator.AuditConfigValidation `json:"keyvaultAccessPolicies"`
		ResourceGraph            *AuditConfigResourceGraph        `json:"resourceGraph"`
		LogAnalytics             *AuditConfiLogAnalytics          `json:"logAnalytics"`
	}

	AuditConfigResourceGraph struct {
		Enabled bool                                        `json:"enabled"`
		Queries map[string]*validator.AuditConfigValidation `json:"queries"`
	}

	AuditConfiLogAnalytics struct {
		Enabled bool                                        `json:"enabled"`
		Queries map[string]*validator.AuditConfigValidation `json:"queries"`
	}
)

func (auditor *AzureAuditor) SetConfigs(configPaths ...string) {
	auditor.configFiles = configPaths

}
func (auditor *AzureAuditor) reloadConfig() {
	var configRaw []byte

	auditor.config = AuditConfig{}

	for _, path := range auditor.configFiles {
		auditor.Logger.Infof("reading configuration from file %v", path)
		/* #nosec */
		if data, err := os.ReadFile(path); err == nil {
			configRaw = data
		} else {
			auditor.Logger.Panic(err)
		}

		auditor.Logger.With(zap.String("path", path)).Info("parsing configuration")
		err := yaml.UnmarshalWithOptions(configRaw, &auditor.config, yaml.Strict(), yaml.UseJSONUnmarshaler())
		if err != nil {
			auditor.Logger.Panic(err)
		}
	}
}

func (config *AuditConfigResourceGraph) IsEnabled() bool {
	return config != nil && config.Enabled && len(config.Queries) >= 1
}

func (config *AuditConfiLogAnalytics) IsEnabled() bool {
	return config != nil && config.Enabled && len(config.Queries) >= 1
}
