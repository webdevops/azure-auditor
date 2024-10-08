package auditor

import (
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/webdevops/azure-auditor/auditor/validator"
)

type (
	AuditConfig struct {
		RoleAssignments          *validator.AuditConfigValidation `yaml:"roleAssignments"`
		ResourceGroups           *validator.AuditConfigValidation `yaml:"resourceGroups"`
		ResourceProviders        *validator.AuditConfigValidation `yaml:"resourceProviders"`
		ResourceProviderFeatures *validator.AuditConfigValidation `yaml:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   *validator.AuditConfigValidation `yaml:"keyvaultAccessPolicies"`
		ResourceGraph            *AuditConfigResourceGraph        `yaml:"resourceGraph"`
		LogAnalytics             *AuditConfiLogAnalytics          `yaml:"logAnalytics"`
	}

	AuditConfigResourceGraph struct {
		Enabled bool                                        `yaml:"enabled"`
		Queries map[string]*validator.AuditConfigValidation `yaml:"queries"`
	}

	AuditConfiLogAnalytics struct {
		Enabled bool                                        `yaml:"enabled"`
		Queries map[string]*validator.AuditConfigValidation `yaml:"queries"`
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
		if err := yaml.Unmarshal(configRaw, &auditor.config); err != nil {
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
