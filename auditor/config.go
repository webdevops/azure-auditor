package auditor

import (
	"os"

	log "github.com/sirupsen/logrus"
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

func (auditor *AzureAuditor) ParseConfig(configPaths ...string) {
	var configRaw []byte

	auditor.config = AuditConfig{}

	for _, path := range configPaths {
		auditor.logger.Infof("reading configuration from file %v", path)
		/* #nosec */
		if data, err := os.ReadFile(path); err == nil {
			configRaw = data
		} else {
			auditor.logger.Panic(err)
		}

		log.WithField("path", path).Info("parsing configuration")
		if err := yaml.Unmarshal(configRaw, &auditor.config); err != nil {
			auditor.logger.Panic(err)
		}
	}
}

func (config *AuditConfigResourceGraph) IsEnabled() bool {
	return config != nil && config.Enabled && len(config.Queries) >= 1
}

func (config *AuditConfiLogAnalytics) IsEnabled() bool {
	return config != nil && config.Enabled && len(config.Queries) >= 1
}
