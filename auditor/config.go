package auditor

import (
	"io/ioutil"

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
	}

	AuditConfigResourceGraph struct {
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
		if data, err := ioutil.ReadFile(path); err == nil {
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

func (configResourceGraph *AuditConfigResourceGraph) IsEnabled() bool {
	return configResourceGraph != nil && configResourceGraph.Enabled && len(configResourceGraph.Queries) >= 1
}
