package auditor

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type (
	AuditConfig struct {
		RoleAssignments          *AuditConfigValidation `yaml:"roleAssignments"`
		ResourceGroups           *AuditConfigValidation `yaml:"resourceGroups"`
		ResourceProviders        *AuditConfigValidation `yaml:"resourceProviders"`
		ResourceProviderFeatures *AuditConfigValidation `yaml:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   *AuditConfigValidation `yaml:"keyvaultAccessPolicies"`
	}
)

func (auditor *AzureAuditor) ParseConfig(path string) {
	var configRaw []byte

	auditor.config = AuditConfig{}

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
