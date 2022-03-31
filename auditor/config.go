package auditor

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"github.com/webdevops/azure-audit-exporter/auditor/validator"
	"gopkg.in/yaml.v3"
)

type (
	AuditConfig struct {
		RoleAssignments          *validator.AuditConfigValidation `yaml:"roleAssignments"`
		ResourceGroups           *validator.AuditConfigValidation `yaml:"resourceGroups"`
		ResourceProviders        *validator.AuditConfigValidation `yaml:"resourceProviders"`
		ResourceProviderFeatures *validator.AuditConfigValidation `yaml:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   *validator.AuditConfigValidation `yaml:"keyvaultAccessPolicies"`
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
