package auditor

import (
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
)

type (
	AuditConfig struct {
		RoleAssignments          AuditConfigRoleAssignments          `yaml:"roleAssignments"`
		ResourceGroups           AuditConfigResourceGroups           `yaml:"resourceGroups"`
		ResourceProviders        AuditConfigResourceProviders        `yaml:"resourceProviders"`
		ResourceProviderFeatures AuditConfigResourceProviderFeatures `yaml:"resourceProviderFeatures"`
		KeyvaultAccessPolicies   AuditConfigKeyvaultAccessPolicies   `yaml:"keyvaultAccessPolicies"`
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
		panic(err)
	}

	log.WithField("path", path).Info("parsing configuration")
	if err := yaml.Unmarshal(configRaw, &auditor.config); err != nil {
		panic(err)
	}
}
