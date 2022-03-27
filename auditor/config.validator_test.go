package auditor

import (
	"testing"

	"gopkg.in/yaml.v3"
)

type (
	TestValidator struct {
		Test *AuditConfigValidation `yaml:"test"`
	}
)

func TestValidation(t *testing.T) {
	var obj *AzureObject
	yamlConfig := `

test:
  enabled: true
  rules:
    - rule: tags
      resourcegroup.tag.foobar:
        required: true
        regexp: "^barfoo"
      action: continue

    - rule: name
      resourcegroup.name: foobar
      action: allow

`

	config := TestValidator{}
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		t.Error(err)
		return
	}

	obj = newAzureObject(
		map[string]interface{}{
			"resourcegroup.name":       "foobar",
			"resourcegroup.tag.foobar": "barfoo",
		},
	)
	if _, status := config.Test.Validate(obj); !status {
		t.Errorf("expected matching object, got: %v", status)
	}

	obj = newAzureObject(
		map[string]interface{}{
			"resourcegroup.name":       "foobar",
			"resourcegroup.tag.barfoo": "foobar",
		},
	)
	if _, status := config.Test.Validate(obj); status {
		t.Errorf("expected NOT matching object, got: %v", status)
	}
}
