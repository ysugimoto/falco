package main

import (
	"encoding/json"

	"github.com/pkg/errors"
)

const fastlyTerraformProviderName = "registry.terraform.io/fastly/fastly"

// Terraform planned input struct
// This struct could be unmarshled from input of `terraform show -json [planned json]
type TerraformVcl struct {
	Content string
	Main    bool
	Name    string
}

type TerraformPlannedResource struct {
	ProviderName string `json:"provider_name"`
	Values       *struct {
		Vcl []*TerraformVcl `json:"vcl"`
	} `json:"values"`
}

type TerraformPlannedInput struct {
	PlannedValues *struct {
		RootModule *struct {
			Resources    []*TerraformPlannedResource `json:"resources"`
			ChildModules []*struct {
				Resources []*TerraformPlannedResource `json:"resources"`
			} `json:"child_modules"`
		} `json:"root_module"`
	} `json:"planned_values"`
}

func unmarshalTerraformPlannedInput(buf []byte) ([]*TerraformVcl, error) {
	var root TerraformPlannedInput

	if err := json.Unmarshal(buf, &root); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal stdin input")
	}

	if root.PlannedValues == nil {
		return nil, errors.New(`Input does not seem to terraform planned JSON: "planned_values" field does not exist`)
	}

	if root.PlannedValues.RootModule == nil {
		return nil, errors.New(`Input does not seem to terraform planned JSON: "root_module" field does not exist`)
	}

	var resources []*TerraformVcl
	for _, v := range root.PlannedValues.RootModule.Resources {
		if v.ProviderName == fastlyTerraformProviderName {
			resources = append(resources, v.Values.Vcl...)
		}
	}
	for _, v := range root.PlannedValues.RootModule.ChildModules {
		for _, v := range v.Resources {
			if v.ProviderName == fastlyTerraformProviderName {
				resources = append(resources, v.Values.Vcl...)
			}
		}
	}

	if len(resources) == 0 {
		return nil, errors.New(`Planned VCL is empty. Did you plan with fastly terraform provider?`)
	}

	return resources, nil
}
