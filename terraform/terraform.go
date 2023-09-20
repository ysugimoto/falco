package terraform

import (
	"encoding/json"

	"github.com/pkg/errors"
)

const (
	fastlyTerraformProviderName = "registry.terraform.io/fastly/fastly"
	fastlyVCLServiceType        = "fastly_service_vcl"
	fastlyVCLServiceTypeV1      = "fastly_service_v1"
)

// Terraform planned input struct
// This struct could be unmarshled from input of `terraform show -json [planned json]
type TerraformVcl struct {
	Content string
	Main    bool
	Name    string
}

type TerraformAcl struct {
	Name string
}

type TerraformDictionary struct {
	Name string
}

type TerraformSnippet struct {
	Name     string
	Type     string
	Content  string
	Priority int64
}

// TODO(davinci26): We can unmarshall all the properties from the TF file
// and lint them to make sure they have sane values.
type TerraformBackend struct {
	Name   string
	Shield *string
}

type FastlyService struct {
	Name         string
	Vcls         []*TerraformVcl
	Backends     []*TerraformBackend
	Acls         []*TerraformAcl
	Dictionaries []*TerraformDictionary
	Snippets     []*TerraformSnippet
}

type TerraformPlannedResource struct {
	ProviderName string `json:"provider_name"`
	Type         string `json:"type"`
	Values       *struct {
		Name       string                 `json:"name"`
		Vcl        []*TerraformVcl        `json:"vcl"`
		Acl        []*TerraformAcl        `json:"acl"`
		Backend    []*TerraformBackend    `json:"backend"`
		Dictionary []*TerraformDictionary `json:"dictionary"`
		Snippets   []*TerraformSnippet    `json:"snippet"`
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

func UnmarshalTerraformPlannedInput(buf []byte) ([]*FastlyService, error) {
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

	var services []*FastlyService
	// Case: service is declared in root module
	if len(root.PlannedValues.RootModule.Resources) > 0 {
		for _, v := range root.PlannedValues.RootModule.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}

			services = append(services, &FastlyService{
				Name:         v.Values.Name,
				Vcls:         v.Values.Vcl,
				Acls:         v.Values.Acl,
				Backends:     v.Values.Backend,
				Dictionaries: v.Values.Dictionary,
				Snippets:     v.Values.Snippets,
			})
		}
	}

	// Case: service is declared in child module
	for _, v := range root.PlannedValues.RootModule.ChildModules {
		for _, v := range v.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}

			services = append(services, &FastlyService{
				Name:         v.Values.Name,
				Vcls:         v.Values.Vcl,
				Acls:         v.Values.Acl,
				Backends:     v.Values.Backend,
				Dictionaries: v.Values.Dictionary,
				Snippets:     v.Values.Snippets,
			})
		}
	}

	if len(services) == 0 {
		return nil, errors.New(`Fastly service does not exist. Did you plan with fastly terraform provider?`)
	}

	return services, nil
}

func isFastlyVCLServiceResource(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName &&
		(r.Type == fastlyVCLServiceType || r.Type == fastlyVCLServiceTypeV1) && len(r.Values.Vcl) > 0
}
