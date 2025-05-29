package terraform

import (
	"encoding/json"
	"sort"

	"github.com/pkg/errors"
)

const (
	fastlyTerraformProviderName      = "registry.terraform.io/fastly/fastly"
	fastlyVCLServiceType             = "fastly_service_vcl"
	fastlyVCLServiceTypeV1           = "fastly_service_v1"
	fastlyServiceAclEntriesType      = "fastly_service_acl_entries"
	fastlyServiceDictionaryItemsType = "fastly_service_dictionary_items"
)

type TerraformPlannedResource struct {
	ProviderName string          `json:"provider_name"`
	Type         string          `json:"type"`
	Values       json.RawMessage `json:"values"`
	Index        string          `json:"index"`
}

type TerraformModule struct {
	Resources    []*TerraformPlannedResource `json:"resources"`
	ChildModules []*TerraformModule          `json:"child_modules"`
}

type TerraformPlannedInput struct {
	PlannedValues *struct {
		RootModule *TerraformModule `json:"root_module"`
	} `json:"planned_values"`
}

func unmarshalTerraformPlannedInput(buf []byte) ([]*FastlyService, error) {
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

	resources, err := findFastlyServicesInTerraformModule(root.PlannedValues.RootModule)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(resources.Services) == 0 {
		return nil, errors.New(`Fastly service does not exist. Did you plan with fastly terraform provider?`)
	}

	return collectServices(resources), nil
}

func findFastlyServicesInTerraformModule(mod *TerraformModule) (*FastlyResources, error) {
	services := make(map[string]*FastlyService)
	var aclEntries []*fastlyAclEntryValues
	var dictionaryItems []*fastlyDictionaryItems

	// Find services in module resources
	if len(mod.Resources) > 0 {
		// v is *TerraformPlannedResource
		for _, v := range mod.Resources {
			switch {
			case isFastlyVCLServiceResource(v):
				var s *fastlyServiceValues
				if err := json.Unmarshal(v.Values, &s); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_vcl values")
				}

				services[s.ID] = &FastlyService{
					Name:             s.Name,
					Vcls:             s.Vcl,
					Acls:             s.Acl,
					Backends:         s.Backend,
					Dictionaries:     s.Dictionary,
					Directors:        s.Director,
					Snippets:         s.Snippets,
					LoggingEndpoints: factoryLoggingEndpoints(s),
				}
			case isFastlyServiceAclEntryResource(v):
				var a *fastlyAclEntryValues
				if err := json.Unmarshal(v.Values, &a); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_acl_entries values")
				}
				a.Index = v.Index
				aclEntries = append(aclEntries, a)

			case isFastlyServiceDictionaryItem(v):
				var d *fastlyDictionaryItems
				if err := json.Unmarshal(v.Values, &d); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_dictionary_items values")
				}
				d.Index = v.Index
				dictionaryItems = append(dictionaryItems, d)
			}
		}
	}

	// Check child_modules existence and return found services if not found
	if len(mod.ChildModules) == 0 {
		return &FastlyResources{
			Services:        services,
			AclEntries:      aclEntries,
			DictionaryItems: dictionaryItems,
		}, nil
	}
	// If module has child_modules, find Fastly service recursively
	for _, child := range mod.ChildModules {
		// child is *TerraformModule
		childResource, err := findFastlyServicesInTerraformModule(child)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		// Merge child resource
		for key, val := range childResource.Services {
			services[key] = val
		}
		aclEntries = append(aclEntries, childResource.AclEntries...)
		dictionaryItems = append(dictionaryItems, childResource.DictionaryItems...)
	}

	return &FastlyResources{
		Services:        services,
		AclEntries:      aclEntries,
		DictionaryItems: dictionaryItems,
	}, nil
}

func isFastlyVCLServiceResource(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName &&
		(r.Type == fastlyVCLServiceType || r.Type == fastlyVCLServiceTypeV1)
}

func isFastlyServiceAclEntryResource(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName && r.Type == fastlyServiceAclEntriesType
}
func isFastlyServiceDictionaryItem(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName && r.Type == fastlyServiceDictionaryItemsType
}

func factoryLoggingEndpoints(values *fastlyServiceValues) []string {
	var endpoints []string
	for _, v := range values.LoggingBigQuerty {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingBlobStorage {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingCloudFiles {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingDatadog {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingDigitalOpean {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingElasticsearch {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingFtp {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingGcs {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingGooglePubSub {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingHeroku {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingHttps {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingKafka {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingKinesis {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLogEntries {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLoggly {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingLogShuttle {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingNewRelic {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingOpenStack {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingPaperTrail {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingS3 {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingScalyr {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSplunk {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSumoLogic {
		endpoints = append(endpoints, v.Name)
	}
	for _, v := range values.LoggingSyslog {
		endpoints = append(endpoints, v.Name)
	}
	return endpoints
}

func collectServices(r *FastlyResources) []*FastlyService {
	for _, entry := range r.AclEntries {
		v, ok := r.Services[entry.ServiceId]
		if !ok {
			continue
		}
		for _, acl := range v.Acls {
			if acl.Name != entry.Index {
				continue
			}
			for _, e := range entry.Entries {
				acl.Entries = append(acl.Entries, &AclEntry{
					Comment: e.Comment,
					Ip:      e.Ip,
					Negated: e.Negated,
					Subnet:  e.Subnet,
				})
			}
		}
	}

	for _, item := range r.DictionaryItems {
		v, ok := r.Services[item.ServiceId]
		if !ok {
			continue
		}
		for _, dict := range v.Dictionaries {
			if dict.Name != item.Index {
				continue
			}
			for key, val := range item.Items {
				dict.Items = append(dict.Items, &DictionaryItem{
					Key:   key,
					Value: val,
				})
			}
		}
	}

	services := make([]*FastlyService, len(r.Services))
	var index int
	for _, service := range r.Services {
		services[index] = service
		index++
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Name > services[j].Name
	})

	return services
}
