package terraform

import (
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

const (
	fastlyTerraformProviderName            = "registry.terraform.io/fastly/fastly"
	fastlyVCLServiceType                   = "fastly_service_vcl"
	fastlyVCLServiceTypeV1                 = "fastly_service_v1"
	fastlyServiceAclEntriesType            = "fastly_service_acl_entries"
	fastlyServiceDictionaryItemsType       = "fastly_service_dictionary_items"
	fastlyServiceDynamicSnippetContentType = "fastly_service_dynamic_snippet_content"
)

type TerraformPlannedResource struct {
	ProviderName string          `json:"provider_name"`
	Type         string          `json:"type"`
	Values       json.RawMessage `json:"values"`
	Index        string          `json:"index"`
	Address      string          `json:"address"`
}

type TerraformModule struct {
	Resources    []*TerraformPlannedResource `json:"resources"`
	ChildModules []*TerraformModule          `json:"child_modules"`
}

type TerraformConfiguredResource struct {
	Address     string          `json:"address"`
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Expressions json.RawMessage `json:"expressions"`
}

type TerraformPlanConfiguration struct {
	Resources []*TerraformConfiguredResource `json:"resources"`
}

type TerraformPlannedInput struct {
	PlannedValues *struct {
		RootModule *TerraformModule `json:"root_module"`
	} `json:"planned_values"`
	Configuration *struct {
		RootModule *TerraformPlanConfiguration `json:"root_module"`
	} `json:"configuration"`
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

	cr := map[string]*TerraformConfiguredResource{}
	if root.Configuration != nil && root.Configuration.RootModule != nil {
		for _, r := range root.Configuration.RootModule.Resources {
			cr[r.Address] = r
		}
	}

	resources, err := findFastlyServicesInTerraformModule(root.PlannedValues.RootModule, cr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(resources.Services) == 0 {
		return nil, errors.New(`Fastly service does not exist. Did you plan with fastly terraform provider?`)
	}

	return collectServices(resources), nil
}

func stripTerraformForEachIndex(address string) string {
	if i := strings.Index(address, "["); i != -1 {
		return address[:i]
	}
	return address
}

func findServiceReference(serviceRef map[string]*fastlyServiceValues, resources []string) (*fastlyServiceValues, string) {
	for _, r := range resources {
		if v, ok := serviceRef[r]; ok {
			return v, r
		}
	}
	return nil, ""
}

// nolint: gocognit
func findFastlyServicesInTerraformModule(mod *TerraformModule, config map[string]*TerraformConfiguredResource) (*FastlyResources, error) {
	services := make(map[string]*FastlyService)
	serviceRef := make(map[string]*fastlyServiceValues)

	var aclEntries []*fastlyAclEntryValues
	var dictionaryItems []*fastlyDictionaryItems
	var dynamicSnippetContents []*fastlyDynamicSnippetContent

	// Find services in module resources
	if len(mod.Resources) > 0 {
		// Collect services in the first-loop to create service and service reference map
		for _, v := range mod.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}
			var s *fastlyServiceValues
			if err := json.Unmarshal(v.Values, &s); err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_vcl values")
			}

			serviceRef[v.Address] = s
			services[v.Address] = &FastlyService{
				Name:             s.Name,
				Vcls:             s.Vcl,
				Acls:             s.Acl,
				Backends:         s.Backend,
				Dictionaries:     s.Dictionary,
				Directors:        s.Director,
				Snippets:         s.Snippets,
				DynamicSnippets:  s.DynamicSnippets,
				Conditions:       s.Conditions,
				Headers:          s.Headers,
				ResponseObjects:  s.ResponseObjects,
				RequestSettings:  s.RequestSettings,
				LoggingEndpoints: factoryLoggingEndpoints(s),
			}
		}

		// Secondary-loop, collect resources that have dependency with fastly_service
		for _, v := range mod.Resources {
			switch {
			case isFastlyServiceAclEntryResource(v):
				var a *fastlyAclEntryValues
				if err := json.Unmarshal(v.Values, &a); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_acl_entries values")
				}
				a.Index = v.Index
				if c, ok := config[stripTerraformForEachIndex(v.Address)]; ok {
					var ac *configurationServiceExpression
					if err := json.Unmarshal(c.Expressions, &ac); err != nil {
						return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_acl_entries configuration values")
					}
					if ref, addr := findServiceReference(serviceRef, ac.ServiceID.References); ref != nil {
						var matches bool
						for _, v := range ref.Acl {
							if v.Name == a.Index {
								matches = true
								break
							}
						}
						if matches {
							a.targetService = services[addr]
						}
					}
				}
				aclEntries = append(aclEntries, a)

			case isFastlyServiceDictionaryItem(v):
				var d *fastlyDictionaryItems
				if err := json.Unmarshal(v.Values, &d); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_dictionary_items values")
				}
				d.Index = v.Index
				if c, ok := config[stripTerraformForEachIndex(v.Address)]; ok {
					var dc *configurationServiceExpression
					if err := json.Unmarshal(c.Expressions, &dc); err != nil {
						return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_dictionary_items configuration values")
					}
					if ref, addr := findServiceReference(serviceRef, dc.ServiceID.References); ref != nil {
						var matches bool
						for _, v := range ref.Dictionary {
							if v.Name == d.Index {
								matches = true
								break
							}
						}
						if matches {
							d.targetService = services[addr]
						}
					}
				}
				dictionaryItems = append(dictionaryItems, d)

			case isFastlyServiceDynamicSnippetContent(v):
				var d *fastlyDynamicSnippetContent
				if err := json.Unmarshal(v.Values, &d); err != nil {
					return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_dynamic_snippet_content values")
				}
				d.Index = v.Index
				if c, ok := config[stripTerraformForEachIndex(v.Address)]; ok {
					var dc *configurationServiceExpression
					if err := json.Unmarshal(c.Expressions, &dc); err != nil {
						return nil, errors.Wrap(err, "Failed to unmarshal fastly_service_dynamic_snippet_content configuration values")
					}
					if ref, addr := findServiceReference(serviceRef, dc.ServiceID.References); ref != nil {
						var matches bool
						for _, v := range ref.DynamicSnippets {
							if v.Name == d.Index {
								matches = true
								break
							}
						}
						if matches {
							d.targetService = services[addr]
						}
					}
				}
				dynamicSnippetContents = append(dynamicSnippetContents, d)
			}
		}
	}

	// Check child_modules existence and return found services if not found
	if len(mod.ChildModules) == 0 {
		return &FastlyResources{
			Services:               services,
			AclEntries:             aclEntries,
			DictionaryItems:        dictionaryItems,
			DynamicSnippetContents: dynamicSnippetContents,
		}, nil
	}
	// If module has child_modules, find Fastly service recursively
	for _, child := range mod.ChildModules {
		// child is *TerraformModule
		childResource, err := findFastlyServicesInTerraformModule(child, config)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		// Merge child resource
		maps.Copy(services, childResource.Services)

		aclEntries = append(aclEntries, childResource.AclEntries...)
		dictionaryItems = append(dictionaryItems, childResource.DictionaryItems...)
		dynamicSnippetContents = append(dynamicSnippetContents, childResource.DynamicSnippetContents...)
	}

	return &FastlyResources{
		Services:               services,
		AclEntries:             aclEntries,
		DictionaryItems:        dictionaryItems,
		DynamicSnippetContents: dynamicSnippetContents,
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

func isFastlyServiceDynamicSnippetContent(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName && r.Type == fastlyServiceDynamicSnippetContentType
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
	for _, v := range r.AclEntries {
		collectAcls(v)
	}
	for _, v := range r.DictionaryItems {
		collectDictionaries(v)
	}
	for _, v := range r.DynamicSnippetContents {
		collectDynamicSnippets(v)
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

func collectAcls(entry *fastlyAclEntryValues) {
	if entry.targetService == nil {
		return
	}
	for _, acl := range entry.targetService.Acls {
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

func collectDictionaries(item *fastlyDictionaryItems) {
	if item.targetService == nil {
		return
	}

	for _, dict := range item.targetService.Dictionaries {
		if dict.Name != item.Index {
			continue
		}
		// Sort items by key ascending
		keys := make([]string, len(item.Items))
		index := 0
		for key := range item.Items {
			keys[index] = key
			index++
		}
		slices.Sort(keys)
		for i := range keys {
			dict.Items = append(dict.Items, &DictionaryItem{
				Key:   keys[i],
				Value: item.Items[keys[i]],
			})
		}
	}
}

func collectDynamicSnippets(dsc *fastlyDynamicSnippetContent) {
	if dsc.targetService == nil {
		return
	}
	for _, ds := range dsc.targetService.DynamicSnippets {
		if ds.Name == dsc.Index {
			ds.Content = dsc.Content
		}
	}
}
