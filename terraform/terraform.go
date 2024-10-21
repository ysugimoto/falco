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

type TerraformLoggingEndpoint struct {
	Name string
}

// TODO(davinci26): We can unmarshall all the properties from the TF file
// and lint them to make sure they have sane values.
type TerraformBackend struct {
	Name    string
	Shield  *string
	Address *string
}

type TerraformDirector struct {
	Type     int
	Name     string
	Backends []string
	Retries  *int
	Quorum   *int
}

type FastlyService struct {
	Name             string
	Vcls             []*TerraformVcl
	Backends         []*TerraformBackend
	Acls             []*TerraformAcl
	Dictionaries     []*TerraformDictionary
	Directors        []*TerraformDirector
	Snippets         []*TerraformSnippet
	LoggingEndpoints []string
}

type FastlyServiceValues struct {
	Name       string                 `json:"name"`
	Vcl        []*TerraformVcl        `json:"vcl"`
	Acl        []*TerraformAcl        `json:"acl"`
	Backend    []*TerraformBackend    `json:"backend"`
	Director   []*TerraformDirector   `json:"director"`
	Dictionary []*TerraformDictionary `json:"dictionary"`
	Snippets   []*TerraformSnippet    `json:"snippet"`

	// Various kinds of realtime logging endpoints
	LoggingBigQuerty     []*TerraformLoggingEndpoint `json:"logging_bigqeury"`
	LoggingBlobStorage   []*TerraformLoggingEndpoint `json:"logging_blobstorage"`
	LoggingCloudFiles    []*TerraformLoggingEndpoint `json:"logging_cloudfiles"`
	LoggingDatadog       []*TerraformLoggingEndpoint `json:"logging_datadog"`
	LoggingDigitalOpean  []*TerraformLoggingEndpoint `json:"logging_digitalocean"`
	LoggingElasticsearch []*TerraformLoggingEndpoint `json:"logging_elasticsearch"`
	LoggingFtp           []*TerraformLoggingEndpoint `json:"logging_ftp"`
	LoggingGcs           []*TerraformLoggingEndpoint `json:"logging_gcs"`
	LoggingGooglePubSub  []*TerraformLoggingEndpoint `json:"logging_googlepubsub"`
	LoggingHeroku        []*TerraformLoggingEndpoint `json:"logging_heroku"`
	LoggingHttps         []*TerraformLoggingEndpoint `json:"logging_https"`
	LoggingKafka         []*TerraformLoggingEndpoint `json:"logging_kafka"`
	LoggingKinesis       []*TerraformLoggingEndpoint `json:"logging_kinesis"`
	LoggingLogEntries    []*TerraformLoggingEndpoint `json:"logging_logentries"`
	LoggingLoggly        []*TerraformLoggingEndpoint `json:"logging_loggly"`
	LoggingLogShuttle    []*TerraformLoggingEndpoint `json:"logging_logshuttle"`
	LoggingNewRelic      []*TerraformLoggingEndpoint `json:"logging_newrelic"`
	LoggingOpenStack     []*TerraformLoggingEndpoint `json:"logging_openstack"`
	LoggingPaperTrail    []*TerraformLoggingEndpoint `json:"logging_papertrail"`
	LoggingS3            []*TerraformLoggingEndpoint `json:"logging_s3"`
	LoggingScalyr        []*TerraformLoggingEndpoint `json:"logging_scalyr"`
	LoggingSftp          []*TerraformLoggingEndpoint `json:"logging_sftp"`
	LoggingSplunk        []*TerraformLoggingEndpoint `json:"logging_splunk"`
	LoggingSumoLogic     []*TerraformLoggingEndpoint `json:"logging_sumologic"`
	LoggingSyslog        []*TerraformLoggingEndpoint `json:"logging_syslog"`
}

type TerraformPlannedResource struct {
	ProviderName string          `json:"provider_name"`
	Type         string          `json:"type"`
	Values       json.RawMessage `json:"values"`
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

	services, err := findFastlyServicesInTerraformModule(root.PlannedValues.RootModule)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(services) == 0 {
		return nil, errors.New(`Fastly service does not exist. Did you plan with fastly terraform provider?`)
	}

	return services, nil
}

func findFastlyServicesInTerraformModule(mod *TerraformModule) ([]*FastlyService, error) {
	var services []*FastlyService

	// Find services in module resources
	if len(mod.Resources) > 0 {
		// v is *TerraformPlannedResource
		for _, v := range mod.Resources {
			if !isFastlyVCLServiceResource(v) {
				continue
			}

			var s *FastlyServiceValues
			if err := json.Unmarshal(v.Values, &s); err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal values")
			}

			services = append(services, &FastlyService{
				Name:             s.Name,
				Vcls:             s.Vcl,
				Acls:             s.Acl,
				Backends:         s.Backend,
				Dictionaries:     s.Dictionary,
				Directors:        s.Director,
				Snippets:         s.Snippets,
				LoggingEndpoints: factoryLoggingEndpoints(s),
			})
		}
	}

	// Check child_modules existence and return found services if not found
	if mod.ChildModules == nil || len(mod.ChildModules) == 0 {
		return services, nil
	}
	// If module has child_modules, find Fastly service recursively
	for _, child := range mod.ChildModules {
		// child is *TerraformModule
		childSerivices, err := findFastlyServicesInTerraformModule(child)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		services = append(services, childSerivices...)
	}

	return services, nil
}

func isFastlyVCLServiceResource(r *TerraformPlannedResource) bool {
	return r.ProviderName == fastlyTerraformProviderName &&
		(r.Type == fastlyVCLServiceType || r.Type == fastlyVCLServiceTypeV1)
}

func factoryLoggingEndpoints(values *FastlyServiceValues) []string {
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
